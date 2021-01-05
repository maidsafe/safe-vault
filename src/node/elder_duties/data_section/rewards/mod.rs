// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod reward_calc;
mod section_funds;
mod validator;

use self::section_funds::{Payout, SectionFunds};
pub use self::{reward_calc::RewardCalc, validator::Validator};
use crate::{
    node::keys::NodeSigningKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{Blah, NodeMessagingDuty, NodeOperation, RewardCmd, RewardDuty, RewardQuery},
};
use crate::{Error, Result};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use sn_data_types::{Error as DtError, Money, PublicKey};
use sn_messaging::{
    Address, ElderDuties, Error as ErrorMessage, Message, MessageId, NodeQuery, NodeQueryResponse,
    NodeRewardQuery, NodeRewardQueryResponse, NodeTransferQuery,
};

use sn_transfers::TransferActor;
use std::collections::BTreeSet;
use xor_name::XorName;

/// The accumulation and paying
/// out of rewards to nodes for
/// their work in the network.
pub struct Rewards {
    node_rewards: DashMap<XorName, NodeRewards>,
    section_funds: SectionFunds,
    wrapping: ElderMsgWrapping,
    reward_calc: RewardCalc,
}

// Node age
type Age = u8;

#[derive(Debug, Clone)]
pub enum NodeRewards {
    /// When a new node joins the network.
    NewNode,
    /// When a node has been relocated to us.
    AwaitingActivation(Age),
    /// After we have received the wallet id, the
    /// stage of the NodeRewards is `Active`.
    Active { wallet: PublicKey, age: Age },
    /// After a node leaves the section
    /// the NodeRewards transitions into
    /// stage `AwaitingRelocation`.
    AwaitingRelocation(PublicKey),
}

impl Rewards {
    pub fn new(
        keys: NodeSigningKeys,
        actor: TransferActor<Validator>,
        reward_calc: RewardCalc,
    ) -> Self {
        let wrapping = ElderMsgWrapping::new(keys, ElderDuties::Rewards);
        let section_funds = SectionFunds::new(actor, wrapping.clone());
        Self {
            node_rewards: Default::default(),
            section_funds,
            wrapping,
            reward_calc,
        }
    }

    /// Returns the node ids of all nodes.
    pub fn all_nodes(&self) -> Vec<XorName> {
        self.node_rewards.iter().map(|r| *r.key()).collect()
    }

    /// Removes a subset of the nodes,
    /// more specifically those no longer
    /// part of this section, after a split.
    pub fn remove(&mut self, split_nodes: BTreeSet<XorName>) {
        for node in split_nodes {
            let _ = self.node_rewards.remove(&node);
        }
    }

    /// Issues a query to existing Replicas
    /// asking for their events, as to catch up and
    /// start working properly in the group.
    #[allow(unused)]
    pub async fn catchup_with_replicas(&self) -> Result<NodeOperation> {
        info!("Rewards: Catching up with our Replicas (section actor history)!");
        // prepare actor init
        let pub_key = self.section_funds.replicas();
        self.wrapping
            .send_to_section(
                Message::NodeQuery {
                    query: NodeQuery::Transfers(NodeTransferQuery::GetSectionActorHistory(pub_key)),
                    id: MessageId::new(),
                },
                true,
            )
            .await
            .convert()
    }

    /// After Elder change, we transition to a new
    /// transfer actor, as there is now a new keypair for it.
    pub async fn transition(&mut self, to: TransferActor<Validator>) -> Result<NodeOperation> {
        Ok(self.section_funds.transition(to).await?.into())
    }

    pub async fn process_reward_duty(&mut self, duty: RewardDuty) -> Result<NodeOperation> {
        use RewardDuty::*;
        match duty {
            ProcessCmd {
                cmd,
                msg_id,
                origin,
            } => self.process_reward_cmd(cmd, msg_id, origin).await,
            ProcessQuery {
                query,
                origin,
                msg_id,
            } => self.process_reward_query(query, msg_id, origin).await,
            NoOp => Ok(NodeOperation::NoOp),
        }
    }

    async fn process_reward_cmd(
        &mut self,
        cmd: RewardCmd,
        _msg_id: MessageId,
        _origin: Address,
    ) -> Result<NodeOperation> {
        use RewardCmd::*;
        let result = match cmd {
            InitiateSectionActor(events) => self.section_funds.synch(events).await?.into(),
            AddNewNode(node_id) => self.add_new_node(node_id)?.into(),
            SetNodeWallet { node_id, wallet_id } => {
                self.set_node_wallet(node_id, wallet_id)?.into()
            }
            AddRelocatingNode {
                old_node_id,
                new_node_id,
                age,
            } => self
                .add_relocating_node(old_node_id, new_node_id, age)
                .await?
                .into(),
            ActivateNodeRewards { id, node_id } => {
                self.activate_node_rewards(id, node_id).await?.into()
            }
            DeactivateNode(node_id) => self.deactivate(node_id)?.into(),
            ReceivePayoutValidation(validation) => self.section_funds.receive(validation).await?,
        };

        Ok(result)
    }

    async fn process_reward_query(
        &self,
        query: RewardQuery,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeOperation> {
        use RewardQuery::*;
        let result = match query {
            GetWalletId {
                old_node_id,
                new_node_id,
            } => self
                .get_wallet_id(old_node_id, new_node_id, msg_id, &origin)
                .await?
                .into(),
        };

        Ok(result)
    }

    /// On section splits, we are paying out to Elders.
    pub async fn payout_rewards(&mut self, node_ids: BTreeSet<XorName>) -> Result<NodeOperation> {
        let mut payouts: Vec<NodeOperation> = vec![];
        for node_id in node_ids {
            // Try get the wallet..
            let (wallet, age) = match self.node_rewards.get(&node_id) {
                None => {
                    warn!("No wallet found for node: {}.", node_id);
                    continue;
                }
                Some(state) => {
                    match *state {
                        // ..and validate its state.
                        NodeRewards::Active { wallet, age } => (wallet, age),
                        _ => {
                            warn!("Invalid operation: Node rewards is not activated.");
                            continue;
                        }
                    }
                }
            };
            info!("Initiating local reward payout to node: {}.", node_id);
            // Because of the more frequent payout, every such payout is made a bit smaller (dividing by age).
            let payout = self
                .section_funds
                .initiate_reward_payout(Payout {
                    to: wallet,
                    amount: Money::from_nano(
                        self.reward_calc.reward(age).await.as_nano() / age as u64,
                    ),
                    node_id,
                })
                .await?;

            // add the payout to list of ops
            payouts.push(payout.into());
        }

        Ok(payouts.into())
    }

    /// 0. A brand new node has joined our section.
    /// A new node always start at age 4.
    /// It still hasn't registered a wallet id at
    /// this point, but will as part of starting up.
    /// At age 5 it gets its first reward payout.
    fn add_new_node(&self, node_id: XorName) -> Result<NodeMessagingDuty> {
        let _ = self.node_rewards.insert(node_id, NodeRewards::NewNode);
        Ok(NodeMessagingDuty::NoOp)
    }

    /// 1. A new node registers a wallet id for future reward payout.
    /// ... or, an active node updates its wallet.
    fn set_node_wallet(&self, node_id: XorName, wallet: PublicKey) -> Result<NodeMessagingDuty> {
        // Try get the info..
        let state = match self.node_rewards.get_mut(&node_id) {
            None => {
                error!("Cannot set node wallet unless active or new.");
                return Err(Error::NetworkData(DtError::NoSuchKey));
            }
            Some(state) => {
                match *state {
                    // ..and validate its state.
                    NodeRewards::NewNode => NodeRewards::AwaitingRelocation(wallet),
                    NodeRewards::Active { age, .. } => NodeRewards::Active { age, wallet },
                    _ => {
                        warn!("Cannot set node wallet unless active or new.");
                        return Err(Error::NetworkData(DtError::InvalidOperation));
                    }
                }
            }
        };
        debug!("Node wallet set! {}, {:?}", node_id, state);
        let _ = self.node_rewards.insert(node_id, state);
        Ok(NodeMessagingDuty::NoOp)
    }

    /// 2. When a node is relocated to our section, we add the node id
    /// and send a query to old section, for retreiving the wallet id.
    async fn add_relocating_node(
        &self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NodeMessagingDuty> {
        use NodeQuery::*;
        use NodeRewardQuery::*;
        use NodeRewards::*;

        let state = AwaitingActivation(age);
        let _ = self.node_rewards.insert(new_node_id, state);

        self.wrapping
            .send_to_section(
                Message::NodeQuery {
                    query: Rewards(GetWalletId {
                        old_node_id,
                        new_node_id,
                    }),
                    id: MessageId::new(),
                },
                true,
            )
            .await
    }

    /// 3. The old section will send back the wallet id, which allows us to activate it.
    /// At this point, we payout a standard reward based on the node age,
    /// which represents the work performed in its previous section.
    async fn activate_node_rewards(
        &mut self,
        wallet: PublicKey,
        node_id: XorName,
    ) -> Result<NodeMessagingDuty> {
        // If we ever hit these errors, something is very odd
        // most likely a bug, because we are receiving a response to our query.
        // So, it doesn't make much sense to send some error msg back on the wire.
        // Makes more sense to panic, or log and just drop the request.
        // But exact course to take there needs to be chiseled out.

        // Try get the wallet..
        let age = match self.node_rewards.get_mut(&node_id) {
            None => {
                warn!("Invalid operation: Node not found {}.", node_id);
                return Err(Error::NodeNotFound);
            }
            Some(state) => {
                match *state {
                    // ..and validate its state.
                    NodeRewards::AwaitingActivation(age) => age,
                    _ => {
                        warn!("Invalid operation: Node is not awaiting reward activation.");
                        return Err(Error::NetworkData(DtError::InvalidOperation));
                    }
                }
            }
        };

        // Store account as `Active`
        let _ = self
            .node_rewards
            .insert(node_id, NodeRewards::Active { wallet, age });

        info!("Initiating reward payout to: {}.", wallet);
        self.section_funds
            .initiate_reward_payout(Payout {
                to: wallet,
                amount: self.reward_calc.reward(age).await,
                node_id,
            })
            .await
    }

    /// 4. When the section becomes aware that a node has left,
    /// its account is deactivated.
    fn deactivate(&self, node_id: XorName) -> Result<NodeMessagingDuty> {
        let entry = match self.node_rewards.get(&node_id) {
            Some(entry) => entry.clone(),
            None => return Ok(NodeMessagingDuty::NoOp),
        };
        let wallet = match entry {
            NodeRewards::Active { wallet, .. } => wallet,
            NodeRewards::AwaitingActivation { .. } // hmm.. left when AwaitingActivation is a tricky case.. // Might be case for lazy messaging..
            | NodeRewards::AwaitingRelocation(_)
            | NodeRewards::NewNode => return Ok(NodeMessagingDuty::NoOp),
        };
        let _ = self
            .node_rewards
            .insert(node_id, NodeRewards::AwaitingRelocation(wallet));
        Ok(NodeMessagingDuty::NoOp)
    }

    /// 5. The section that received a relocated node,
    /// will locally be executing `add_wallet(..)` of this very module,
    /// thereby sending a query to the old section, leading to this method
    /// here being called. A query response will be sent back with the wallet id.
    async fn get_wallet_id(
        &self,
        old_node_id: XorName,
        new_node_id: XorName,
        msg_id: MessageId,
        origin: &Address,
    ) -> Result<NodeMessagingDuty> {
        let entry = match self.node_rewards.get(&old_node_id) {
            Some(entry) => entry.clone(),
            None => return Ok(NodeMessagingDuty::NoOp),
        };
        let wallet = match entry {
            NodeRewards::AwaitingRelocation(id) => id,
            NodeRewards::NewNode
            | NodeRewards::AwaitingActivation { .. }
            | NodeRewards::Active { .. } => {
                // ..means the node has not left, and was not
                // marked as relocating..
                // (Could be a case for lazy messaging..)
                return self
                    .wrapping
                    .send_to_node(Message::NodeQueryResponse {
                        response: Rewards(GetWalletId(Err(ErrorMessage::UnexpectedNodeError(
                            "Node is not being relocated.".to_string(),
                        )))),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                        query_origin: origin.clone(),
                    })
                    .await;
            }
        };

        // Remove the old node, as it is being
        // taken over by the new section.
        let _ = self.node_rewards.remove(&old_node_id);

        // Send the reward counter to the new section.
        // Once received over there, the new section
        // will pay out the accumulated rewards to the wallet.
        use NodeQueryResponse::*;
        use NodeRewardQueryResponse::*;
        self.wrapping
            .send_to_node(Message::NodeQueryResponse {
                response: Rewards(GetWalletId(Ok((wallet, new_node_id)))),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin.clone(),
            })
            .await
    }
}
