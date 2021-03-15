// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use super::reward_calc::RewardCalc;
use super::{
    elder_signing::ElderSigning,
    rewarding_wallet::{Payout, RewardingWallet, Validator},
};
use crate::node_ops::{NodeDuties, NodeDuty, OutgoingMsg};
use crate::{Error, Result};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use sn_data_types::{Error as DtError, NodeRewardStage, PublicKey, Token, WalletInfo};
use sn_messaging::{
    client::{
        Error as ErrorMessage, Message, NodeQuery, NodeQueryResponse, NodeRewardQuery,
        NodeRewardQueryResponse,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_transfers::TransferActor;
use std::collections::{BTreeMap, BTreeSet};
use xor_name::XorName;

type SectionActor = TransferActor<Validator, ElderSigning>;

/// The accumulation and paying
/// out of rewards to nodes for
/// their work in the network.
pub struct RewardPayout {
    node_rewards: DashMap<XorName, NodeRewardStage>,
    wallet: RewardingWallet,
    reward_calc: RewardCalc,
}

// Node age
type Age = u8;

impl RewardPayout {
    pub fn new(
        wallet: RewardingWallet,
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
        reward_calc: RewardCalc,
    ) -> Self {
        Self {
            node_rewards: node_rewards.into_iter().collect(),
            wallet,
            reward_calc,
        }
    }

    ///
    pub fn section_wallet(&self) -> WalletInfo {
        self.wallet.wallet_info()
    }

    ///
    pub fn node_rewards(&self) -> BTreeMap<XorName, NodeRewardStage> {
        self.node_rewards
            .clone()
            .into_read_only()
            .iter()
            .map(|(node, stage)| (*node, stage.clone()))
            .collect()
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

    pub async fn synch(&mut self, info: WalletInfo) -> Result<NodeDuty> {
        if self.wallet.replicas() != PublicKey::Bls(info.replicas.key_set.public_key()) {
            error!("Section funds keys dont match");
            return Err(Error::Logic("crap..".to_string()));
        }
        debug!(">>>> syncing....");
        self.wallet.synch(info.history).await
    }

    /// On section splits, we are paying out to Elders.
    pub async fn payout_rewards(&mut self, node_ids: BTreeSet<&XorName>) -> Result<NodeDuties> {
        let mut payouts: NodeDuties = vec![];
        for node_id in node_ids {
            // Try get the wallet..
            let (wallet, age) = match self.node_rewards.get(node_id) {
                None => {
                    warn!("No wallet found for node: {}.", node_id);
                    continue;
                }
                Some(state) => {
                    match *state {
                        // ..and validate its state.
                        NodeRewardStage::Active { wallet, age } => (wallet, age),
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
                .wallet
                .initiate_reward_payout(Payout {
                    to: wallet,
                    amount: Token::from_nano(
                        self.reward_calc.reward(age).await.as_nano() / age as u64,
                    ),
                    node_id: *node_id,
                })
                .await?;

            // add the payout to list of ops
            payouts.push(payout);
        }

        Ok(payouts)
    }

    /// 0. A brand new node has joined our section.
    /// A new node always start at age 4.
    /// It still hasn't registered a wallet id at
    /// this point, but will as part of starting up.
    /// At age 5 it gets its first reward payout.
    pub fn add_new_node(&self, node_id: XorName) -> NodeDuty {
        info!("Rewards: New node added: {:?}", node_id);
        let _ = self.node_rewards.insert(node_id, NodeRewardStage::NewNode);
        NodeDuty::NoOp
    }

    /// 1. A new node registers a wallet id for future reward payout.
    /// ... or, an active node updates its wallet.
    pub fn set_node_wallet(&self, node_id: XorName, wallet: PublicKey) -> Result<NodeDuty> {
        // Try get the info..
        if !self.node_rewards.contains_key(&node_id) {
            let _ = self.node_rewards.insert(node_id, NodeRewardStage::NewNode);
        }
        let state = match self.node_rewards.get_mut(&node_id) {
            Some(state) => {
                match *state {
                    // ..and validate its state.
                    NodeRewardStage::NewNode => NodeRewardStage::AwaitingRelocation(wallet),
                    NodeRewardStage::Active { age, .. } => NodeRewardStage::Active { age, wallet },
                    _ => {
                        warn!("Cannot set node wallet unless active or new.");
                        return Err(Error::NetworkData(DtError::InvalidOperation));
                    }
                }
            }
            None => {
                // should be unreachable..
                warn!("Cannot see node wallet in the node reward register. (Add new node command may still be pending....)");
                return Err(Error::NetworkData(DtError::NoSuchKey));
            }
        };
        debug!("Node wallet set! {}, {:?}", node_id, state);
        let _ = self.node_rewards.insert(node_id, state);
        Ok(NodeDuty::NoOp)
    }

    /// 2. When a node is relocated to our section, we add the node id
    /// and send a query to old section, for retreiving the wallet id.
    pub async fn add_relocating_node(
        &self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NodeDuty> {
        use NodeQuery::*;
        use NodeRewardQuery::*;
        use NodeRewardStage::*;

        let state = AwaitingActivation(age);
        let _ = self.node_rewards.insert(new_node_id, state);
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeQuery {
                query: Rewards(GetNodeWalletId {
                    old_node_id,
                    new_node_id,
                }),
                id: MessageId::combine(vec![old_node_id, new_node_id]),
                target_section_pk: None,
            },
            section_source: true, // i.e. responses go to our section
            dst: DstLocation::Section(old_node_id),
            aggregation: Aggregation::AtDestination,
        }))
    }

    /// 3. The old section will send back the wallet id, which allows us to activate it.
    /// At this point, we payout a standard reward based on the node age,
    /// which represents the work performed in its previous section.
    pub async fn activate_node_rewards(
        &mut self,
        wallet: PublicKey,
        node_id: XorName,
    ) -> Result<NodeDuty> {
        // If we ever hit these errors, something is very odd
        // most likely a bug, because we are receiving a response to our query.
        // So, it doesn't make much sense to send some error msg back on the wire.
        // Makes more sense to panic, or log and just drop the request.
        // But exact course to take there needs to be chiseled out.

        // Try get the wallet..
        let age = match self.node_rewards.get_mut(&node_id) {
            None => {
                warn!(
                    ">>>activate_node_rewards Invalid operation: Node not found {}.",
                    node_id
                );
                return Err(Error::NodeNotFoundForReward);
            }
            Some(state) => {
                match *state {
                    // ..and validate its state.
                    NodeRewardStage::AwaitingActivation(age) => age,
                    NodeRewardStage::Active { .. } => {
                        info!("Node already activated.");
                        return Ok(NodeDuty::NoOp);
                    }
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
            .insert(node_id, NodeRewardStage::Active { wallet, age });

        info!("Initiating reward payout to: {}.", wallet);
        self.wallet
            .initiate_reward_payout(Payout {
                to: wallet,
                amount: self.reward_calc.reward(age).await,
                node_id,
            })
            .await
    }

    /// 4. When the section becomes aware that a node has left,
    /// its account is deactivated.
    pub fn deactivate(&self, node_id: XorName) -> Result<NodeDuty> {
        debug!("Rewards: trying to deactivate {}", node_id);
        let entry = match self.node_rewards.get(&node_id) {
            Some(entry) => entry.clone(),
            None => {
                warn!("Could not deactivate, node not found");
                return Err(Error::NodeNotFoundForReward);
            }
        };
        debug!(
            "Rewards: node {} found as {:?}, deactivating..",
            node_id, entry
        );
        let wallet = match entry {
            NodeRewardStage::Active { wallet, .. } => wallet,
            NodeRewardStage::AwaitingRelocation(_) => {
                debug!("Rewards: {} is already awaiting relocation", node_id);
                return Ok(NodeDuty::NoOp);
            }
            NodeRewardStage::AwaitingActivation { .. } // hmm.. left when AwaitingActivation is a tricky case.. // Might be case for lazy messaging..
            | NodeRewardStage::NewNode => {
                debug!("Rewards: Could not deactivate {}, node was never activated!", node_id);
                return Err(Error::Logic(format!("Rewards: Could not deactivate {}, node was never activated!", node_id)));
            }
        };
        debug!(
            "Rewards: Active node {} is using wallet {}..",
            node_id, wallet
        );
        let _ = self
            .node_rewards
            .insert(node_id, NodeRewardStage::AwaitingRelocation(wallet));
        debug!(
            "Rewards: deactivated {}. It is now awaiting relocation.",
            node_id
        );
        Ok(NodeDuty::NoOp)
    }

    /// 5. The section that received a relocated node,
    /// will locally be executing `add_wallet(..)` of this very module,
    /// thereby sending a query to the old section, leading to this method
    /// here being called. A query response will be sent back with the wallet id.
    pub async fn get_wallet_key(
        &self,
        old_node_id: XorName,
        new_node_id: XorName,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        let entry = match self.node_rewards.get(&old_node_id) {
            Some(entry) => entry.clone(),
            None => return Ok(NodeDuty::NoOp),
        };
        let wallet = match entry {
            NodeRewardStage::AwaitingRelocation(id) => id,
            NodeRewardStage::NewNode
            | NodeRewardStage::AwaitingActivation { .. }
            | NodeRewardStage::Active { .. } => {
                // ..means the node has not left, and was not
                // marked as relocating..
                // (Could be a case for lazy messaging..)
                return Ok(NodeDuty::Send(OutgoingMsg {
                    msg: Message::NodeQueryResponse {
                        response: Rewards(GetNodeWalletId(Err(ErrorMessage::NodeWasNotRelocated))),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                        target_section_pk: None,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to a response..
                    dst: origin.to_dst(),
                    aggregation: Aggregation::AtDestination,
                }));
            }
        };

        // Remove the old node, as it is being
        // taken over by the new section.
        let _ = self.node_rewards.remove(&old_node_id);

        // Send the wallet key to the new section.
        // Once received over there, the new section
        // will pay out rewards to the wallet.
        use NodeQueryResponse::*;
        use NodeRewardQueryResponse::*;
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeQueryResponse {
                response: Rewards(GetNodeWalletId(Ok((wallet, new_node_id)))),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::Section(new_node_id),
            aggregation: Aggregation::AtDestination,
        }))
    }
}
