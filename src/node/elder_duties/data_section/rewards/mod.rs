// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod section_funds;
mod validator;

use self::section_funds::{Payout, SectionFunds};
pub use self::validator::Validator;
use crate::{
    node::keys::NodeSigningKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{MessagingDuty, NodeOperation, RewardDuty},
};
use log::{info, warn};
use safe_nd::{
    AccountId, Address, ElderDuties, Error, Message, MessageId, Money, NodeQuery,
    NodeQueryResponse, NodeRewardQuery, NodeRewardQueryResponse,
};
use safe_transfers::TransferActor;
use std::collections::{BTreeSet, HashMap};
use xor_name::XorName;

/// The accumulation and paying
/// out of rewards to nodes for
/// their work in the network.
pub struct Rewards {
    node_accounts: HashMap<XorName, RewardAccount>,
    section_funds: SectionFunds,
    wrapping: ElderMsgWrapping,
}

// Node age
type Age = u8;

pub enum RewardAccount {
    /// When added.
    AwaitingStart(Age),
    /// After we have received the account id, the
    /// stage of the RewardAccount is `Active`.
    Active { id: AccountId, age: Age },
    /// After a node leaves the section
    /// the RewardAccount transitions into
    /// stage `Inactive`.
    Inactive(AccountId),
}

fn reward(age: Age) -> Money {
    Money::from_nano(2_u64.pow(age as u32) * 1_000_000_000)
}

impl Rewards {
    pub fn new(keys: NodeSigningKeys, actor: TransferActor<Validator>) -> Self {
        let wrapping = ElderMsgWrapping::new(keys, ElderDuties::Rewards);
        let section_funds = SectionFunds::new(actor, wrapping.clone());
        Self {
            node_accounts: Default::default(),
            section_funds,
            wrapping,
        }
    }

    /// Returns the node ids of all nodes.
    pub fn all_nodes(&self) -> Vec<XorName> {
        self.node_accounts.keys().copied().collect()
    }

    /// Removes a subset of the nodes,
    /// more specifically those no longer
    /// part of this section, after a split.
    pub fn remove(&mut self, split_nodes: BTreeSet<XorName>) {
        for node in split_nodes {
            let _ = self.node_accounts.remove(&node);
        }
    }

    /// After Elder change, we transition to a new
    /// transfer actor, as there is now a new keypair for it.
    pub fn transition(&mut self, to: TransferActor<Validator>) -> Option<NodeOperation> {
        Some(self.section_funds.transition(to)?.into())
    }

    pub fn process(&mut self, duty: RewardDuty) -> Option<NodeOperation> {
        use RewardDuty::*;
        let result = match duty {
            AddNewNode(node_id) => self.add_node(node_id)?.into(),
            AddRelocatedNode {
                old_node_id,
                new_node_id,
                age,
            } => self
                .add_relocated_account(old_node_id, new_node_id, age)?
                .into(),
            GetAccountId {
                old_node_id,
                new_node_id,
                msg_id,
                origin,
            } => self
                .get_account_id(old_node_id, new_node_id, msg_id, &origin)?
                .into(),
            ReceiveAccountId { id, node_id } => self.receive_account_id(id, node_id)?.into(),
            DeactivateNode(node_id) => self.deactivate(node_id)?.into(),
            ReceivePayoutValidation(validation) => self.section_funds.receive(validation)?,
        };

        Some(result)
    }

    /// On section splits, we are paying out to Elders.
    pub fn payout_rewards(&mut self, node_ids: BTreeSet<XorName>) -> Option<NodeOperation> {
        let mut payouts: Vec<NodeOperation> = vec![];
        for node_id in node_ids {
            // Try get the account..
            let (id, age) = match self.node_accounts.get(&node_id) {
                None => {
                    warn!("No account found for node: {}.", node_id);
                    continue;
                }
                Some(account) => {
                    match account {
                        // ..and validate its state.
                        RewardAccount::Active { id, age } => (*id, *age),
                        _ => {
                            warn!("Invalid operation: Account is not active.");
                            return None;
                        }
                    }
                }
            };
            info!("Initiating local reward payout to node: {}.", node_id);
            // Because of the more frequent payout, every such payout is made a bit smaller (dividing by age).
            if let Some(payout) = self.section_funds.initiate_reward_payout(Payout {
                to: id,
                amount: Money::from_nano(reward(age).as_nano() / age as u64),
                node_id,
            }) {
                // add the payout to list of ops
                payouts.push(payout.into());
            }
        }

        Some(payouts.into())
    }

    /// 0. A brand new node has joined our section.
    /// A new node always start at age 4.
    /// It still hasn't registered an account id at
    /// this point, but will as part of starting up.
    /// At age 5 it gets its first reward payout.
    fn add_node(&mut self, node_id: XorName) -> Option<MessagingDuty> {
        let _ = self
            .node_accounts
            .insert(node_id, RewardAccount::AwaitingStart(4));
        None
    }

    /// 1. When a node is relocated to our section, we add the node id
    /// and send a cmd to old section, for retreiving the account id.
    fn add_relocated_account(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Option<MessagingDuty> {
        use NodeQuery::*;
        use NodeRewardQuery::*;
        use RewardAccount::*;

        let account = AwaitingStart(age);
        let _ = self.node_accounts.insert(new_node_id, account);

        self.wrapping.send(Message::NodeQuery {
            query: Rewards(GetAccountId {
                old_node_id,
                new_node_id,
            }),
            id: MessageId::new(),
        })
    }

    /// 2. The old section will send back the account id.
    /// At this point, we payout a standard reward based on the node age,
    /// which represents the work performed in its previous section.
    fn receive_account_id(&mut self, id: AccountId, node_id: XorName) -> Option<MessagingDuty> {
        // If we ever hit these errors, something is very odd
        // most likely a bug, because we are receiving an event triggered by our cmd.
        // So, it doesn't make much sense to send some error msg back on the wire.
        // Makes more sense to panic, or log and just drop the request.
        // But exact course to take there needs to be chiseled out.

        // Try get the account..
        let age = match self.node_accounts.get_mut(&node_id) {
            None => {
                warn!("Invalid receive: No such account found to receive the rewards.");
                return None;
            }
            Some(account) => {
                match account {
                    // ..and validate its state.
                    RewardAccount::AwaitingStart(age) => *age,
                    _ => {
                        warn!("Invalid receive: Account is not awaiting start.");
                        return None;
                    }
                }
            }
        };

        // Store account as `Active`
        let _ = self
            .node_accounts
            .insert(node_id, RewardAccount::Active { id, age });

        info!("Initiating reward payout to: {}.", id);
        self.section_funds.initiate_reward_payout(Payout {
            to: id,
            amount: reward(age),
            node_id,
        })
    }

    /// 4. When the section becomes aware that a node has left,
    /// its account is deactivated.
    fn deactivate(&mut self, node_id: XorName) -> Option<MessagingDuty> {
        let id = match self.node_accounts.get(&node_id) {
            Some(RewardAccount::Active { id, .. }) => *id,
            Some(RewardAccount::AwaitingStart { .. }) // hmm.. left when AwaitingStart is a tricky case..
            | Some(RewardAccount::Inactive(_))
            | None => return None,
        };
        let _ = self
            .node_accounts
            .insert(node_id, RewardAccount::Inactive(id));
        None
    }

    /// 5. The section that received a relocated node,
    /// will locally be executing `add_account(..)` of this very module,
    /// thereby sending a query to the old section, leading to this method
    /// here being called. A query response will be sent back with the account id.
    fn get_account_id(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        let account_id = match self.node_accounts.get(&old_node_id) {
            Some(RewardAccount::Inactive(id)) => *id,
            Some(RewardAccount::Active { .. }) => {
                // ..means the node has not left, and was not
                // marked as awaiting move..
                // (Could be a case for lazy messaging..)
                return self.wrapping.send(Message::NodeQueryResponse {
                    response: Rewards(GetAccountId(Err(Error::NetworkOther(
                        "InvalidClaim: Account is not awaiting move.".to_string(),
                    )))),
                    id: MessageId::new(),
                    correlation_id: msg_id,
                    query_origin: origin.clone(),
                });
            }
            Some(RewardAccount::AwaitingStart { .. }) // todo: return error, but we need to have the account id in that case, or change / extend the current error(s)
            | None => return None,
        };

        // Remove the old node, as it is being
        // taken over by the new section.
        let _ = self.node_accounts.remove(&old_node_id);

        // Send the reward counter to the new section.
        // Once received over there, the new section
        // will pay out the accumulated rewards to the account.
        use NodeQueryResponse::*;
        use NodeRewardQueryResponse::*;
        self.wrapping.send(Message::NodeQueryResponse {
            response: Rewards(GetAccountId(Ok((account_id, new_node_id)))),
            id: MessageId::new(),
            correlation_id: msg_id,
            query_origin: origin.clone(),
        })
    }
}
