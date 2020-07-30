// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod farming;
mod section_funds;
mod validator;

use self::section_funds::SectionFunds;
pub use self::{farming::FarmingSystem, validator::Validator};
use crate::{
    node::economy::MintingMetrics,
    node::keys::NodeKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{MessagingDuty, NodeOperation, RewardDuty},
};
use log::{info, warn};
use safe_farming::{Accumulation, RewardCounterSet, StorageRewards};
use safe_nd::{
    AccountId, Address, ElderDuties, Error, Message, MessageId, Money, NodeCmd, NodeCmdError,
    NodeEvent, NodeRewardCmd, NodeRewardError, RewardCounter, XorName,
};
use safe_transfers::TransferActor;
use std::collections::HashMap;

/// The accumulation and paying
/// out of rewards to nodes for
/// their work in the network.
pub struct Rewards {
    farming: FarmingSystem<StorageRewards>,
    node_accounts: HashMap<XorName, RewardAccount>,
    section_funds: SectionFunds,
    minting_metrics: MintingMetrics,
    wrapping: ElderMsgWrapping,
}

pub enum RewardAccount {
    /// When added.
    AwaitingStart(RewardCounterSet),
    /// After having received the counters, the
    /// stage of the RewardAccount is `Active`.
    Active(AccountId),
    /// After a node leaves the section
    /// the RewardAccount transitions into
    /// stage `AwaitingMove`.
    AwaitingMove(AccountId),
}

impl Rewards {
    pub fn new(keys: NodeKeys, actor: TransferActor<Validator>) -> Self {
        let wrapping = ElderMsgWrapping::new(keys.clone(), ElderDuties::Rewards);
        let acc = Accumulation::new(Default::default(), Default::default());
        let base_cost = Money::from_nano(1);
        let algo = StorageRewards::new(base_cost);
        let farming = FarmingSystem::new(algo, acc);
        let section_funds = SectionFunds::new(actor, wrapping.clone());
        Self {
            farming,
            node_accounts: Default::default(),
            section_funds,
            minting_metrics: MintingMetrics {
                key: keys.public_key(),
                store_cost: base_cost,
                velocity: 2.0,
            },
            wrapping,
        }
    }

    pub fn transition(&mut self, to: TransferActor<Validator>) -> Option<NodeOperation> {
        Some(self.section_funds.transition(to)?.into())
    }

    pub fn process(&mut self, duty: RewardDuty) -> Option<NodeOperation> {
        use RewardDuty::*;
        let result = match duty {
            AccumulateReward { points, msg_id } => self.accumulate_reward(points, msg_id),
            AddNewAccount { id, node_id } => self.add_account(id, node_id),
            AddRelocatedAccount {
                old_node_id,
                new_node_id,
            } => self.add_relocated_account(old_node_id, new_node_id),
            ClaimRewardCounter {
                old_node_id,
                new_node_id,
                msg_id,
                origin,
            } => self.claim_rewards(old_node_id, new_node_id, msg_id, &origin),
            ReceiveClaimedRewards {
                id,
                node_id,
                counter,
            } => self.receive_claimed_rewards(id, node_id, counter),
            PrepareAccountMove { node_id } => self.prepare_move(node_id),
            ReceivePayoutValidation(validation) => self.section_funds.receive(validation),
            UpdateRewards(metrics) => {
                self.farming.set_base_cost(metrics.store_cost);
                self.minting_metrics = metrics;
                None
            }
        };

        result.map(|c| c.into())
    }

    /// 0. A brand new node has joined our section.
    fn add_account(&mut self, id: AccountId, node_id: XorName) -> Option<MessagingDuty> {
        let _ = self
            .node_accounts
            .insert(node_id, RewardAccount::Active(id));
        None
    }

    /// 1. When a node is relocated to our section, we add the account
    /// and send a cmd to old section, for claiming the rewards.
    fn add_relocated_account(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
    ) -> Option<MessagingDuty> {
        use NodeCmd::*;
        use NodeRewardCmd::*;
        use RewardAccount::*;

        let elder_count = 7; // todo, fix better source
        let account = AwaitingStart(RewardCounterSet::new(elder_count, vec![]).ok()?);
        let _ = self.node_accounts.insert(new_node_id, account);

        self.wrapping.send(Message::NodeCmd {
            cmd: Rewards(ClaimRewardCounter {
                old_node_id,
                new_node_id,
            }),
            id: MessageId::new(),
        })
    }

    /// 2. The old section will send back the claimed rewards.
    /// Work is the total work associated with this account id.
    /// It is a strictly incrementing value during the lifetime of
    /// the owner on the network.
    fn receive_claimed_rewards(
        &mut self,
        id: AccountId,
        node_id: XorName,
        counter: RewardCounter,
    ) -> Option<MessagingDuty> {
        // If we ever hit these errors, something is very odd
        // most likely a bug, because we are receiving an event triggered by our cmd.
        // So, it doesn't make much sense to send some error msg back on the wire.
        // Makes more sense to panic, or log and just drop the request.
        // But exact course to take there needs to be chiseled out.

        // Try get the account..
        let counter_set = match self.node_accounts.get_mut(&node_id) {
            None => {
                warn!("Invalid receive: No such account found to receive the rewards.");
                return None;
            }
            Some(account) => {
                match account {
                    // ..and validate its state.
                    RewardAccount::AwaitingStart(set) => set,
                    _ => {
                        warn!("Invalid receive: Account is not awaiting start.");
                        return None;
                    }
                }
            }
        };

        // Add the counter to the set.
        counter_set.add(counter);

        info!("Reward counter added (total: {})", counter_set.len());

        // And try to get an agreed value..
        let counter = counter_set.agreed_value()?;

        // Add the account to our farming.
        // It will now be eligible for farming rewards.
        match self.farming.add_account(id, counter.work) {
            Ok(_) => {
                // Set the stage to `Active`
                let _ = self
                    .node_accounts
                    .insert(node_id, RewardAccount::Active(id));
                // If any reward was accumulated,
                // we initiate payout to the account.
                if counter.reward > Money::zero() {
                    info!("Initiating reward payout to: {}.", id);
                    return self
                        .section_funds
                        .initiate_reward_payout(counter.reward, id);
                }
                None
            }
            Err(error) => {
                // Really, the same comment about error
                // as above, applies here as well..
                // There is nothing the old section can do about this error
                // and it should be a bug, so, something other than sending
                // an error to the old section needs to be done here.
                warn!(
                    "Failed to add account and agreed counter! Error: {}.",
                    error
                );
                None
            }
        }
    }

    /// 3. Every time the section receives
    /// a write request, the accounts accumulate reward.
    fn accumulate_reward(&mut self, points: u64, msg_id: MessageId) -> Option<MessagingDuty> {
        let hash = (msg_id.0).0.to_vec(); // todo: fix the parameter type down-streams (in safe-farming)
        let factor = self.minting_metrics.velocity;
        match self.farming.reward(hash, points, factor) {
            Ok(amount) => {
                info!(
                    "Rewarded {} for {} points by write id {:?}.",
                    amount, points, msg_id
                );
                None
            }
            Err(error) => {
                warn!(
                    "Failed to accumulate reward! Error: {}, msg id: {:?}.",
                    error, msg_id
                );
                None
            }
        }
    }

    /// 4. When the section becomes aware that a node has left,
    /// it is flagged for being awaiting move.
    fn prepare_move(&mut self, node_id: XorName) -> Option<MessagingDuty> {
        let id = match self.node_accounts.get(&node_id) {
            Some(RewardAccount::Active(id)) => *id,
            Some(RewardAccount::AwaitingStart(_)) // hmm.. left when AwaitingStart is a tricky case..
            | Some(RewardAccount::AwaitingMove(_))
            | None => return None,
        };
        let _ = self
            .node_accounts
            .insert(node_id, RewardAccount::AwaitingMove(id));
        None
    }

    /// 5. The section that received a relocated node,
    /// will locally be executing `add_account(..)` of this very module,
    /// thereby sending a cmd to the old section, leading to this method
    /// here being called. An event will be sent back with the claimed counter.
    fn claim_rewards(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        use NodeCmdError::*;
        use NodeRewardError::*;

        let account_id = match self.node_accounts.get(&old_node_id) {
            Some(RewardAccount::AwaitingMove(id)) => *id,
            Some(RewardAccount::Active(id)) => {
                // ..means the node has not left, and was not
                // marked as awaiting move..
                return self.wrapping.network_error(
                    Rewards(RewardClaiming {
                        error: Error::NetworkOther(
                            "InvalidClaim: Account is not awaiting move.".to_string(),
                        ),
                        account_id: *id,
                    }),
                    msg_id,
                    origin,
                );
            }
            Some(RewardAccount::AwaitingStart(_)) // todo: return error, but we need to have the account id in that case, or change / extend the current error(s)
            | None => return None,
        };

        // Claim the counter. (This removes it from our state.)
        let counter = match self.farming.claim(account_id) {
            Ok(counter) => counter,
            Err(error) => {
                return self.wrapping.network_error(
                    Rewards(RewardClaiming { error, account_id }),
                    msg_id,
                    origin,
                );
            }
        };

        // Remove the old node, as it is being
        // taken over by the new section.
        let _ = self.node_accounts.remove(&old_node_id);

        // Send the reward counter to the new section.
        // Once received over there, the new section
        // will pay out any accumulated rewards to the account.
        // From there on, they accumulate rewards for the node
        // until it is being relocated again.
        self.wrapping.send(Message::NodeEvent {
            event: NodeEvent::RewardCounterClaimed {
                new_node_id,
                account_id,
                counter,
            },
            id: MessageId::new(),
            correlation_id: msg_id,
        })
    }
}
