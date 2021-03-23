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
    reward_payout::{Payout, RewardPayout, Validator},
    reward_stages::RewardStages,
    section_wallet::SectionWallet,
};
use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Error, Result,
};
use log::{debug, info, warn};
use sn_data_types::{
    ActorHistory, NodeRewardStage, PublicKey, SectionElders, SignedTransferShare, Token,
    TransferValidated, WalletHistory,
};
use sn_messaging::{
    client::{NodeCmd, NodeTransferCmd, ProcessMsg},
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_transfers::{ActorEvent, TransferActor};
use sn_transfers::{ReplicaValidator, Wallet};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use xor_name::XorName;
use ActorEvent::*;

type SectionActor = TransferActor<Validator, ElderSigning>;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
#[derive(Clone)]
pub struct Rewards {
    payout: RewardPayout,
    stages: RewardStages,
    reward_calc: RewardCalc,
}

impl Rewards {
    pub fn new(payout: RewardPayout, stages: RewardStages, reward_calc: RewardCalc) -> Self {
        Self {
            payout,
            stages,
            reward_calc,
        }
    }

    pub fn set(&mut self, actor: SectionActor, members: SectionElders, reward_calc: RewardCalc) {
        self.payout.set(actor, members);
        self.reward_calc = reward_calc;
    }

    /// On section splits, we are paying out to Elders.
    pub async fn payout_rewards(&mut self, node_ids: BTreeSet<&XorName>) -> Result<NodeDuties> {
        let mut payouts: NodeDuties = vec![];
        for node_id in node_ids {
            // Try get the wallet..
            match self.stages.get(node_id) {
                None => warn!("No wallet found for node: {}.", node_id),
                Some(NodeRewardStage::Active { wallet, age }) => {
                    info!("Initiating local reward payout to node: {}.", node_id);
                    // Because of the more frequent payout, every such payout is made a bit smaller (dividing by age).
                    let payout = self
                        .payout
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
                _ => warn!("Invalid operation: Node rewards is not activated."),
            };
        }

        Ok(payouts)
    }

    pub async fn receive(&mut self, validation: TransferValidated) -> Result<NodeDuties> {
        self.payout.receive(validation).await
    }

    pub fn section_wallet_members(&self) -> SectionWallet {
        self.payout.section_wallet_members()
    }

    pub fn section_wallet_history(&self) -> WalletHistory {
        self.payout.section_wallet_history()
    }

    /// Balance
    pub fn balance(&self) -> Token {
        self.payout.balance()
    }

    pub fn has_payout_in_flight(&self) -> bool {
        self.payout.has_payout_in_flight()
    }

    pub fn stash_payout_in_flight(&mut self) {
        self.payout.stash_payout_in_flight()
    }

    // ---------------------------------------------
    //   ----------------- STAGES ---------------
    // ---------------------------------------------

    pub fn merge(&mut self, node_rewards: BTreeMap<XorName, NodeRewardStage>) {
        let mut existing_stages = self.stages.node_rewards();
        existing_stages.extend(node_rewards); // TODO: fix this!
        self.stages = RewardStages::new(existing_stages);
    }

    /// Returns current stages of registered nodes.
    pub fn node_rewards(&self) -> BTreeMap<XorName, NodeRewardStage> {
        self.stages.node_rewards()
    }

    /// Removes a subset of the nodes,
    /// more specifically those no longer
    /// part of this section, after a split.
    pub fn remove(&mut self, split_nodes: BTreeSet<XorName>) {
        self.stages.remove(split_nodes)
    }

    /// 0. A brand new node has joined our section.
    /// A new node always start at age 4.
    /// It still hasn't registered a wallet id at
    /// this point, but will as part of starting up.
    /// At age 5 it gets its first reward payout.
    pub fn add_new_node(&self, node_id: XorName) {
        self.stages.add_new_node(node_id);
    }

    /// 1. A new node registers a wallet id for future reward payout.
    /// ... or, an active node updates its wallet.
    pub fn set_node_wallet(&self, node_id: XorName, wallet: PublicKey) -> Result<NodeDuty> {
        self.stages.set_node_wallet(node_id, wallet)
    }

    /// 2. When a node is relocated to our section, we add the node id
    /// and send a query to old section, for retreiving the wallet id.
    pub async fn add_relocating_node(
        &self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NodeDuty> {
        self.stages
            .add_relocating_node(old_node_id, new_node_id, age)
            .await
    }

    /// If relocations queued up during a churn.
    pub async fn payout_node_rewards(
        &mut self,
        reward_queue: BTreeMap<XorName, PublicKey>,
    ) -> Result<Vec<NodeDuty>> {
        let mut ops = vec![];
        for (node_id, wallet) in reward_queue {
            ops.push(self.payout_node_reward(wallet, node_id).await?);
        }

        Ok(ops)
    }

    /// 3. The old section will send back the wallet id, which allows us to activate it.
    /// At this point, we payout a standard reward based on the node age,
    /// which represents the work performed in its previous section.
    pub async fn payout_node_reward(
        &mut self,
        wallet: PublicKey,
        node_id: XorName,
    ) -> Result<NodeDuty> {
        let age = self.stages.activate_node_rewards(wallet, node_id).await?;

        info!("Initiating reward payout to: {}.", wallet);
        self.payout
            .initiate_reward_payout(Payout {
                to: wallet,
                amount: self.reward_calc.reward(age).await,
                node_id,
            })
            .await
    }

    /// 4. When the section becomes aware that a node has left,
    /// its account is deactivated.
    pub fn deactivate(&self, node_id: XorName) -> Result<()> {
        self.stages.deactivate(node_id)
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
        self.stages
            .get_wallet_key(old_node_id, new_node_id, msg_id, origin)
            .await
    }
}
