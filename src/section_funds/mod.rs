// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod churn_process;
pub mod elder_signing;
mod reward_calc;
pub mod reward_payout;
pub mod reward_stages;
pub mod rewards;
mod section_wallet;
pub mod wallet_stage;

use self::{
    churn_process::ChurnProcess, reward_payout::RewardPayout, reward_stages::RewardStages,
    rewards::Rewards, section_wallet::SectionWallet,
};
use super::node_ops::{NodeDuty, OutgoingMsg};
use crate::Result;
use sn_data_types::{NodeRewardStage, PublicKey, SectionElders, Token};
use sn_messaging::{
    client::{NodeQuery, NodeSystemQuery, ProcessMsg},
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::XorName;
use std::collections::BTreeMap;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
#[allow(clippy::large_enum_variant)]
pub enum SectionFunds {
    // ready, can do payouts
    Rewarding(Rewards),
    // in transition and cannot do payouts
    Churning {
        rewards: Rewards,
        process: ChurnProcess,
        replicas: Option<SectionElders>,
        reward_queue: BTreeMap<XorName, PublicKey>,
    },
}

impl SectionFunds {
    /// Returns current stages of registered nodes.
    pub fn node_rewards(&self) -> BTreeMap<XorName, NodeRewardStage> {
        match &self {
            //Self::TakingNodes(stages) => stages.node_rewards(),
            Self::Churning { rewards, .. } | Self::Rewarding(rewards) => rewards.node_rewards(),
        }
    }

    /// 0. A brand new node has joined our section.
    /// A new node always start at age 4.
    /// It still hasn't registered a wallet id at
    /// this point, but will as part of starting up.
    /// At age 5 it gets its first reward payout.
    pub fn add_new_node(&self, node_id: XorName) {
        //info!("Rewards: New node added: {:?}", node_id);
        match &self {
            //Self::TakingNodes(stages) => stages.add_new_node(node_id),
            Self::Churning { rewards, .. } | Self::Rewarding(rewards) => {
                rewards.add_new_node(node_id)
            }
        }
    }

    /// 1. A new node registers a wallet id for future reward payout.
    /// ... or, an active node updates its wallet.
    pub fn set_node_wallet(&self, node_id: XorName, wallet: PublicKey) -> Result<NodeDuty> {
        match &self {
            Self::Churning { rewards, .. } | Self::Rewarding(rewards) => {
                rewards.set_node_wallet(node_id, wallet)
            }
        }
    }

    /// 2. When a node is relocated to our section, we add the node id
    /// and send a query to old section, for retreiving the wallet id.
    pub async fn add_relocating_node(
        &self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NodeDuty> {
        match &self {
            Self::Churning { rewards, .. } | Self::Rewarding(rewards) => {
                rewards
                    .add_relocating_node(old_node_id, new_node_id, age)
                    .await
            }
        }
    }

    /// 4. When the section becomes aware that a node has left,
    /// its account is deactivated.
    pub fn deactivate(&self, node_id: XorName) -> Result<()> {
        match &self {
            Self::Churning { rewards, .. } | Self::Rewarding(rewards) => {
                rewards.deactivate(node_id)
            }
        }
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
        match &self {
            Self::Churning { rewards, .. } | Self::Rewarding(rewards) => {
                rewards
                    .get_wallet_key(old_node_id, new_node_id, msg_id, origin)
                    .await
            }
        }
    }
}

//     let to_remove = self
//         .rewards
//         .all_nodes()
//         .into_iter()
//         .filter(|c| !prefix.matches(&XorName(c.0)))
//         .collect();
//     self.rewards.remove(to_remove);

// /// At section split, all Elders get their reward payout.
// pub async fn reward_elders(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
// let elders = self.rewards_and_wallets.elder_names();
// self.rewards.payout_rewards(elders).await
// }
