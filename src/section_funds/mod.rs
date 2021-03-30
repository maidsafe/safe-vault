// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod churn_payout_stage;
pub mod churn_process;
pub mod elder_signing;
mod reward_calc;
pub mod reward_wallets;
pub mod section_wallet;

use self::{
    churn_process::ChurnProcess, reward_wallets::RewardWallets, section_wallet::SectionWallet,
};
use super::node_ops::{NodeDuty, OutgoingMsg};
use crate::Result;
use sn_data_types::{PublicKey, SectionElders, Token};
use sn_messaging::{
    client::{Message, NodeQuery, NodeSystemQuery},
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::XorName;
use std::collections::BTreeMap;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
#[allow(clippy::large_enum_variant)]
pub enum SectionFunds {
    KeepingNodeWallets {
        section_wallet: SectionWallet,
        wallets: RewardWallets,
    },
    // in transition
    Churning {
        process: ChurnProcess,
        wallets: RewardWallets,
        replicas: Option<SectionElders>,
    },
}

impl SectionFunds {
    /// Returns registered wallet key of a node.
    pub fn get_node_wallet(&self, node_name: &XorName) -> Option<PublicKey> {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                let (_, key) = wallets.get(node_name)?;
                Some(key)
            }
        }
    }

    /// Returns node wallet keys of registered nodes.
    pub fn node_wallets(&self) -> BTreeMap<XorName, (u8, PublicKey)> {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                wallets.node_wallets()
            }
        }
    }

    /// Nodes register/updates wallets for future reward payouts.
    pub fn set_node_wallet(&self, node_id: XorName, wallet: PublicKey, age: u8) {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                wallets.set_node_wallet(node_id, age, wallet)
            }
        }
    }

    /// When the section becomes aware that a node has left,
    /// its reward key is removed.
    pub fn remove_node_wallet(&self, node_name: XorName) -> Result<()> {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                wallets.remove_wallet(node_name)
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
