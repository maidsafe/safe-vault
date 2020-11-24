// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::state_db::AgeGroup;
use crate::{
    node::node_ops::{NodeDuty, NodeOperation, RewardDuty},
    Network,
};
use sn_data_types::PublicKey;

/// Configuration made after connected to
/// network, or promoted to elder.
///
/// These are calls made as part of
/// a node initialising into a certain duty.
/// Being first node:
/// -> 1. Add own node id to rewards.
/// -> 2. Add own wallet to rewards.
/// Becoming an Adult:
/// -> 1. Become Adult.
/// -> 2. Register wallet at Elders.
/// Becoming an Elder:
/// -> 1. Become Elder.
/// -> 2. Add own node id to rewards.
/// -> 3. Add own wallet to rewards.
pub struct DutyConfig {
    reward_key: PublicKey,
    network_api: Network,
    status: AgeGroup,
}

impl DutyConfig {
    pub fn new(reward_key: PublicKey, network_api: Network, status: AgeGroup) -> Self {
        Self {
            reward_key,
            network_api,
            status,
        }
    }

    /// When first node in network.
    #[allow(dead_code)]
    pub async fn setup_as_first(&self) -> Option<NodeOperation> {
        None
    }

    /// When becoming Adult.
    pub fn setup_as_adult(&mut self) -> Option<NodeOperation> {
        self.status = AgeGroup::Adult;
        // 1. Becomde Adult.
        let first: NodeOperation = NodeDuty::BecomeAdult.into();
        // 2. Register wallet at Elders.
        let second = NodeDuty::RegisterWallet(self.reward_key).into();
        Some(vec![first, second].into())
    }

    /// When becoming Elder.
    pub async fn setup_as_elder(&mut self) -> Option<NodeOperation> {
        self.status = AgeGroup::Elder;
        // 1. Become Elder.
        let first: NodeOperation = NodeDuty::BecomeElder.into();
        // 2. Add own node id to rewards.
        let node_id = self.network_api.name().await;
        let second = RewardDuty::AddNewNode(node_id).into();
        // 3. Add own wallet to rewards.
        let third = RewardDuty::SetNodeWallet {
            node_id,
            wallet_id: self.reward_key,
        }
        .into();
        Some(vec![first, second, third].into())
    }
}
