// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod metadata;
mod rewards;

use self::{
    metadata::Metadata,
    rewards::{RewardCalc, Rewards, Validator},
};

use crate::{
    capacity::ChunkHolderDbs,
    node::node_ops::{DataSectionDuty, NodeOperation, RewardDuty},
    node::state_db::NodeInfo,
    utils, Network, Result,
};
use futures::lock::Mutex;
use sn_routing::Prefix;
use sn_transfers::TransferActor;
use std::sync::Arc;
use xor_name::XorName;

/// A DataSection is responsible for
/// the storage and retrieval of data,
/// and the rewarding of nodes in the section
/// for participating in these duties.
pub struct DataSection {
    /// The logic for managing data.
    metadata: Metadata,
    /// Rewards for performing storage
    /// services to the network.
    rewards: Rewards,
    /// The routing layer.
    network: Network,
}

impl DataSection {
    ///
    pub async fn new(
        info: &NodeInfo,
        dbs: ChunkHolderDbs,
        total_used_space: &Arc<Mutex<u64>>,
        network: Network,
    ) -> Result<Self> {
        // Metadata
        let metadata = Metadata::new(info, dbs, &total_used_space, network.clone())?;

        // Rewards
        let keypair = utils::key_pair(network.clone()).await?;
        let public_key_set = network.public_key_set().await?;
        let actor = TransferActor::new(keypair, public_key_set, Validator {});
        let reward_calc = RewardCalc::new(network.clone());
        let rewards = Rewards::new(info.keys.clone(), actor, reward_calc);

        Ok(Self {
            metadata,
            rewards,
            network,
        })
    }

    pub async fn process_data_section_duty(
        &mut self,
        duty: DataSectionDuty,
    ) -> Option<NodeOperation> {
        use DataSectionDuty::*;
        match duty {
            RunAsMetadata(duty) => self.metadata.process_metadata_duty(duty).await,
            RunAsRewards(duty) => self.rewards.process_reward_duty(duty).await,
        }
    }

    // Transition the section funds account to the new key.
    pub async fn elders_changed(&mut self) -> Option<NodeOperation> {
        let pub_key_set = self.network.public_key_set().await.ok()?;
        let keypair = utils::key_pair(self.network.clone()).await.ok()?;
        let actor = TransferActor::new(keypair, pub_key_set, Validator {});
        self.rewards.transition(actor).await
    }

    // At section split, all Elders get their reward payout.
    pub async fn section_split(&mut self, prefix: Prefix) -> Option<NodeOperation> {
        // First remove nodes that are no longer in our section.
        let to_remove = self
            .rewards
            .all_nodes()
            .into_iter()
            .filter(|c| !prefix.matches(&XorName(c.0)))
            .collect();
        self.rewards.remove(to_remove);

        // Then payout rewards to all the Elders.
        let elders = self.network.our_elder_names().await;
        self.rewards.payout_rewards(elders).await
    }

    /// When a new node joins, it is registered for receiving rewards.
    pub async fn new_node_joined(&mut self, id: XorName) -> Option<NodeOperation> {
        self.rewards
            .process_reward_duty(RewardDuty::AddNewNode(id))
            .await
    }

    /// When a relocated node joins, a DataSection
    /// has a few different things to do, such as
    /// pay out rewards and trigger chunk duplication.
    pub async fn relocated_node_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Option<NodeOperation> {
        // Adds the relocated account.
        let first = self
            .rewards
            .process_reward_duty(RewardDuty::AddRelocatingNode {
                old_node_id,
                new_node_id,
                age,
            })
            .await;
        let second = self.metadata.trigger_chunk_duplication(new_node_id).await;
        Some(vec![first, second].into())
    }

    /// Name of the node
    /// Age of the node
    pub async fn member_left(&mut self, node_id: XorName, _age: u8) -> Option<NodeOperation> {
        // marks the reward account as
        // awaiting claiming of the counter
        let first = self
            .rewards
            .process_reward_duty(RewardDuty::DeactivateNode(node_id))
            .await;
        let second = self.metadata.trigger_chunk_duplication(node_id).await;
        Some(vec![first, second].into())
    }
}
