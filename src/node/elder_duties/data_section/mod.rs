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
    chunk_store::UsedSpace,
    node::node_ops::{DataSectionDuty, NodeOperation, RewardCmd, RewardDuty},
    node::state_db::NodeInfo,
    utils, Error, Network, Result,
};
use sn_data_types::{Address, MessageId, WalletInfo};
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
        used_space: UsedSpace,
        wallet_info: WalletInfo,
        network: Network,
    ) -> Result<Self> {
        // Metadata
        let metadata = Metadata::new(info, dbs, used_space, network.clone()).await?;

        // Rewards
        let keypair = utils::key_pair(network.clone()).await?;
        let actor = TransferActor::from_info(Arc::new(keypair), wallet_info, Validator {})?;
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
    ) -> Result<NodeOperation> {
        use DataSectionDuty::*;
        match duty {
            RunAsMetadata(duty) => self.metadata.process_metadata_duty(duty).await,
            RunAsRewards(duty) => self.rewards.process_reward_duty(duty).await,
            NoOp => Ok(NodeOperation::NoOp),
        }
    }

    /// Issues query to Elders of the section
    /// as to catch up with the current state of the replicas.
    pub async fn catchup_with_section(&mut self) -> Result<NodeOperation> {
        self.rewards.catchup_with_replicas().await
    }

    // Transition the section funds account to the new key.
    pub async fn elders_changed(&mut self) -> Result<NodeOperation> {
        // if we were demoted, we should not call this at all,
        // make sure demoted is handled properly first, so that
        // EldersChanged doesn't lead to calling this method..
        if let Some(new_section_key) = self.network.section_public_key().await {
            let new_keypair_share = utils::key_pair(self.network.clone()).await?;
            self.rewards
                .init_transition(new_section_key, new_keypair_share)
                .await
        } else {
            Err(Error::Logic(
                "Seems we are not an Elder, this code should not be reachable then..".to_string(),
            ))
        }
    }

    // At section split, all Elders get their reward payout.
    pub async fn section_split(&mut self, prefix: Prefix) -> Result<NodeOperation> {
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
    pub async fn new_node_joined(&mut self, id: XorName) -> Result<NodeOperation> {
        self.rewards
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::AddNewNode(id),
                msg_id: MessageId::new(),
                origin: Address::Node(self.network.name().await),
            })
            .await
    }

    /// When a relocated node joins, a DataSection
    /// has a few different things to do, such as
    /// pay out rewards and trigger chunk replication.
    pub async fn relocated_node_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NodeOperation> {
        // Adds the relocated account.
        self.rewards
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::AddRelocatingNode {
                    old_node_id,
                    new_node_id,
                    age,
                },
                msg_id: MessageId::new(),
                origin: Address::Node(self.network.name().await),
            })
            .await
    }

    /// Name of the node
    /// Age of the node
    pub async fn member_left(&mut self, node_id: XorName, _age: u8) -> Result<NodeOperation> {
        // marks the reward account as
        // awaiting claiming of the counter
        let first = self
            .rewards
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::DeactivateNode(node_id),
                msg_id: MessageId::new(),
                origin: Address::Node(self.network.name().await),
            })
            .await;
        let second = self.metadata.trigger_chunk_replication(node_id).await;
        Ok(vec![first, second].into())
    }
}
