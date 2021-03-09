// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elder_signing;
mod metadata;
mod rewards;

use self::{
    elder_signing::ElderSigning,
    metadata::Metadata,
    rewards::{RewardCalc, Rewards, Validator},
};
use crate::{
    capacity::ChunkHolderDbs,
    node::node_ops::{DataSectionDuty, NetworkDuties, RewardCmd, RewardDuty},
    node::{NodeInfo, RewardsAndWallets},
    Network, Result,
};
use log::info;
use sn_data_types::{NodeRewardStage, PublicKey, WalletInfo};
use sn_messaging::{MessageId, SrcLocation};
use sn_routing::Prefix;
use sn_transfers::TransferActor;
use std::collections::BTreeMap;
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
    /// The network state.
    rewards_and_wallets: RewardsAndWallets,

    network: Network,
}

pub struct RewardData {
    pub section_wallet: WalletInfo,
    pub node_rewards: BTreeMap<XorName, NodeRewardStage>,
}

impl DataSection {
    // ///
    // pub async fn new(
    //     info: &NodeInfo,
    //     dbs: ChunkHolderDbs,
    //     rewards_and_wallets: RewardsAndWallets,
    //     reward_data: RewardData,
    //     network: Network,
    // ) -> Result<Self> {
    //     // Metadata
    //     let metadata = Metadata::new(info, dbs, network.clone()).await?;
    //     // Rewards
    //     let signing = ElderSigning::new(network.clone(), network.our_public_key_set().await?);
    //     let actor = TransferActor::from_info(signing, reward_data.section_wallet, Validator {})?;
    //     let reward_calc = RewardCalc::new(network.our_prefix().await);
    //     let rewards = Rewards::new(actor, reward_data.node_rewards, reward_calc);

    //     Ok(Self {
    //         metadata,
    //         rewards,
    //         rewards_and_wallets,
    //     })
    // }

    // pub async fn process_data_section_duty(
    //     &mut self,
    //     duty: DataSectionDuty,
    // ) -> Result<NetworkDuties> {
    //     use DataSectionDuty::*;
    //     match duty {
    //         RunAsMetadata(duty) => self.metadata.process_metadata_duty(duty).await,
    //         RunAsRewards(duty) => self.rewards.process_reward_duty(duty).await,
    //         NoOp => Ok(vec![]),
    //     }
    // }

    // ///
    // pub fn section_wallet(&self) -> WalletInfo {
    //     self.rewards.section_wallet()
    // }

    // ///
    // pub fn node_rewards(&self) -> BTreeMap<XorName, NodeRewardStage> {
    //     self.rewards.node_rewards()
    // }

    // /// Issues query to Elders of the section
    // /// as to catch up with the current state of the replicas.
    // pub async fn catchup_with_section(&mut self) -> Result<NetworkDuties> {
    //     let prefix_name = self.rewards_and_wallets().prefix().name();
    //     self.rewards
    //         .get_section_wallet_history(prefix_name)
    //         .await
    // }

    // /// Transition the section funds account to the new key.
    // pub async fn initiate_elder_change(
    //     &mut self,
    //     rewards_and_wallets: RewardsAndWallets,
    //     sibling_key: Option<PublicKey>,
    // ) -> Result<NetworkDuties> {
    //     info!(">> Processing Elder change in data section");
    //     // TODO: Query sn_routing for info for [new_section_key]
    //     // specifically (regardless of how far back that was) - i.e. not the current info!

    //     // if we were demoted, we should not call this at all,
    //     // make sure demoted is handled properly first, so that
    //     // EldersChanged doesn't lead to calling this method..

    //     self.rewards
    //         .init_wallet_transition(rewards_and_wallets, sibling_key)
    //         .await
    // }

    // /// At section split, all Elders get their reward payout.
    // pub async fn split_section(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
    //     // First remove nodes that are no longer in our section.
    //     let to_remove = self
    //         .rewards
    //         .all_nodes()
    //         .into_iter()
    //         .filter(|c| !prefix.matches(&XorName(c.0)))
    //         .collect();
    //     self.rewards.remove(to_remove);

    //     Ok(vec![])
    //     // // Then payout rewards to all the Elders.
    //     // let elders = self.rewards_and_wallets.elder_names();
    //     // self.rewards.payout_rewards(elders).await
    // }

    // /// When a new node joins, it is registered for receiving rewards.
    // pub async fn new_node_joined(&mut self, id: XorName) -> Result<NetworkDuties> {
    //     let node_name = self.network.our_name().await;
    //     self.rewards
    //         .process_reward_duty(RewardDuty::ProcessCmd {
    //             cmd: RewardCmd::AddNewNode(id),
    //             msg_id: MessageId::new(),
    //             origin: SrcLocation::Node(node_name),
    //         })
    //         .await
    // }

    // /// When a relocated node joins, a DataSection
    // /// has a few different things to do, such as
    // /// pay out rewards and trigger chunk replication.
    // pub async fn relocated_node_joined(
    //     &mut self,
    //     old_node_id: XorName,
    //     new_node_id: XorName,
    //     age: u8,
    // ) -> Result<NetworkDuties> {
    //     // Adds the relocated account.
    //     let node_name = self.network.our_name().await;
    //     self.rewards
    //         .process_reward_duty(RewardDuty::ProcessCmd {
    //             cmd: RewardCmd::AddRelocatingNode {
    //                 old_node_id,
    //                 new_node_id,
    //                 age,
    //             },
    //             msg_id: MessageId::new(),
    //             origin: SrcLocation::Node(node_name),
    //         })
    //         .await
    // }

    // /// Name of the node
    // /// Age of the node
    // pub async fn member_left(&mut self, node_id: XorName, _age: u8) -> Result<NetworkDuties> {
    //     let node_name = self.network.our_name().await;
    //     let mut duties = self
    //         .rewards
    //         .process_reward_duty(RewardDuty::ProcessCmd {
    //             cmd: RewardCmd::DeactivateNode(node_id),
    //             msg_id: MessageId::new(),
    //             origin: SrcLocation::Node(node_name),
    //         })
    //         .await?;
    //     duties.extend(self.metadata.trigger_chunk_replication(node_id).await?);
    //     Ok(duties)
    // }
}
