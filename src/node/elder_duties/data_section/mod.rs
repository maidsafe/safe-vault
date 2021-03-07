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
    node::NodeInfo,
    ElderState, Error, Result,
};
use log::info;
use sn_data_types::{PublicKey, WalletInfo};
use sn_messaging::{MessageId, SrcLocation};
use sn_routing::Prefix;
use sn_transfers::TransferActor;
use xor_name::XorName;

/// A DataSection is responsible for
/// the storage and retrieval of data,
/// and the rewarding of nodes in the section
/// for participating in these duties.
#[allow(clippy::large_enum_variant)]
pub enum DataSection {
    PreElder {
        /// The logic for managing data.
        metadata: Metadata,
        /// The network state.
        elder_state: ElderState,
    },
    Elder {
        /// The logic for managing data.
        metadata: Metadata,
        /// Rewards for performing storage
        /// services to the network.
        rewards: Rewards,
        /// The network state.
        elder_state: ElderState,
    },
}

impl DataSection {
    ///
    pub async fn pre_elder(
        info: &NodeInfo,
        dbs: ChunkHolderDbs,
        elder_state: ElderState,
    ) -> Result<Self> {
        // Metadata
        let metadata = Metadata::new(info, dbs, elder_state.clone()).await?;
        Ok(Self::PreElder {
            metadata,
            elder_state,
        })
    }

    /// Only once we have the section wallet info
    /// can we instantiate rewards module.
    pub async fn enable(self, wallet_info: WalletInfo) -> Result<Self> {
        if let Self::PreElder {
            metadata,
            elder_state,
        } = self
        {
            // Rewards
            let signing = ElderSigning::new(elder_state.clone());
            let actor = TransferActor::from_info(signing, wallet_info, Validator {})?;
            let reward_calc = RewardCalc::new(*elder_state.prefix());
            let rewards = Rewards::new(actor, reward_calc);

            Ok(Self::Elder {
                metadata,
                rewards,
                elder_state,
            })
        } else {
            Err(Error::InvalidOperation(
                "This instance is already enabled.".to_string(),
            ))
        }
    }

    fn metadata(&mut self) -> &mut Metadata {
        match self {
            Self::PreElder { metadata, .. } | Self::Elder { metadata, .. } => metadata,
        }
    }

    fn rewards(&mut self) -> Result<&mut Rewards> {
        match self {
            Self::PreElder { .. } => Err(Error::InvalidOperation(format!(""))),
            Self::Elder { rewards, .. } => Ok(rewards),
        }
    }

    fn elder_state(&self) -> &ElderState {
        match &self {
            Self::PreElder { elder_state, .. } | Self::Elder { elder_state, .. } => elder_state,
        }
    }

    pub async fn process_data_section_duty(
        &mut self,
        duty: DataSectionDuty,
    ) -> Result<NetworkDuties> {
        use DataSectionDuty::*;
        match duty {
            RunAsMetadata(duty) => self.metadata().process_metadata_duty(duty).await,
            RunAsRewards(duty) => self.rewards()?.process_reward_duty(duty).await,
            NoOp => Ok(vec![]),
        }
    }

    // /// Issues query to Elders of the section
    // /// as to catch up with the current state of the replicas.
    // pub async fn catchup_with_section(&mut self) -> Result<NetworkDuties> {
    //     let prefix_name = self.elder_state().prefix().name();
    //     self.rewards()?
    //         .get_section_wallet_history(prefix_name)
    //         .await
    // }

    /// Transition the section funds account to the new key.
    pub async fn initiate_elder_change(
        &mut self,
        elder_state: ElderState,
        sibling_key: Option<PublicKey>,
    ) -> Result<NetworkDuties> {
        info!(">> Processing Elder change in data section");
        // TODO: Query sn_routing for info for [new_section_key]
        // specifically (regardless of how far back that was) - i.e. not the current info!

        // if we were demoted, we should not call this at all,
        // make sure demoted is handled properly first, so that
        // EldersChanged doesn't lead to calling this method..

        self.rewards()?
            .init_wallet_transition(elder_state, sibling_key)
            .await
    }

    /// At section split, all Elders get their reward payout.
    pub async fn split_section(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
        // First remove nodes that are no longer in our section.
        let to_remove = self
            .rewards()?
            .all_nodes()
            .into_iter()
            .filter(|c| !prefix.matches(&XorName(c.0)))
            .collect();
        self.rewards()?.remove(to_remove);

        Ok(vec![])
        // // Then payout rewards to all the Elders.
        // let elders = self.elder_state.elder_names();
        // self.rewards.payout_rewards(elders).await
    }

    /// When a new node joins, it is registered for receiving rewards.
    pub async fn new_node_joined(&mut self, id: XorName) -> Result<NetworkDuties> {
        let node_name = self.elder_state().node_name();
        self.rewards()?
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::AddNewNode(id),
                msg_id: MessageId::new(),
                origin: SrcLocation::Node(node_name),
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
    ) -> Result<NetworkDuties> {
        // Adds the relocated account.
        let node_name = self.elder_state().node_name();
        self.rewards()?
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::AddRelocatingNode {
                    old_node_id,
                    new_node_id,
                    age,
                },
                msg_id: MessageId::new(),
                origin: SrcLocation::Node(node_name),
            })
            .await
    }

    /// Name of the node
    /// Age of the node
    pub async fn member_left(&mut self, node_id: XorName, _age: u8) -> Result<NetworkDuties> {
        let node_name = self.elder_state().node_name();
        let mut duties = self
            .rewards()?
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::DeactivateNode(node_id),
                msg_id: MessageId::new(),
                origin: SrcLocation::Node(node_name),
            })
            .await?;
        duties.extend(self.metadata().trigger_chunk_replication(node_id).await?);
        Ok(duties)
    }
}
