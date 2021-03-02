// Copyright 2021 MaidSafe.net limited.
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
    node::node_ops::{DataSectionDuty, NetworkDuties, RewardCmd, RewardDuty},
    node::NodeInfo,
    ElderState, Result,
};
use log::info;
use sn_data_types::{OwnerType, PublicKey, Result as DtResult, Signing, WalletInfo};
use sn_messaging::{MessageId, SrcLocation};
use sn_routing::Prefix;
use sn_transfers::TransferActor;
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
    elder_state: ElderState,
}

#[derive(Clone)]
pub struct ElderSigning {
    id: OwnerType,
    elder_state: ElderState,
}

impl ElderSigning {
    pub fn new(elder_state: ElderState) -> Self {
        Self {
            id: OwnerType::Multi(elder_state.public_key_set().clone()),
            elder_state,
        }
    }
}

impl Signing for ElderSigning {
    fn id(&self) -> OwnerType {
        self.id.clone()
    }

    fn sign<T: serde::Serialize>(&self, data: &T) -> DtResult<sn_data_types::Signature> {
        use sn_data_types::Error as DtError;
        Ok(sn_data_types::Signature::BlsShare(
            futures::executor::block_on(self.elder_state.sign_as_elder(data))
                .map_err(|_| DtError::InvalidOperation)?,
        ))
    }

    fn verify<T: serde::Serialize>(&self, sig: &sn_data_types::Signature, data: &T) -> bool {
        let data = match bincode::serialize(data) {
            Ok(data) => data,
            Err(_) => return false,
        };
        use sn_data_types::Signature::*;
        match sig {
            Bls(sig) => {
                if let OwnerType::Multi(set) = self.id() {
                    set.public_key().verify(&sig, data)
                } else {
                    false
                }
            }
            Ed25519(_) => {
                if let OwnerType::Single(public_key) = self.id() {
                    public_key.verify(sig, data).is_ok()
                } else {
                    false
                }
            }
            BlsShare(share) => {
                if let OwnerType::Multi(set) = self.id() {
                    let pubkey_share = set.public_key_share(share.index);
                    pubkey_share.verify(&share.share, data)
                } else {
                    false
                }
            }
        }
    }
}

impl DataSection {
    ///
    pub async fn new(
        info: &NodeInfo,
        dbs: ChunkHolderDbs,
        wallet_info: WalletInfo,
        elder_state: ElderState,
    ) -> Result<Self> {
        // Metadata
        let metadata = Metadata::new(info, dbs, elder_state.clone()).await?;

        // Rewards
        let signing = ElderSigning::new(elder_state.clone());
        let actor = TransferActor::from_info(signing, wallet_info, Validator {})?;
        let reward_calc = RewardCalc::new(*elder_state.prefix());
        let rewards = Rewards::new(actor, reward_calc);

        Ok(Self {
            metadata,
            rewards,
            elder_state,
        })
    }

    pub async fn process_data_section_duty(
        &mut self,
        duty: DataSectionDuty,
    ) -> Result<NetworkDuties> {
        use DataSectionDuty::*;
        match duty {
            RunAsMetadata(duty) => self.metadata.process_metadata_duty(duty).await,
            RunAsRewards(duty) => self.rewards.process_reward_duty(duty).await,
            NoOp => Ok(vec![]),
        }
    }

    /// Issues query to Elders of the section
    /// as to catch up with the current state of the replicas.
    pub async fn catchup_with_section(&mut self) -> Result<NetworkDuties> {
        self.rewards
            .get_section_wallet_history(self.elder_state.prefix().name())
            .await
    }

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

        self.rewards.init_transition(elder_state, sibling_key).await
    }

    /// At section split, all Elders get their reward payout.
    pub async fn split_section(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
        // First remove nodes that are no longer in our section.
        let to_remove = self
            .rewards
            .all_nodes()
            .into_iter()
            .filter(|c| !prefix.matches(&XorName(c.0)))
            .collect();
        self.rewards.remove(to_remove);

        Ok(vec![])
        // // Then payout rewards to all the Elders.
        // let elders = self.elder_state.elder_names();
        // self.rewards.payout_rewards(elders).await
    }

    /// When a new node joins, it is registered for receiving rewards.
    pub async fn new_node_joined(&mut self, id: XorName) -> Result<NetworkDuties> {
        self.rewards
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::AddNewNode(id),
                msg_id: MessageId::new(),
                origin: SrcLocation::Node(self.elder_state.node_name()),
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
        self.rewards
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::AddRelocatingNode {
                    old_node_id,
                    new_node_id,
                    age,
                },
                msg_id: MessageId::new(),
                origin: SrcLocation::Node(self.elder_state.node_name()),
            })
            .await
    }

    /// Name of the node
    /// Age of the node
    pub async fn member_left(&mut self, node_id: XorName, _age: u8) -> Result<NetworkDuties> {
        let mut duties = self
            .rewards
            .process_reward_duty(RewardDuty::ProcessCmd {
                cmd: RewardCmd::DeactivateNode(node_id),
                msg_id: MessageId::new(),
                origin: SrcLocation::Node(self.elder_state.node_name()),
            })
            .await?;
        duties.extend(self.metadata.trigger_chunk_replication(node_id).await?);
        Ok(duties)
    }
}
