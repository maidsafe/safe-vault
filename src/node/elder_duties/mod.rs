// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod data_section;
mod key_section;

use self::{data_section::DataSection, key_section::KeySection};
use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    node::node_ops::{ElderDuty, NetworkDuties, NetworkDuty},
    ElderState, NodeInfo, Result,
};
use log::trace;
use sn_data_types::{PublicKey, TransferPropagated, WalletInfo};
use sn_routing::Prefix;
use std::fmt::{self, Display, Formatter};
use xor_name::XorName;

/// Duties carried out by an Elder node.
pub struct ElderDuties {
    state: ElderState,
    key_section: KeySection,
    data_section: DataSection,
}

impl ElderDuties {
    pub async fn new(
        wallet_info: WalletInfo,
        node_info: &NodeInfo,
        state: ElderState,
    ) -> Result<Self> {
        let dbs = ChunkHolderDbs::new(node_info.path())?;
        let rate_limit = RateLimit::new(state.clone(), Capacity::new(dbs.clone()));
        let key_section = KeySection::new(rate_limit, node_info, state.clone()).await?;
        let data_section = DataSection::new(node_info, dbs, wallet_info, state.clone()).await?;
        Ok(Self {
            state,
            key_section,
            data_section,
        })
    }

    ///
    pub fn state(&self) -> &ElderState {
        &self.state
    }

    /// Issues queries to Elders of the section
    /// as to catch up with shares state and
    /// start working properly in the group.
    pub async fn initiate(&mut self, genesis: Option<TransferPropagated>) -> Result<NetworkDuties> {
        let mut ops = vec![];
        if let Some(genesis) = genesis {
            // if we are genesis
            // does local init, with no roundrip via network messaging
            let _ = self.key_section.init_genesis_node(genesis).await?;
        } else {
            ops.append(&mut self.key_section.catchup_with_section().await?);
            ops.append(&mut self.data_section.catchup_with_section().await?);
        }

        Ok(ops)
    }

    /// Processing of any Elder duty.
    pub async fn process_elder_duty(&mut self, duty: ElderDuty) -> Result<NetworkDuties> {
        trace!("Processing elder duty: {:?}", duty);
        use ElderDuty::*;
        match duty {
            ProcessNewMember(name) => self.new_node_joined(name).await,
            ProcessLostMember { name, age } => self.member_left(name, age).await,
            ProcessRelocatedMember {
                old_node_id,
                new_node_id,
                age,
            } => {
                self.relocated_node_joined(old_node_id, new_node_id, age)
                    .await
            }
            RunAsKeySection(the_key_duty) => {
                self.key_section
                    .process_key_section_duty(the_key_duty)
                    .await
            }
            RunAsDataSection(duty) => self.data_section.process_data_section_duty(duty).await,
            StorageFull { node_id } => self.increase_full_node_count(node_id).await,
            SwitchNodeJoin(joins_allowed) => {
                self.key_section.set_node_join_flag(joins_allowed).await
            }
            NoOp => Ok(vec![]),
        }
    }

    ///
    async fn new_node_joined(&mut self, name: XorName) -> Result<NetworkDuties> {
        self.data_section.new_node_joined(name).await
    }

    async fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<NetworkDuties> {
        self.key_section
            .increase_full_node_count(node_id)
            .await
            .map(|()| vec![])
    }

    ///
    async fn relocated_node_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NetworkDuties> {
        self.data_section
            .relocated_node_joined(old_node_id, new_node_id, age)
            .await
    }

    ///
    async fn member_left(&mut self, node_id: XorName, age: u8) -> Result<NetworkDuties> {
        self.data_section.member_left(node_id, age).await
    }

    ///
    pub async fn initiate_elder_change(
        &mut self,
        elder_state: ElderState,
    ) -> Result<NetworkDuties> {
        // 1. First we must update data section..
        self.data_section.initiate_elder_change(elder_state).await
    }

    ///
    pub async fn finish_elder_change(
        &mut self,
        node_info: &NodeInfo,
        state: ElderState,
    ) -> Result<()> {
        // 2. Then we must update key section..
        let dbs = ChunkHolderDbs::new(node_info.path())?;
        let rate_limit = RateLimit::new(state.clone(), Capacity::new(dbs));
        self.key_section.elders_changed(state, rate_limit);
        Ok(())
    }

    ///
    pub async fn split_section(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
        let _ = self.key_section.split_section(prefix).await?;
        self.data_section.split_section(prefix).await
    }
}

impl Display for ElderDuties {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ElderDuties")
    }
}
