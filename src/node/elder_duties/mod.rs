// Copyright 2020 MaidSafe.net limited.
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
    chunk_store::UsedSpace,
    node::node_ops::{ElderDuty, NodeOperation},
    node::state_db::NodeInfo,
    Network, Result,
};
use log::{debug, trace};
use sn_data_types::{PublicKey, WalletInfo};
use sn_routing::Prefix;
use std::fmt::{self, Display, Formatter};
use xor_name::XorName;

/// Duties carried out by an Elder node.
pub struct ElderDuties {
    prefix: Prefix,
    key_section: KeySection,
    data_section: DataSection,
}

impl ElderDuties {
    pub async fn new(
        info: &NodeInfo,
        wallet_info: WalletInfo,
        used_space: UsedSpace,
        network: Network,
    ) -> Result<Self> {
        let prefix = network.our_prefix().await;
        let dbs = ChunkHolderDbs::new(info.path(), info.init_mode)?;
        let rate_limit = RateLimit::new(network.clone(), Capacity::new(dbs.clone()));
        let key_section = KeySection::new(info, rate_limit, network.clone()).await?;
        let data_section = DataSection::new(info, dbs, used_space, wallet_info, network).await?;
        Ok(Self {
            prefix,
            key_section,
            data_section,
        })
    }

    /// Issues queries to Elders of the section
    /// as to catch up with shares state and
    /// start working properly in the group.
    pub async fn initiate(&mut self, first: bool) -> Result<NodeOperation> {
        let mut ops = vec![];
        if first {
            // if we are genesis
            // does local init, with no roundrip via network messaging
            ops.push(self.key_section.init_genesis_node().await?);
        } else {
            ops.push(self.key_section.catchup_with_section().await?);
            ops.push(self.data_section.catchup_with_section().await?);
        }

        Ok(ops.into())
    }

    /// Processing of any Elder duty.
    pub async fn process_elder_duty(&mut self, duty: ElderDuty) -> Result<NodeOperation> {
        trace!("Processing elder duty");
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
            ProcessElderChange { prefix, .. } => self.elders_changed(prefix).await,
            RunAsKeySection(the_key_duty) => {
                self.key_section
                    .process_key_section_duty(the_key_duty)
                    .await
            }
            RunAsDataSection(duty) => self.data_section.process_data_section_duty(duty).await,
            NoOp => Ok(NodeOperation::NoOp),
            StorageFull { node_id } => {
                self.increase_full_node_count(node_id).await;
                Ok(NodeOperation::NoOp)
            }
            SwitchNodeJoin(joins_allowed) => {
                self.key_section.set_node_join_flag(joins_allowed).await
            }
        }
    }

    ///
    async fn new_node_joined(&mut self, name: XorName) -> Result<NodeOperation> {
        self.data_section.new_node_joined(name).await
    }

    async fn increase_full_node_count(&mut self, node_id: PublicKey) {
        self.key_section.increase_full_node_count(node_id).await;
    }

    ///
    async fn relocated_node_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Result<NodeOperation> {
        self.data_section
            .relocated_node_joined(old_node_id, new_node_id, age)
            .await
    }

    ///
    async fn member_left(&mut self, node_id: XorName, age: u8) -> Result<NodeOperation> {
        self.data_section.member_left(node_id, age).await
    }

    ///
    async fn elders_changed(&mut self, prefix: Prefix) -> Result<NodeOperation> {
        let mut ops = Vec::new();
        match self.key_section.elders_changed().await? {
            NodeOperation::NoOp => (),
            op => ops.push(op),
        };
        debug!("Key section completed elder change update.");
        match self.data_section.elders_changed().await? {
            NodeOperation::NoOp => (),
            op => ops.push(op),
        };
        debug!("Data section completed elder change update.");
        if prefix != self.prefix {
            debug!("Prefix changed, i.e. split occurred!");
            match self.key_section.section_split(prefix).await? {
                NodeOperation::NoOp => (),
                op => ops.push(op),
            };
            match self.data_section.section_split(prefix).await? {
                NodeOperation::NoOp => (),
                op => ops.push(op),
            };
        }

        Ok(ops.into())
    }
}

impl Display for ElderDuties {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ElderDuties")
    }
}
