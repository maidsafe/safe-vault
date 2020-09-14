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
    node::node_ops::{ElderDuty, NodeOperation},
    node::state_db::NodeInfo,
    Error, Network, Result,
};
use log::trace;
use rand::{CryptoRng, Rng};
use sn_routing::Prefix;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex};
use xor_name::XorName;

/// Duties carried out by an Elder node.
pub struct ElderDuties<R: CryptoRng + Rng> {
    prefix: Prefix,
    key_section: KeySection<R>,
    data_section: DataSection,
}

impl<R: CryptoRng + Rng> ElderDuties<R> {
    pub async fn new(
        info: &NodeInfo,
        total_used_space: &Arc<Mutex<u64>>,
        routing: Network,
        rng: R,
    ) -> Result<Self> {
        let prefix = routing.our_prefix().await.ok_or(Error::Logic)?;
        let key_section = KeySection::new(info, routing.clone(), rng).await?;
        let data_section = DataSection::new(info, total_used_space, routing).await?;
        Ok(Self {
            prefix,
            key_section,
            data_section,
        })
    }

    /// Issues queries to Elders of the section
    /// as to catch up with shares state and
    /// start working properly in the group.
    pub fn initiate(&mut self) -> Option<NodeOperation> {
        // currently only key section needs to catch up
        self.key_section.catchup_with_section()
    }

    /// Processing of any Elder duty.
    pub async fn process(&mut self, duty: ElderDuty) -> Option<NodeOperation> {
        trace!("Processing elder duty");
        use ElderDuty::*;
        match duty {
            ProcessNewMember(name) => self.new_node_joined(name),
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
            RunAsKeySection(mut the_key_duty) => self.key_section.process(&mut the_key_duty).await,
            RunAsDataSection(duty) => self.data_section.process(duty).await,
        }
    }

    ///
    fn new_node_joined(&mut self, name: XorName) -> Option<NodeOperation> {
        self.data_section.new_node_joined(name)
    }

    ///
    async fn relocated_node_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Option<NodeOperation> {
        self.data_section
            .relocated_node_joined(old_node_id, new_node_id, age)
            .await
    }

    ///
    async fn member_left(&mut self, node_id: XorName, age: u8) -> Option<NodeOperation> {
        self.data_section.member_left(node_id, age).await
    }

    ///
    async fn elders_changed(&mut self, prefix: Prefix) -> Option<NodeOperation> {
        let mut ops = vec![
            self.key_section.elders_changed().await,
            self.data_section.elders_changed().await,
        ];

        if prefix != self.prefix {
            // section has split!
            self.prefix = prefix;
            ops.push(self.key_section.section_split(prefix));
            ops.push(self.data_section.section_split(prefix).await);
        }

        Some(ops.into())
    }
}

impl<R: CryptoRng + Rng> Display for ElderDuties<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ElderDuties")
    }
}
