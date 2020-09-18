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
    node::node_ops::{ElderDuty, NodeOperation},
    node::state_db::NodeInfo,
    Error, Network, Result,
};
use log::trace;
use rand::{CryptoRng, Rng};
use sn_routing::Prefix;
use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};
use xor_name::XorName;

/// Duties carried out by an Elder node.
pub struct ElderDuties<R: CryptoRng + Rng> {
    prefix: Prefix,
    key_section: KeySection<R>,
    data_section: DataSection,
}

impl<R: CryptoRng + Rng> ElderDuties<R> {
    pub fn new(
        info: &NodeInfo,
        total_used_space: &Rc<Cell<u64>>,
        network: Network,
        rng: R,
    ) -> Result<Self> {
        let prefix = network.our_prefix().ok_or(Error::Logic)?;
        let dbs = ChunkHolderDbs::new(info.path(), info.init_mode)?;
        let rate_limit = RateLimit::new(network.clone(), Capacity::new(dbs.clone()));
        let key_section = KeySection::new(info, rate_limit, network.clone(), rng)?;
        let data_section = DataSection::new(info, dbs, total_used_space, network)?;
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
    pub fn process_elder_duty(&mut self, duty: ElderDuty) -> Option<NodeOperation> {
        trace!("Processing elder duty");
        use ElderDuty::*;
        match duty {
            ProcessNewMember(name) => self.new_node_joined(name),
            ProcessLostMember { name, age } => self.member_left(name, age),
            ProcessRelocatedMember {
                old_node_id,
                new_node_id,
                age,
            } => self.relocated_node_joined(old_node_id, new_node_id, age),
            ProcessElderChange { prefix, .. } => self.elders_changed(prefix),
            RunAsKeySection(the_key_duty) => {
                self.key_section.process_key_section_duty(the_key_duty)
            }
            RunAsDataSection(duty) => self.data_section.process_data_section_duty(duty),
        }
    }

    ///
    fn new_node_joined(&mut self, name: XorName) -> Option<NodeOperation> {
        self.data_section.new_node_joined(name)
    }

    ///
    fn relocated_node_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
        age: u8,
    ) -> Option<NodeOperation> {
        self.data_section
            .relocated_node_joined(old_node_id, new_node_id, age)
    }

    ///
    fn member_left(&mut self, node_id: XorName, age: u8) -> Option<NodeOperation> {
        self.data_section.member_left(node_id, age)
    }

    ///
    fn elders_changed(&mut self, prefix: Prefix) -> Option<NodeOperation> {
        let mut ops = vec![
            self.key_section.elders_changed(),
            self.data_section.elders_changed(),
        ];

        if prefix != self.prefix {
            // section has split!
            self.prefix = prefix;
            ops.push(self.key_section.section_split(prefix));
            ops.push(self.data_section.section_split(prefix));
        }

        Some(ops.into())
    }
}

impl<R: CryptoRng + Rng> Display for ElderDuties<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ElderDuties")
    }
}
