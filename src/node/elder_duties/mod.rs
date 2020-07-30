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
    node::keys::NodeKeys,
    node::node_ops::{ElderDuty, NodeOperation},
    node::state_db::NodeInfo,
    Result,
};
use rand::{CryptoRng, Rng};
use routing::Node as Routing;
use safe_nd::XorName;
use std::{
    cell::{Cell, RefCell},
    fmt::{self, Display, Formatter},
    rc::Rc,
};

/// Duties carried out by an Elder node.
pub struct ElderDuties<R: CryptoRng + Rng> {
    keys: NodeKeys,
    key_section: KeySection<R>,
    data_section: DataSection,
}

impl<R: CryptoRng + Rng> ElderDuties<R> {
    pub fn new(
        info: NodeInfo,
        total_used_space: &Rc<Cell<u64>>,
        routing: Rc<RefCell<Routing>>,
        rng: R,
    ) -> Result<Self> {
        let key_section = KeySection::new(info.clone(), routing.clone(), rng)?;
        let data_section = DataSection::new(info.clone(), total_used_space, routing)?;

        Ok(Self {
            keys: info.keys,
            key_section,
            data_section,
        })
    }

    /// Issues a query to existing Replicas
    /// asking for their events, as to catch up and
    /// start working properly in the group.
    pub fn initiate(&mut self) -> Option<NodeOperation> {
        self.key_section.synch_with_replicas()
    }

    pub fn process(&mut self, duty: ElderDuty) -> Option<NodeOperation> {
        use ElderDuty::*;
        match duty {
            ProcessLostMember { name, age } => self.member_left(name, age),
            ProcessJoinedMember {
                old_node_id,
                new_node_id,
            } => self.relocated_member_joined(old_node_id, new_node_id),
            ProcessElderChange { .. } => self.elders_changed(),
            RunAsKeySection(duty) => self.key_section.process(duty),
            RunAsDataSection(duty) => self.data_section.process(duty),
        }
    }

    ///
    fn relocated_member_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
    ) -> Option<NodeOperation> {
        self.data_section
            .relocated_member_joined(old_node_id, new_node_id)
    }

    ///
    fn member_left(&mut self, node_id: XorName, age: u8) -> Option<NodeOperation> {
        self.data_section.member_left(node_id, age)
    }

    ///
    fn elders_changed(&mut self) -> Option<NodeOperation> {
        self.key_section.elders_changed()
        // Some(
        //     vec![
        //         self.key_section.elders_changed(),
        //         self.data_section.elders_changed(),
        //     ]
        //     .into(),
        // )
    }
}

impl<R: CryptoRng + Rng> Display for ElderDuties<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.keys.public_key())
    }
}
