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
    rewards::{Rewards, Validator},
};

use crate::{
    node::node_ops::{DataSectionDuty, NodeOperation, RewardDuty},
    node::section_querying::SectionQuerying,
    node::state_db::NodeInfo,
    utils, Result,
};
use routing::Node as Routing;
use safe_nd::XorName;
use safe_transfers::TransferActor;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

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
    #[allow(dead_code)]
    /// The transport layer.
    routing: Rc<RefCell<Routing>>,
}

impl DataSection {
    ///
    pub fn new(
        info: NodeInfo,
        total_used_space: &Rc<Cell<u64>>,
        routing: Rc<RefCell<Routing>>,
    ) -> Result<Self> {
        let section_querying = SectionQuerying::new(routing.clone());

        // Metadata
        let metadata = Metadata::new(info.clone(), &total_used_space, section_querying)?;

        // Rewards
        let keypair = utils::key_pair(routing.clone())?;
        let public_key_set = routing.borrow().public_key_set()?.clone();
        let actor = TransferActor::new(keypair, public_key_set, Validator {});
        let rewards = Rewards::new(info.keys, actor);

        Ok(Self {
            metadata,
            rewards,
            routing,
        })
    }

    pub fn process(&mut self, duty: DataSectionDuty) -> Option<NodeOperation> {
        use DataSectionDuty::*;
        match duty {
            RunAsMetadata(duty) => self.metadata.process(&duty),
            RunAsRewards(duty) => self.rewards.process(duty),
        }
    }

    #[allow(dead_code)]
    // Transition the section funds account to the new key.
    pub fn elders_changed(&mut self) -> Option<NodeOperation> {
        let pub_key_set = self.routing.borrow().public_key_set().ok()?.clone();
        let keypair = utils::key_pair(self.routing.clone()).ok()?;
        let actor = TransferActor::new(keypair, pub_key_set, Validator {});
        self.rewards.transition(actor)
    }

    pub fn relocated_member_joined(
        &mut self,
        old_node_id: XorName,
        new_node_id: XorName,
    ) -> Option<NodeOperation> {
        // Adds the relocated account.
        let first = self.rewards.process(RewardDuty::AddRelocatedAccount {
            old_node_id,
            new_node_id,
        });
        let second = self.metadata.trigger_chunk_duplication(new_node_id);
        Some(vec![first, second].into())
    }

    /// Name of the node
    /// Age of the node
    pub fn member_left(&mut self, node_id: XorName, _age: u8) -> Option<NodeOperation> {
        // marks the reward account as
        // awaiting claiming of the counter
        let first = self
            .rewards
            .process(RewardDuty::PrepareAccountMove { node_id });
        let second = self.metadata.trigger_chunk_duplication(node_id);
        Some(vec![first, second].into())
    }
}
