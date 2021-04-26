use std::collections::{BTreeSet, HashMap, HashSet};

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use itertools::Itertools;
use sn_data_types::BlobAddress;
use sn_messaging::{client::BlobWrite, EndUser, MessageId};
use sn_routing::XorName;
use std::collections::hash_map::Entry;

const MAX_PENDING_OP_DIFFERENCE: usize = 5;
const NEIGHBOUR_COUNT: usize = 2;

#[derive(Clone)]
enum Operation {
    Read {
        address: BlobAddress,
        origin: EndUser,
        targets: BTreeSet<XorName>,
    },
    Write {
        blob_write: Box<BlobWrite>,
        origin: EndUser,
        targets: BTreeSet<XorName>,
    },
}

pub struct AdultLiveness {
    ops: HashMap<MessageId, Operation>,
    pending_ops: HashMap<XorName, usize>,
    closest_adults: HashMap<XorName, Vec<XorName>>,
}

impl AdultLiveness {
    pub fn new() -> Self {
        Self {
            ops: HashMap::default(),
            pending_ops: HashMap::default(),
            closest_adults: HashMap::default(),
        }
    }

    // Inserts a new write operation
    // Returns false if the operation already existed.
    pub fn new_write(
        &mut self,
        msg_id: MessageId,
        blob_write: BlobWrite,
        origin: EndUser,
        targets: BTreeSet<XorName>,
    ) -> bool {
        let new_operation = if let Entry::Vacant(entry) = self.ops.entry(msg_id) {
            let _ = entry.insert(Operation::Write {
                blob_write: Box::new(blob_write),
                origin,
                targets: targets.clone(),
            });
            true
        } else {
            false
        };
        if new_operation {
            self.increment_pending_op(&targets);
        }
        new_operation
    }

    // Inserts a new read operation
    // Returns false if the operation already existed.
    pub fn new_read(
        &mut self,
        msg_id: MessageId,
        address: BlobAddress,
        origin: EndUser,
        targets: BTreeSet<XorName>,
    ) -> bool {
        let new_operation = if let Entry::Vacant(entry) = self.ops.entry(msg_id) {
            let _ = entry.insert(Operation::Read {
                address,
                origin,
                targets: targets.clone(),
            });
            true
        } else {
            false
        };
        if new_operation {
            self.increment_pending_op(&targets);
        }
        new_operation
    }

    pub fn stop_tracking(&mut self, names: BTreeSet<XorName>) {
        for name in names {
            let _ = self.pending_ops.remove(&name);
            let _ = self.closest_adults.remove(&name);
            let message_ids = self.ops.keys().cloned().collect::<Vec<_>>();
            // TODO(after T4): For write operations perhaps we need to write it to a different Adult
            for msg_id in message_ids {
                self.remove_target(msg_id, name);
            }
        }
        self.recompute_closest_adults();
    }

    pub fn remove_target(&mut self, msg_id: MessageId, name: XorName) {
        if let Some(count) = self.pending_ops.get_mut(&name) {
            let counter = *count;
            if counter > 0 {
                *count -= 1;
            }
        }
        let complete = if let Some(operation) = self.ops.get_mut(&msg_id) {
            match operation {
                Operation::Read { targets, .. } => {
                    let _ = targets.remove(&name);
                    targets.is_empty()
                }
                Operation::Write { targets, .. } => {
                    let _ = targets.remove(&name);
                    targets.is_empty()
                }
            }
        } else {
            true
        };
        if complete {
            let _ = self.ops.remove(&msg_id);
        }
    }

    pub fn record_adult_write_liveness(
        &mut self,
        correlation_id: MessageId,
        src: XorName,
    ) -> Option<BlobWrite> {
        let op = self.ops.get(&correlation_id).cloned();
        self.remove_target(correlation_id, src);
        op.and_then(|op| match op {
            Operation::Write { blob_write, .. } => Some(*blob_write),
            Operation::Read { .. } => None,
        })
    }

    pub fn record_adult_read_liveness(
        &mut self,
        correlation_id: MessageId,
        src: XorName,
    ) -> Option<(BlobAddress, EndUser)> {
        let op = self.ops.get(&correlation_id).cloned();
        self.remove_target(correlation_id, src);
        op.and_then(|op| match op {
            Operation::Read {
                address, origin, ..
            } => Some((address, origin)),
            Operation::Write { .. } => None,
        })
    }

    fn increment_pending_op(&mut self, targets: &BTreeSet<XorName>) {
        for node in targets {
            *self.pending_ops.entry(*node).or_insert(0) += 1;
            if !self.closest_adults.contains_key(node) {
                let _ = self.closest_adults.insert(*node, Vec::new());
                self.recompute_closest_adults();
            }
        }
    }

    pub fn recompute_closest_adults(&mut self) {
        let adults = self.closest_adults.keys().cloned().collect::<HashSet<_>>();
        for adult in &adults {
            let closest_adults = adults
                .iter()
                .filter(|name| name != &adult)
                .sorted_by(|lhs, rhs| adult.cmp_distance(lhs, rhs))
                .take(NEIGHBOUR_COUNT)
                .cloned()
                .collect::<Vec<_>>();
            let _ = self.closest_adults.insert(*adult, closest_adults);
        }
    }

    pub fn find_unresponsive_adults(&self) -> Vec<(XorName, usize)> {
        let mut unresponsive_adults = Vec::new();
        for (adult, neighbours) in &self.closest_adults {
            if let Some(max_pending_by_neighbours) = neighbours
                .iter()
                .map(|neighbour| self.pending_ops.get(neighbour).cloned().unwrap_or(0))
                .max()
            {
                let our_pending_ops = *self.pending_ops.get(adult).unwrap_or(&0);
                if our_pending_ops.saturating_sub(max_pending_by_neighbours)
                    > MAX_PENDING_OP_DIFFERENCE
                {
                    log::info!(
                        "Our pending ops: {} Neighbour max: {}",
                        our_pending_ops,
                        max_pending_by_neighbours
                    );
                    unresponsive_adults.push((*adult, our_pending_ops));
                }
            }
        }
        unresponsive_adults
    }
}
