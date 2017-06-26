// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

/// Poll events
pub mod poll;
/// Test client node
pub mod test_client;
/// Test full node
pub mod test_node;

use GROUP_SIZE;
use itertools::Itertools;
use mock_crust_detail::test_node::TestNode;
use personas::data_manager::DataId;
use routing::{self, ImmutableData, MutableData, XorName, Xorable};
use std::collections::HashMap;

/// Type that can hold both immutable and mutable data.
#[derive(Clone)]
pub enum Data {
    /// Immutable data.
    Immutable(ImmutableData),
    /// Mutable data.
    Mutable(MutableData),
}

impl Data {
    fn id(&self) -> DataId {
        match *self {
            Data::Immutable(ref data) => DataId::immutable(*data.name()),
            Data::Mutable(ref data) => DataId::mutable(*data.name(), data.tag()),
        }
    }
}

/// Checks that the given `nodes` store the expected number of copies of the given data.
pub fn check_data<T>(all_data: T, nodes: &[TestNode])
    where T: IntoIterator<Item = Data>
{
    let mut data_holders_map: HashMap<(DataId, u64), Vec<XorName>> = HashMap::new();
    for node in nodes {
        for data_idv in unwrap!(node.get_stored_ids_and_versions()) {
            data_holders_map
                .entry(data_idv)
                .or_insert_with(Vec::new)
                .push(node.name());
        }
    }

    for data in all_data {
        let data_id = data.id();
        let data_version = match data {
            Data::Immutable(_) => 0,
            Data::Mutable(data) => data.version(),
        };

        let data_holders = data_holders_map
            .get(&(data_id, data_version))
            .cloned()
            .unwrap_or_else(Vec::new)
            .into_iter()
            .sorted_by(|left, right| data_id.name().cmp_distance(left, right));

        let mut expected_data_holders =
            nodes
                .iter()
                .map(TestNode::name)
                .sorted_by(|left, right| data_id.name().cmp_distance(left, right));
        expected_data_holders.truncate(GROUP_SIZE);

        if expected_data_holders != data_holders {
            panic!("Unexpected data holders for {:?}\n  expected: {:?}\n    actual: {:?}",
                   data_id,
                   expected_data_holders,
                   data_holders);
        }
    }
}

/// Verify that the network invariant is upheld for all nodes.
pub fn verify_network_invariant_for_all_nodes(nodes: &[TestNode]) {
    let routing_tables = nodes.iter().map(TestNode::routing_table).collect_vec();
    routing::verify_network_invariant(routing_tables);
}
