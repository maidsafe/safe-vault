// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunk_dbs;
mod rate_limit;

pub use chunk_dbs::ChunkHolderDbs;
pub use rate_limit::RateLimit;
use sn_data_types::PublicKey;

/// A util for sharing the
/// info on data capacity among the
/// chunk storing nodes in the section.
pub struct Capacity {
    dbs: ChunkHolderDbs,
}

impl Capacity {
    /// Pass in dbs with info on chunk holders.
    pub(super) fn new(dbs: ChunkHolderDbs) -> Self {
        Self { dbs }
    }

    /// Number of full chunk storing nodes in the section.
    pub fn full_nodes(&self) -> u8 {
        self.dbs.full_adults.borrow().total_keys() as u8
    }

    ///
    pub fn increase_full_node_count(&mut self, node_id: PublicKey) {
        let _ = self
            .dbs
            .full_adults
            .borrow_mut()
            .ladd(&node_id.to_string(), &"");
    }
}
