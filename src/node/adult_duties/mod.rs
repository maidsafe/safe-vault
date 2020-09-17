// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunks;

use self::chunks::Chunks;
use crate::{
    node::node_ops::{AdultDuty, ChunkDuty, NodeOperation},
    node::state_db::NodeInfo,
    Result,
};
use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

/// The main duty of an Adult node is
/// storage and retrieval of data chunks.
pub struct AdultDuties {
    chunks: Chunks,
}

impl AdultDuties {
    pub fn new(node_info: &NodeInfo, total_used_space: &Rc<Cell<u64>>) -> Result<Self> {
        let chunks = Chunks::new(node_info, &total_used_space)?;
        Ok(Self { chunks })
    }

    pub fn process_adult_duty(&mut self, duty: &AdultDuty) -> Option<NodeOperation> {
        use AdultDuty::*;
        use ChunkDuty::*;
        let RunAsChunks(chunk_duty) = duty;
        let result = match chunk_duty {
            ReadChunk(msg) | WriteChunk(msg) => self.chunks.receive_msg(msg),
        };

        result.map(|c| c.into())
    }
}

impl Display for AdultDuties {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "AdultDuties")
    }
}
