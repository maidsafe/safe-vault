// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunks;

use self::chunks::{Chunks, UsedSpace};
use crate::{
    node::node_ops::{AdultDuty, ChunkDuty, NodeOperation},
    node::state_db::NodeInfo,
    Outcome, Result, TernaryResult,
};
use std::fmt::{self, Display, Formatter};

/// The main duty of an Adult node is
/// storage and retrieval of data chunks.
pub struct AdultDuties {
    chunks: Chunks,
}

impl AdultDuties {
    pub async fn new(node_info: &NodeInfo, used_space: UsedSpace) -> Result<Self> {
        let chunks = Chunks::new(node_info, used_space).await?;
        Ok(Self { chunks })
    }

    pub async fn process_adult_duty(&mut self, duty: &AdultDuty) -> Outcome<NodeOperation> {
        use AdultDuty::*;
        use ChunkDuty::*;
        let RunAsChunks(chunk_duty) = duty;
        let result = match chunk_duty {
            ReadChunk(msg) | WriteChunk(msg) => self.chunks.receive_msg(msg).await,
        };

        result.asdf()
    }
}

impl Display for AdultDuties {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "AdultDuties")
    }
}
