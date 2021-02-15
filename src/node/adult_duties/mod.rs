// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunks;

use self::chunks::Chunks;
use crate::{
    node::node_ops::{
        AdultDuty, ChunkReplicationCmd, ChunkReplicationDuty, ChunkReplicationQuery,
        ChunkStoreDuty, IntoNodeOp,
    },
    AdultState, NodeInfo, Result,
};
use std::fmt::{self, Display, Formatter};

/// The main duty of an Adult node is
/// storage and retrieval of data chunks.
pub struct AdultDuties {
    state: AdultState,
    chunks: Chunks,
}

impl AdultDuties {
    pub async fn new(node_info: &NodeInfo, state: AdultState) -> Result<Self> {
        let chunks = Chunks::new(node_info, state.clone()).await?;
        Ok(Self { state, chunks })
    }

    ///
    pub fn state(&self) -> &AdultState {
        &self.state
    }

    pub async fn process_adult_duty(&mut self, duty: AdultDuty) -> Result<Vec<NetworkDuty>> {
        use AdultDuty::*;
        use ChunkReplicationCmd::*;
        use ChunkReplicationDuty::*;
        use ChunkReplicationQuery::*;
        use ChunkStoreDuty::*;
        let result: Result<Vec<NetworkDuty>> = match duty {
            RunAsChunkStore(chunk_duty) => match chunk_duty {
                ReadChunk { read, id, origin } => {
                    let mut ops = vec![];
                    ops.push(self.chunks.read(&read, id, origin).await.convert());
                    ops.push(self.chunks.check_storage().await);
                    Ok(ops.into())
                }
                WriteChunk { write, id, origin } => {
                    let mut ops = vec![];
                    ops.push(self.chunks.write(&write, id, origin).await.convert());
                    ops.push(self.chunks.check_storage().await);
                    Ok(ops.into())
                }
                ChunkStoreDuty::NoOp => return Ok(vec![]),
            },
            RunAsChunkReplication(replication_duty) => match replication_duty {
                ProcessQuery {
                    query: GetChunk(address),
                    msg_id,
                    origin,
                } => self
                    .chunks
                    .get_chunk_for_replication(address, msg_id, origin)
                    .await
                    .convert(),
                ProcessCmd { cmd, msg_id, .. } => match cmd {
                    StoreReplicatedBlob(blob) => {
                        self.chunks.store_replicated_chunk(blob).await.convert()
                    }
                    ReplicateChunk {
                        //section_authority,
                        address,
                        current_holders,
                    } => self
                        .chunks
                        .replicate_chunk(
                            address,
                            current_holders,
                            //section_authority,
                            msg_id,
                            //origin,
                        )
                        .await
                        .convert(),
                },
                ChunkReplicationDuty::NoOp => return Ok(vec![]),
            },
            _ => return Ok(vec![]),
        };

        result
    }
}

impl Display for AdultDuties {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "AdultDuties")
    }
}
