// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunks;

use self::chunks::{Chunks, UsedSpace};
use crate::node::msg_wrapping::AdultMsgWrapping;
use crate::{
    node::node_ops::{AdultDuty, Blah, ChunkDuty, NodeOperation},
    node::state_db::NodeInfo,
    Result,
};
use log::{error, info};
use sn_data_types::{
    AdultDuties::ChunkStorage, Message, MessageId, MsgEnvelope, MsgSender, NodeCmd, NodeDataCmd,
};
use std::fmt::{self, Display, Formatter};

/// The main duty of an Adult node is
/// storage and retrieval of data chunks.
pub struct AdultDuties {
    chunks: Chunks,
    msg_wrapping: AdultMsgWrapping,
}

impl AdultDuties {
    pub async fn new(node_info: &NodeInfo, used_space: UsedSpace) -> Result<Self> {
        let chunks = Chunks::new(node_info, used_space).await?;
        let msg_wrapping = AdultMsgWrapping::new(node_info.keys(), ChunkStorage);
        Ok(Self {
            chunks,
            msg_wrapping,
        })
    }

    pub async fn process_adult_duty(&mut self, duty: AdultDuty) -> Result<NodeOperation> {
        use AdultDuty::*;
        use ChunkDuty::*;
        let result = match duty {
            RunAsChunks(chunk_duty) => match chunk_duty {
                ReadChunk(msg) | WriteChunk(msg) => self.chunks.receive_msg(msg).await,
                ChunkDuty::NoOp => return Ok(NodeOperation::NoOp),
            },
            RequestForChunk {
                section_authority,
                address,
                targets,
            } => {
                info!("Creating new MsgEnvelope for getting duplicate chunk from current_holders");
                let msg = Message::NodeCmd {
                    cmd: NodeCmd::Data(NodeDataCmd::GetChunk {
                        section_authority,
                        address,
                        new_holder: self.msg_wrapping.name().await,
                        fetch_from_holders: targets.clone(),
                    }),
                    id: MessageId::new(),
                };
                let (pk, sign) = self.msg_wrapping.sign(&msg).await?;
                let origin = MsgSender::adult(pk, ChunkStorage, sign)?;
                let env = MsgEnvelope {
                    message: msg,
                    origin,
                    proxies: vec![],
                };
                info!("Sending to existing Holders");
                self.msg_wrapping.send_to_adults(&env, targets).await
            }
            ReplyForDuplication {
                address,
                new_holder,
                correlation_id,
                ..
            } => {
                let res = self.chunks.get_chunk_for_duplication(&address);
                match res {
                    Ok(blob) => {
                        let msg = Message::NodeCmd {
                            cmd: NodeCmd::Data(NodeDataCmd::GiveChunk {
                                blob,
                                new_holder,
                                correlation_id,
                            }),
                            id: MessageId::new(),
                        };
                        info!("Send blob for duplication to the NewHolder");
                        self.msg_wrapping.send_to_node(msg).await
                    }
                    Err(e) => {
                        // TODO: Penalise adult for this behaviour
                        error!("Chunk doesn't exist at current holder for Duplication. But it should. Check Logic");
                        Err(e)
                    }
                }
            }
            StoreDuplicatedBlob { blob } => self.chunks.store_duplicated_chunk(blob).await,
            _ => return Ok(NodeOperation::NoOp),
        };

        result.convert()
    }
}

impl Display for AdultDuties {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "AdultDuties")
    }
}
