// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::BlobChunkStore,
    error::convert_to_error_message,
    node::{
        node_ops::{NodeMessagingDuty, OutgoingMsg},
        Error,
    },
    AdultState, NodeInfo, Result,
};
use log::{error, info};
use sn_data_types::{Blob, BlobAddress};
use sn_messaging::{
    client::{CmdError, Error as ErrorMessage, QueryResponse},
    location::User,
    node::{NodeDataQueryResponse, NodeQuery, NodeQueryResponse, NodeSystemQuery},
    ClientMessage, DstLocation, MessageId, NodeMessage, SrcLocation,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

/// Storage of data chunks.
pub(crate) struct ChunkStorage {
    node_name: XorName,
    chunks: BlobChunkStore,
}

impl ChunkStorage {
    pub(crate) async fn new(node_info: &NodeInfo, adult_state: AdultState) -> Result<Self> {
        let chunks = BlobChunkStore::new(&node_info.root_dir, node_info.used_space.clone()).await?;
        Ok(Self {
            chunks,
            node_name: adult_state.node_name(),
        })
    }

    pub(crate) async fn store(
        &mut self,
        data: &Blob,
        msg_id: MessageId,
        origin: User,
    ) -> Result<NodeMessagingDuty> {
        if let Err(error) = self.try_store(data, origin).await {
            Ok(NodeMessagingDuty::Send(OutgoingMsg {
                msg: ClientMessage::CmdError {
                    error: CmdError::Data(convert_to_error_message(error)?),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                    cmd_origin: SrcLocation::User(origin),
                }
                .into(),
                dst: DstLocation::User(origin),
                to_be_aggregated: true,
            }))
        } else {
            Ok(NodeMessagingDuty::NoOp)
        }
    }

    // #[allow(unused)]
    // pub(crate) async fn take_replica(
    //     &mut self,
    //     data: &Blob,
    //     msg_id: MessageId,
    //     origin: SrcLocation,
    //     accumulated_signature: &Signature,
    // ) -> Result<NodeMessagingDuty> {
    //     let msg = match self.try_store(data, origin).await {
    //         Ok(()) => Message::NodeEvent {
    //             event: NodeEvent::ReplicationCompleted {
    //                 chunk: *data.address(),
    //                 proof: accumulated_signature.clone(),
    //             },
    //             id: MessageId::new(),
    //             correlation_id: msg_id,
    //         },
    //         Err(error) => {
    //             let message_error = convert_to_error_message(error)?;
    //             Message::NodeCmdError {
    //                 id: MessageId::new(),
    //                 error: NodeCmdError::Data(NodeDataError::ChunkReplication {
    //                     address: *data.address(),
    //                     error: message_error,
    //                 }),
    //                 correlation_id: msg_id,
    //                 cmd_origin: origin,
    //             }
    //         }
    //     };
    //     self.wrapping
    //         .send_to_node(Msg {
    //             msg,
    //             dst: origin.to_dst(),
    //         })
    //         .await
    // }

    async fn try_store(&mut self, data: &Blob, origin: User) -> Result<()> {
        info!("TRYING TO STORE BLOB");
        if data.is_private() {
            let data_owner = data
                .owner()
                .ok_or_else(|| Error::InvalidOwners(*origin.id()))?;
            info!("Blob is unpub");
            info!("DATA OWNER: {:?}", data_owner);
            info!("ORIGIN: {:?}", origin);
            if data_owner != origin.id() {
                info!("INVALID OWNER! Returning error");
                return Err(Error::InvalidOwners(*origin.id()));
            }
        }

        if self.chunks.has(data.address()) {
            info!(
                "{}: Immutable chunk already exists, not storing: {:?}",
                self,
                data.address()
            );
            return Err(Error::DataExists);
        }
        self.chunks.put(&data).await
    }

    pub(crate) async fn get(
        &self,
        address: &BlobAddress,
        msg_id: MessageId,
        origin: User,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .chunks
            .get(address)
            .map_err(|_| ErrorMessage::NoSuchData);
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: ClientMessage::QueryResponse {
                id: MessageId::in_response_to(&msg_id),
                response: QueryResponse::GetBlob(result),
                correlation_id: msg_id,
                query_origin: SrcLocation::User(origin),
            }
            .into(),
            dst: DstLocation::User(origin),
            to_be_aggregated: false,
        }))
    }

    pub async fn replicate_chunk(
        &self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
        //_msg_id: MessageId,
        //_origin: MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let msg = NodeMessage::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetChunk {
                address,
                new_holder: self.node_name,
                current_holders: current_holders.clone(),
            }),
            id: MessageId::new(),
        }
        .into();
        info!("Sending NodeSystemQuery::GetChunk to existing holders");

        Ok(NodeMessagingDuty::SendToAdults {
            msg,
            targets: current_holders,
        })
    }

    ///
    pub async fn get_for_replication(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        let result = match self.chunks.get(&address) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: NodeMessage::NodeQueryResponse {
                response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(result)),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            }
            .into(),
            dst: origin.to_dst(),
            to_be_aggregated: true,
        }))
    }

    ///
    pub async fn store_for_replication(&mut self, blob: Blob) -> Result<NodeMessagingDuty> {
        if self.chunks.has(blob.address()) {
            info!(
                "{}: Immutable chunk already exists, not storing: {:?}",
                self,
                blob.address()
            );
            return Ok(NodeMessagingDuty::NoOp);
        }

        let _ = self.chunks.put(&blob).await?;

        Ok(NodeMessagingDuty::NoOp)
    }

    pub async fn used_space_ratio(&self) -> f64 {
        self.chunks.used_space_ratio().await
    }

    // pub(crate) fn get_for_duplciation(
    //     &self,
    //     address: BlobAddress,
    //     msg: &Message,
    // ) -> Result<NodeMessagingDuty> {

    //     match self.chunks.get(&address) {

    //     }

    //     let mut targets: BTreeSet<XorName> = Default::default();
    //     let _ = targets.insert(XorName(xorname.0));
    //     Some(NodeMessagingDuty::SendToNode {
    //         targets,
    //         msg: Message::QueryResponse {
    //             requester: requester.clone(),
    //             response: Response::GetBlob(result),
    //             message_id,
    //             proof: Some((request, (accumulated_signature?).clone())),
    //         },
    //     })
    // }

    pub(crate) async fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: User,
    ) -> Result<NodeMessagingDuty> {
        if !self.chunks.has(&address) {
            info!("{}: Immutable chunk doesn't exist: {:?}", self, address);
            return Ok(NodeMessagingDuty::NoOp);
        }

        let result = match self.chunks.get(&address) {
            Ok(Blob::Private(data)) => {
                if data.owner() == origin.id() {
                    self.chunks
                        .delete(&address)
                        .await
                        .map_err(|_error| ErrorMessage::FailedToDelete)
                } else {
                    Err(ErrorMessage::InvalidOwners(*origin.id()))
                }
            }
            Ok(_) => {
                error!(
                    "{}: Invalid DeletePrivate(Blob::Public) encountered: {:?}",
                    self, msg_id
                );
                Err(ErrorMessage::InvalidOperation)
            }
            _ => Err(ErrorMessage::NoSuchKey),
        };

        if let Err(error) = result {
            return Ok(NodeMessagingDuty::Send(OutgoingMsg {
                msg: ClientMessage::CmdError {
                    error: CmdError::Data(error),
                    id: MessageId::new(),
                    correlation_id: msg_id,
                    cmd_origin: SrcLocation::User(origin),
                }
                .into(),
                dst: DstLocation::User(origin),
                to_be_aggregated: true,
            }));
        }
        Ok(NodeMessagingDuty::NoOp)
    }
}

impl Display for ChunkStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ChunkStorage")
    }
}
