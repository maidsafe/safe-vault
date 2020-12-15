// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use crate::chunk_store::UsedSpace;
use crate::node::{msg_wrapping::AdultMsgWrapping, node_ops::NodeMessagingDuty};
use crate::{chunk_store::BlobChunkStore, node::state_db::NodeInfo, Error, Result};
use log::{error, info};
use sn_data_types::{
    Address, AdultDuties, Blob, BlobAddress, CmdError, Error as NdError, Message, MessageId,
    MsgSender, NodeCmdError, NodeDataError, NodeDataQuery, NodeDataQueryResponse, NodeEvent,
    NodeQuery, NodeQueryResponse, QueryResponse, Result as NdResult, Signature,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

/// Storage of data chunks.
pub(crate) struct ChunkStorage {
    chunks: BlobChunkStore,
    wrapping: AdultMsgWrapping,
}

impl ChunkStorage {
    pub(crate) async fn new(node_info: &NodeInfo, used_space: UsedSpace) -> Result<Self> {
        let chunks = BlobChunkStore::new(node_info.path(), used_space, node_info.init_mode).await?;
        let wrapping = AdultMsgWrapping::new(node_info.keys(), AdultDuties::ChunkStorage);
        Ok(Self { chunks, wrapping })
    }

    pub(crate) async fn store(
        &mut self,
        data: &Blob,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        if let Err(error) = self.try_store(data, origin).await {
            return self
                .wrapping
                .error(CmdError::Data(error), msg_id, &origin.address())
                .await;
        }
        Ok(NodeMessagingDuty::NoOp)
    }

    #[allow(unused)]
    pub(crate) async fn take_replica(
        &mut self,
        data: &Blob,
        msg_id: MessageId,
        origin: &MsgSender,
        accumulated_signature: &Signature,
    ) -> Result<NodeMessagingDuty> {
        let message = match self.try_store(data, origin).await {
            Ok(()) => Message::NodeEvent {
                event: NodeEvent::ReplicationCompleted {
                    chunk: *data.address(),
                    proof: accumulated_signature.clone(),
                },
                id: MessageId::new(),
                correlation_id: msg_id,
            },
            Err(error) => Message::NodeCmdError {
                id: MessageId::new(),
                error: NodeCmdError::Data(NodeDataError::ChunkReplication {
                    address: *data.address(),
                    error,
                }),
                correlation_id: msg_id,
                cmd_origin: origin.address(),
            },
        };
        self.wrapping.send_to_node(message).await
    }

    async fn try_store(&mut self, data: &Blob, origin: &MsgSender) -> NdResult<()> {
        info!("TRYING TO STORE BLOB");
        let id = origin.id().public_key();

        if data.is_unpub() {
            let data_owner = *data.owner().ok_or(NdError::InvalidOwners)?;
            info!("Blob is unpub");
            info!("DATA OWNER: {:?}", data_owner);
            info!("ID OWNER: {:?}", id);
            if data_owner != id {
                info!("INVALID OWNER! Returning error");
                return Err(NdError::InvalidOwners);
            }
        }

        if self.chunks.has(data.address()) {
            info!(
                "{}: Immutable chunk already exists, not storing: {:?}",
                self,
                data.address()
            );
            return Err(NdError::DataExists);
        }
        self.chunks
            .put(&data)
            .await
            .map_err(|error| error.to_string().into())
    }

    pub(crate) async fn get(
        &self,
        address: &BlobAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .chunks
            .get(address)
            .map_err(|error| error.to_string().into());
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    id: MessageId::in_response_to(&msg_id),
                    response: QueryResponse::GetBlob(result),
                    correlation_id: msg_id,
                    query_origin: origin.address(),
                },
                true,
            )
            .await
    }

    pub async fn replicate_chunk(
        &self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
        section_authority: MsgSender,
        _msg_id: MessageId,
        _origin: Address,
    ) -> Result<NodeMessagingDuty> {
        let message = Message::NodeQuery {
            query: NodeQuery::Data(NodeDataQuery::GetChunk {
                section_authority,
                address,
                new_holder: self.wrapping.name().await,
                current_holders: current_holders.clone(),
            }),
            id: MessageId::new(),
        };
        info!("Sending NodeDataQuery::GetChunk to existing holders");
        self.wrapping
            .send_to_adults(message, current_holders, AdultDuties::ChunkReplication)
            .await
    }

    ///
    pub async fn get_for_replication(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .chunks
            .get(&address)
            .map_err(|error| error.to_string().into());

        self.wrapping
            .send_to_node(Message::NodeQueryResponse {
                response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(result)),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
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

        let _ = self.chunks.put(&blob).await.map_err(Error::ChunkStore)?;

        Ok(NodeMessagingDuty::NoOp)
    }

    pub async fn remaining_space_ratio(&self) -> f64 {
        self.chunks.remaining_space_ratio().await
    }

    // pub(crate) fn get_for_duplciation(
    //     &self,
    //     address: BlobAddress,
    //     msg: &MsgEnvelope,
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
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        if !self.chunks.has(&address) {
            info!("{}: Immutable chunk doesn't exist: {:?}", self, address);
            return Ok(NodeMessagingDuty::NoOp);
        }

        let result = match self.chunks.get(&address) {
            Ok(Blob::Private(data)) => {
                if *data.owner() == origin.id().public_key() {
                    self.chunks
                        .delete(&address)
                        .await
                        .map_err(|error| error.to_string().into())
                } else {
                    Err(NdError::InvalidOwners)
                }
            }
            Ok(_) => {
                error!(
                    "{}: Invalid DeletePrivate(Blob::Public) encountered: {:?}",
                    self, msg_id
                );
                Err(NdError::InvalidOperation)
            }
            _ => Err(NdError::NoSuchKey),
            //err @ Err(_) => err.map_err(|error| error.to_string().into()),
        };

        if let Err(error) = result {
            return self
                .wrapping
                .error(CmdError::Data(error), msg_id, &origin.address())
                .await;
        }
        Ok(NodeMessagingDuty::NoOp)
    }
}

impl Display for ChunkStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ChunkStorage")
    }
}
