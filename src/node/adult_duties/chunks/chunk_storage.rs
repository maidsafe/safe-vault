// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use crate::chunk_store::UsedSpace;
use crate::node::{msg_wrapping::AdultMsgWrapping, node_ops::NodeMessagingDuty};
use crate::{chunk_store::BlobChunkStore, node::state_db::NodeInfo, Result};
use log::{error, info};
use sn_data_types::{
    AdultDuties, Blob, BlobAddress, CmdError, Error as NdError, Message, MessageId, MsgSender,
    NodeCmdError, NodeDataError, NodeEvent, QueryResponse, Result as NdResult, Signature,
};
use std::fmt::{self, Display, Formatter};

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
    ) -> Option<NodeMessagingDuty> {
        if let Err(error) = self.try_store(data).await {
            return self
                .wrapping
                .error(CmdError::Data(error), msg_id, &origin.address())
                .await;
        }
        None
    }

    #[allow(unused)]
    pub(crate) async fn take_duplicate(
        &mut self,
        data: &Blob,
        msg_id: MessageId,
        origin: &MsgSender,
        accumulated_signature: &Signature,
    ) -> Option<NodeMessagingDuty> {
        let message = match self.try_store(data).await {
            Ok(()) => Message::NodeEvent {
                event: NodeEvent::DuplicationComplete {
                    chunk: *data.address(),
                    proof: accumulated_signature.clone(),
                },
                id: MessageId::new(),
                correlation_id: msg_id,
            },
            Err(error) => Message::NodeCmdError {
                id: MessageId::new(),
                error: NodeCmdError::Data(NodeDataError::ChunkDuplication {
                    address: *data.address(),
                    error,
                }),
                correlation_id: msg_id,
                cmd_origin: origin.address(),
            },
        };
        self.wrapping.send(message).await
    }

    async fn try_store(&mut self, data: &Blob) -> NdResult<()> {
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
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .chunks
            .get(address)
            .map_err(|error| error.to_string().into());
        self.wrapping
            .send(Message::QueryResponse {
                id: MessageId::new(),
                response: QueryResponse::GetBlob(result),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    // pub(crate) fn get_for_duplciation(
    //     &self,
    //     address: BlobAddress,
    //     msg: &MsgEnvelope,
    // ) -> Option<NodeMessagingDuty> {

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
    ) -> Option<NodeMessagingDuty> {
        if !self.chunks.has(&address) {
            info!("{}: Immutable chunk doesn't exist: {:?}", self, address);
            return None;
        }

        let result = match self.chunks.get(&address) {
            Ok(Blob::Private(_)) => self
                .chunks
                .delete(&address)
                .await
                .map_err(|error| error.to_string().into()),
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
        None
    }
}

impl Display for ChunkStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ChunkStorage")
    }
}
