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
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Error, Result,
};
use log::{error, info};
use sn_data_types::{Blob, BlobAddress, DataAddress};
use sn_messaging::{
    client::{CmdError, Error as ErrorMessage, Message, NodeEvent, QueryResponse},
    Aggregation, DstLocation, EndUser, MessageId,
};
use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};

/// Storage of data chunks.
pub(crate) struct ChunkStorage {
    chunks: BlobChunkStore,
}

impl ChunkStorage {
    #[allow(dead_code)]
    pub(crate) async fn new(path: &Path, max_capacity: u64) -> Result<Self> {
        let chunks = BlobChunkStore::new(path, max_capacity).await?;
        Ok(Self { chunks })
    }

    pub fn keys(&self) -> Vec<BlobAddress> {
        self.chunks.keys()
    }

    pub(crate) async fn store(&mut self, data: &Blob, msg_id: MessageId) -> Result<NodeDuty> {
        let result = match self.try_store(data).await {
            Ok(()) | Err(Error::DataExists) => Ok(()), // if the data already exists we are fine too
            Err(other) => Err(CmdError::Data(convert_to_error_message(other)?)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeEvent {
                event: NodeEvent::ChunkWriteHandled(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // sent as single node
            // Data's metadata section
            dst: DstLocation::Section(*data.address().name()),
            aggregation: Aggregation::None,
        }))
    }

    async fn try_store(&mut self, data: &Blob) -> Result<()> {
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

    pub(crate) fn get_chunk(&self, address: &BlobAddress) -> Result<Blob> {
        self.chunks.get(address)
    }

    pub(crate) async fn delete_chunk(&mut self, address: &BlobAddress) -> Result<()> {
        self.chunks.delete(&address).await
    }

    pub(crate) fn get(&self, address: &BlobAddress, msg_id: MessageId) -> NodeDuties {
        let mut ops = vec![];
        let result = self
            .get_chunk(address)
            .map_err(|_| ErrorMessage::DataNotFound(DataAddress::Blob(*address)));

        // Sent back to data's metadata section, who will then
        // forward it to client after having recorded the adult liveness.
        ops.push(NodeDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                id: MessageId::in_response_to(&msg_id),
                response: QueryResponse::GetBlob(result),
                correlation_id: msg_id,
            },
            section_source: false, // sent as single node
            dst: DstLocation::Section(*address.name()),
            aggregation: Aggregation::None,
        }));

        ops
    }

    /// Stores a chunk that Elders sent to it for replication.
    pub async fn store_for_replication(&mut self, blob: Blob) -> Result<()> {
        if self.chunks.has(blob.address()) {
            info!(
                "{}: Immutable chunk already exists, not storing: {:?}",
                self,
                blob.address()
            );
            return Ok(());
        }

        self.chunks.put(&blob).await?;

        Ok(())
    }

    pub async fn used_space_ratio(&self) -> f64 {
        self.chunks.used_space_ratio().await
    }

    pub(crate) async fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        if !self.chunks.has(&address) {
            info!("{}: Immutable chunk doesn't exist: {:?}", self, address);
            return Ok(NodeDuty::NoOp);
        }

        let result = match self.chunks.get(&address) {
            Ok(Blob::Private(data)) => {
                if data.owner() == origin.id() {
                    self.delete_chunk(&address)
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
                Err(ErrorMessage::InvalidOperation(format!(
                    "{}: Invalid DeletePrivate(Blob::Public) encountered: {:?}",
                    self, msg_id
                )))
            }
            _ => Err(ErrorMessage::NoSuchKey),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeEvent {
                event: NodeEvent::ChunkWriteHandled(result.map_err(CmdError::Data)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // sent as single node
            // respond to data's metadata elders
            dst: DstLocation::Section(*address.name()),
            aggregation: Aggregation::None,
        }))
    }
}

impl Display for ChunkStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ChunkStorage")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use bls::SecretKey;
    use sn_data_types::{PrivateBlob, PublicBlob, PublicKey};
    use std::path::PathBuf;
    use tempdir::TempDir;

    fn temp_dir() -> Result<TempDir> {
        TempDir::new("test").map_err(|e| Error::TempDirCreationFailed(e.to_string()))
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }

    #[tokio::test]
    pub async fn try_store_stores_public_blob() -> Result<()> {
        let path = PathBuf::from(temp_dir()?.path());
        let mut storage = ChunkStorage::new(&path, u64::MAX).await?;
        let value = "immutable data value".to_owned().into_bytes();
        let blob = Blob::Public(PublicBlob::new(value));
        assert!(storage.try_store(&blob).await.is_ok());
        assert!(storage.chunks.has(blob.address()));

        Ok(())
    }

    #[tokio::test]
    pub async fn try_store_stores_private_blob() -> Result<()> {
        let path = PathBuf::from(temp_dir()?.path());
        let mut storage = ChunkStorage::new(&path, u64::MAX).await?;
        let value = "immutable data value".to_owned().into_bytes();
        let key = get_random_pk();
        let blob = Blob::Private(PrivateBlob::new(value, key));
        assert!(storage.try_store(&blob).await.is_ok());
        assert!(storage.chunks.has(blob.address()));

        Ok(())
    }
}
