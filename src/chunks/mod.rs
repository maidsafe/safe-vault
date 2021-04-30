// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunk_storage;

use crate::{
    error::convert_to_error_message,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Result,
};
use chunk_storage::ChunkStorage;
use log::{info, warn};
use sn_data_types::{Blob, BlobAddress};
use sn_messaging::{
    client::{BlobRead, BlobWrite, CmdError, Message, NodeEvent},
    Aggregation, DstLocation, EndUser, MessageId,
};
use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};

/// At 50% full, the node will report that it's reaching full capacity.
pub const MAX_STORAGE_USAGE_RATIO: f64 = 0.5;

/// Operations on data chunks.
pub(crate) struct Chunks {
    chunk_storage: ChunkStorage,
}

impl Chunks {
    pub async fn new(path: &Path, max_capacity: u64) -> Result<Self> {
        Ok(Self {
            chunk_storage: ChunkStorage::new(path, max_capacity).await?,
        })
    }

    pub fn keys(&self) -> Vec<BlobAddress> {
        self.chunk_storage.keys()
    }

    pub async fn remove_chunk(&mut self, address: &BlobAddress) -> Result<Blob> {
        let chunk = self.chunk_storage.get_chunk(address)?;
        if let Err(err) = self.chunk_storage.delete_chunk(address).await {
            warn!("Error deleting chunk at {:?}: {:?}", address, err);
        }
        Ok(chunk)
    }

    pub fn read(&mut self, read: &BlobRead, msg_id: MessageId) -> NodeDuties {
        let BlobRead::Get(address) = read;
        self.chunk_storage.get(address, msg_id)
    }

    pub async fn write(
        &mut self,
        write: &BlobWrite,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        match &write {
            BlobWrite::New(data) => self.chunk_storage.store(&data, msg_id).await,
            // really though, for a delete, what we should be looking at is the origin signature! That would be the source of truth!
            BlobWrite::DeletePrivate(address) => {
                self.chunk_storage.delete(*address, msg_id, origin).await
            }
        }
    }

    pub async fn check_storage(&self) -> Result<NodeDuties> {
        info!("Checking used storage");
        if self.chunk_storage.used_space_ratio().await > MAX_STORAGE_USAGE_RATIO {
            Ok(NodeDuties::from(NodeDuty::ReachingMaxCapacity))
        } else {
            Ok(vec![])
        }
    }

    /// Stores a chunk that Elders sent to it for replication.
    pub async fn store_for_replication(
        &mut self,
        blob: Blob,
        msg_id: MessageId,
    ) -> Result<NodeDuty> {
        let data_name = *blob.address().name();
        let result = match self.chunk_storage.store_for_replication(blob).await {
            Ok(()) => Ok(()),
            Err(err) => Err(CmdError::Data(convert_to_error_message(err)?)),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeEvent {
                event: NodeEvent::ChunkWriteHandled(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // sent as single node
            // Data's metadata section
            dst: DstLocation::Section(data_name),
            aggregation: Aggregation::None,
        }))
    }
}

impl Display for Chunks {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Chunks")
    }
}
