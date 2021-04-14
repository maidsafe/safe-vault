// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunk_storage;
mod reading;
mod writing;

use crate::{
    chunk_store::UsedSpace,
    node_ops::{NodeDuties, NodeDuty},
    Result,
};
use chunk_storage::ChunkStorage;
use log::info;
use sn_data_types::{Blob, BlobAddress};
use sn_messaging::{
    client::{BlobRead, BlobWrite},
    EndUser, MessageId, SrcLocation,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    path::Path,
};
use xor_name::XorName;

/// At 50% full, the node will report that it's reaching full capacity.
pub const MAX_STORAGE_USAGE_RATIO: f64 = 0.5;

/// Operations on data chunks.
pub(crate) struct Chunks {
    chunk_storage: ChunkStorage,
}

impl Chunks {
    pub async fn new(node_name: XorName, path: &Path, used_space: UsedSpace) -> Result<Self> {
        Ok(Self {
            chunk_storage: ChunkStorage::new(node_name, path, used_space).await?,
        })
    }

    pub async fn read(
        &mut self,
        read: &BlobRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        reading::get_result(read, msg_id, origin, &self.chunk_storage).await
    }

    pub async fn write(
        &mut self,
        write: &BlobWrite,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        writing::get_result(write, msg_id, origin, &mut self.chunk_storage).await
    }

    pub async fn check_storage(&self) -> Result<NodeDuties> {
        info!("Checking used storage");
        if self.chunk_storage.used_space_ratio().await > MAX_STORAGE_USAGE_RATIO {
            Ok(NodeDuties::from(NodeDuty::ReachingMaxCapacity))
        } else {
            Ok(vec![])
        }
    }

    /// Returns a chunk to the Elders of a section.
    pub async fn get_chunk_for_replication(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        section: XorName,
    ) -> Result<NodeDuty> {
        info!("Send blob for replication to the Elders.");
        self.chunk_storage
            .get_for_replication(address, msg_id, section)
            .await
    }

    /// Stores a chunk that Elders sent to it for replication.
    pub async fn store_for_replication(&mut self, blob: Blob) -> Result<()> {
        self.chunk_storage.store_for_replication(blob).await
    }
}

impl Display for Chunks {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Chunks")
    }
}
