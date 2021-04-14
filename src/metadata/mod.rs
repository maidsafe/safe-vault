// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod adult_reader;
mod blob_register;
mod elder_stores;
mod map_storage;
mod reading;
mod sequence_storage;
mod writing;

use self::adult_reader::AdultReader;
use super::node_ops::NodeDuty;
use crate::{
    capacity::ChunkHolderDbs, chunk_store::UsedSpace, network::Network, node_ops::NodeDuties,
    Result,
};
use blob_register::BlobRegister;
use elder_stores::ElderStores;
use map_storage::MapStorage;
use sequence_storage::SequenceStorage;
use sn_data_types::Blob;
use sn_messaging::{
    client::{DataCmd, DataQuery},
    EndUser, MessageId,
};
use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};
use xor_name::XorName;

/// This module is called `Metadata`
/// as a preparation for the responsibilities
/// it will have eventually, after `Data Hierarchy Refinement`
/// has been implemented; where the data types are all simply
/// the structures + their metadata - handled at `Elders` - with
/// all underlying data being chunks stored at `Adults`.
pub struct Metadata {
    elder_stores: ElderStores,
}

impl Metadata {
    pub async fn new(
        path: &Path,
        used_space: &UsedSpace,
        dbs: ChunkHolderDbs,
        reader: AdultReader,
    ) -> Result<Self> {
        let blob_register = BlobRegister::new(dbs, reader);
        let map_storage = MapStorage::new(path, used_space.clone()).await?;
        let sequence_storage = SequenceStorage::new(path, used_space.clone()).await?;
        let elder_stores = ElderStores::new(blob_register, map_storage, sequence_storage);
        Ok(Self { elder_stores })
    }

    pub async fn read(&self, query: DataQuery, id: MessageId, origin: EndUser) -> Result<NodeDuty> {
        reading::get_result(query, id, origin, &self.elder_stores).await
    }

    pub async fn write(
        &mut self,
        cmd: DataCmd,
        id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        writing::get_result(cmd, id, origin, &mut self.elder_stores).await
    }

    // This should be called whenever a node leaves the section. It fetches the list of data that was
    // previously held by the node and requests the remaining holders to return that chunk to us.
    // The list of holders is also updated by removing the node that left.
    // When receiving the chunk from remaining holders, we ask new holders to store it.
    pub async fn trigger_chunk_replication(&mut self, node: XorName) -> Result<NodeDuties> {
        self.elder_stores
            .blob_register_mut()
            .begin_replicate_chunks(node)
            .await
    }

    // When receiving the chunk from remaining holders, we ask new holders to store it.
    pub async fn finish_chunk_replication(&mut self, data: Blob) -> Result<NodeDuty> {
        self.elder_stores
            .blob_register_mut()
            .replicate_chunk(data)
            .await
    }
}

impl Display for Metadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Metadata")
    }
}
