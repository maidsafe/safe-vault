// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adult_ops;
pub mod adult_reader;
mod blob_records;
mod elder_stores;
mod map_storage;
mod reading;
mod register_storage;
mod sequence_storage;
mod writing;

use self::adult_reader::AdultReader;
use super::node_ops::NodeDuty;
use crate::{capacity::ChunkHolderDbs, chunk_store::UsedSpace, node_ops::NodeDuties, Result};
use blob_records::BlobRecords;
use elder_stores::ElderStores;
use map_storage::MapStorage;
use register_storage::RegisterStorage;
use sequence_storage::SequenceStorage;
use sn_data_types::Blob;
use sn_messaging::{
    client::{DataCmd, DataExchange, DataQuery, NodeCmdResult, QueryResponse},
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
        let blob_records = BlobRecords::new(dbs, reader);
        let map_storage = MapStorage::new(path, used_space.clone()).await?;
        let sequence_storage = SequenceStorage::new(path, used_space.clone()).await?;
        let register_storage = RegisterStorage::new(path, used_space.clone()).await?;
        let elder_stores = ElderStores::new(
            blob_records,
            map_storage,
            sequence_storage,
            register_storage,
        );
        Ok(Self { elder_stores })
    }

    pub async fn read(
        &mut self,
        query: DataQuery,
        id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        reading::get_result(query, id, origin, &mut self.elder_stores).await
    }

    pub async fn process_blob_write_result(
        &mut self,
        msg_id: MessageId,
        result: NodeCmdResult,
        src: XorName,
    ) -> Result<NodeDuty> {
        self.elder_stores
            .blob_records_mut()
            .process_blob_write_result(msg_id, result, src)
            .await
    }

    pub async fn process_blob_read_result(
        &mut self,
        msg_id: MessageId,
        response: QueryResponse,
        src: XorName,
    ) -> Result<NodeDuty> {
        self.elder_stores
            .blob_records_mut()
            .process_blob_read_result(msg_id, response, src)
            .await
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
            .blob_records_mut()
            .begin_replicate_chunks(node)
            .await
    }

    // When receiving the chunk from remaining holders, we ask new holders to store it.
    pub async fn finish_chunk_replication(&mut self, data: Blob) -> Result<NodeDuty> {
        self.elder_stores
            .blob_records_mut()
            .replicate_chunk(data)
            .await
    }

    pub async fn get_data_exchange_packet(&self) -> Result<DataExchange> {
        self.elder_stores.get_all_data().await
    }

    pub async fn update(&mut self, data: DataExchange) -> Result<()> {
        self.elder_stores.update(data).await
    }
}

impl Display for Metadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Metadata")
    }
}
