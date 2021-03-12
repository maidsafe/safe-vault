// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod blob_register;
mod elder_stores;
mod map_storage;
mod reading;
mod sequence_storage;
mod writing;

use crate::{
    capacity::ChunkHolderDbs,
    node::node_ops::{MetadataDuty, NodeDuties},
    node::NodeInfo,
    node::RewardsAndWallets,
    Network, Result,
};
use blob_register::BlobRegister;
use elder_stores::ElderStores;
use map_storage::MapStorage;
use sequence_storage::SequenceStorage;
use sn_messaging::{
    client::{DataCmd, DataQuery},
    EndUser, MessageId,
};
use std::fmt::{self, Display, Formatter};
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
    pub async fn new(node_info: &NodeInfo, dbs: ChunkHolderDbs) -> Result<Self> {
        let blob_register = BlobRegister::new(dbs);
        let map_storage = MapStorage::new(node_info).await?;
        let sequence_storage = SequenceStorage::new(node_info).await?;
        let elder_stores = ElderStores::new(blob_register, map_storage, sequence_storage);
        Ok(Self { elder_stores })
    }

    pub async fn read(
        &mut self,
        query: DataQuery,
        id: MessageId,
        origin: EndUser,
        network: &Network,
    ) -> Result<()> {
        reading::get_result(query, id, origin, &self.elder_stores, network).await
    }

    pub async fn write(
        &mut self,
        cmd: DataCmd,
        id: MessageId,
        origin: EndUser,
        network: &Network,
    ) -> Result<()> {
        writing::get_result(cmd, id, origin, &mut self.elder_stores, network).await
    }

    // This should be called whenever a node leaves the section. It fetches the list of data that was
    // previously held by the node and requests the other holders to store an additional copy.
    // The list of holders is also updated by removing the node that left.
    pub async fn trigger_chunk_replication(
        &mut self,
        node: XorName,
        network: &Network,
    ) -> Result<NodeDuties> {
        self.elder_stores
            .blob_register_mut()
            .replicate_chunks(node, network)
            .await
    }
}

impl Display for Metadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Metadata")
    }
}
