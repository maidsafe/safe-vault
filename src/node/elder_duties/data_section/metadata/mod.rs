// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod account_storage;
mod blob_register;
mod elder_stores;
mod map_storage;
mod reading;
mod sequence_storage;
mod writing;

use crate::{
    capacity::ChunkHolderDbs,
    chunk_store::UsedSpace,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{IntoNodeOp, MetadataDuty, NodeOperation},
    node::state_db::NodeInfo,
    Error, Network, Result,
};
use account_storage::AccountStorage;
use blob_register::BlobRegister;
use elder_stores::ElderStores;
use map_storage::MapStorage;
use sequence_storage::SequenceStorage;
use sn_data_types::{ElderDuties, Message, MsgEnvelope};
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
    #[allow(unused)]
    wrapping: ElderMsgWrapping,
}

impl Metadata {
    pub async fn new(
        node_info: &NodeInfo,
        dbs: ChunkHolderDbs,
        used_space: UsedSpace,
        routing: Network,
    ) -> Result<Self> {
        let wrapping = ElderMsgWrapping::new(node_info.keys(), ElderDuties::Metadata);
        let account_storage =
            AccountStorage::new(node_info, used_space.clone(), wrapping.clone()).await?;
        let blob_register = BlobRegister::new(dbs, wrapping.clone(), routing)?;
        let map_storage = MapStorage::new(node_info, used_space.clone(), wrapping.clone()).await?;
        let sequence_storage =
            SequenceStorage::new(node_info, used_space.clone(), wrapping.clone()).await?;
        let elder_stores = ElderStores::new(
            account_storage,
            blob_register,
            map_storage,
            sequence_storage,
        );
        Ok(Self {
            elder_stores,
            wrapping,
        })
    }

    pub async fn process_metadata_duty(&mut self, duty: MetadataDuty) -> Result<NodeOperation> {
        use MetadataDuty::*;
        match duty {
            ProcessRead(msg) | ProcessWrite(msg) => self.process_msg(msg).await,
            NoOp => Ok(NodeOperation::NoOp),
        }
    }

    async fn process_msg(&mut self, msg: MsgEnvelope) -> Result<NodeOperation> {
        match &msg.message {
            Message::Cmd { .. } => writing::get_result(msg, &mut self.elder_stores).await,
            Message::Query { .. } => reading::get_result(msg, &self.elder_stores).await.convert(),
            _ => Err(Error::Logic(
                "Only Queries and Cmds from client can be handled at Metadata".to_string(),
            )), // only Queries and Cmds from client is handled at Metadata
        }
    }

    // This should be called whenever a node leaves the section. It fetches the list of data that was
    // previously held by the node and requests the other holders to store an additional copy.
    // The list of holders is also updated by removing the node that left.
    pub async fn trigger_chunk_replication(&mut self, node: XorName) -> Result<NodeOperation> {
        self.elder_stores
            .blob_register_mut()
            .replicate_chunks(node)
            .await
    }
}

impl Display for Metadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Metadata")
    }
}
