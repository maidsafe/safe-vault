// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunk_storage;
mod reading;
mod writing;

use crate::{node::node_ops::NodeMessagingDuty, node::state_db::NodeInfo, Error, Result};
use chunk_storage::ChunkStorage;

use log::{info, trace};
use sn_data_types::{
    Address, Blob, BlobAddress, Cmd, DataCmd, DataQuery, Message, MessageId, MsgEnvelope,
    MsgSender, Query,
};
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

/// Operations on data chunks.
pub(crate) struct Chunks {
    chunk_storage: ChunkStorage,
}
pub use chunk_storage::UsedSpace;

impl Chunks {
    pub async fn new(node_info: &NodeInfo, used_space: UsedSpace) -> Result<Self> {
        let chunk_storage = ChunkStorage::new(node_info, used_space).await?;
        Ok(Self { chunk_storage })
    }

    pub async fn receive_msg(&mut self, msg: MsgEnvelope) -> Result<NodeMessagingDuty> {
        trace!(
            "{}: Received ({:?} from src {:?}",
            self,
            msg.id(),
            msg.most_recent_sender().address(),
        );
        match &msg.message {
            Message::Query {
                query: Query::Data(DataQuery::Blob(ref read)),
                ..
            } => reading::get_result(read, msg.clone(), &self.chunk_storage).await,
            Message::Cmd {
                cmd:
                    Cmd::Data {
                        cmd: DataCmd::Blob(ref write),
                        ..
                    },
                ..
            } => writing::get_result(write, msg.clone(), &mut self.chunk_storage).await,
            _ => Err(Error::Logic(format!(
                "{:?}: Could not receive msg as Adult",
                msg.id()
            ))),
        }
    }

    // fn validate_section_signature(&self, request: &Request, signature: &Signature) -> Option<()> {
    //     if self
    //         .public_key()?
    //         .verify(signature, &utils::serialise(request))
    //     {
    //         Some(())
    //     } else {
    //         None
    //     }
    // }

    ///
    pub async fn replicate_chunk(
        &self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
        section_authority: MsgSender,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        info!("Creating new MsgEnvelope for acquiring chunk from current_holders");
        self.chunk_storage
            .replicate_chunk(address, current_holders, section_authority, msg_id, origin)
            .await
    }

    ///
    pub async fn get_chunk_for_replication(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        info!("Send blob for replication to the new holder.");
        self.chunk_storage
            .get_for_replication(address, msg_id, origin)
            .await
    }

    ///
    pub async fn store_replicated_chunk(&mut self, blob: Blob) -> Result<NodeMessagingDuty> {
        self.chunk_storage.store_for_replication(blob).await
    }
}

impl Display for Chunks {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Chunks")
    }
}
