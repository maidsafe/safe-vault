// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::ChunkHolderDbs,
    error::convert_to_error_message,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{NodeMessagingDuty, NodeOperation},
    Error, Network, Result, ToDbKey,
};
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};
use sn_data_types::{Blob, BlobAddress, Error as DtError, PublicKey, Result as NdResult};
use sn_messaging::{
    BlobRead, BlobWrite, CmdError, DataQuery, Error as ErrorMessage, Message, MessageId, MsgSender,
    NodeCmd, NodeDataCmd, Query, QueryResponse,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

// The number of separate copies of a blob chunk which should be maintained.
const CHUNK_COPY_COUNT: usize = 4;

#[derive(Default, Debug, Serialize, Deserialize)]
struct ChunkMetadata {
    holders: BTreeSet<XorName>,
    owner: Option<PublicKey>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct HolderMetadata {
    chunks: BTreeSet<BlobAddress>,
}

/// Operations over the data type Blob.
pub(super) struct BlobRegister {
    dbs: ChunkHolderDbs,
    routing: Network,
    wrapping: ElderMsgWrapping,
}

impl BlobRegister {
    pub(super) fn new(
        dbs: ChunkHolderDbs,
        wrapping: ElderMsgWrapping,
        routing: Network,
    ) -> Result<Self> {
        Ok(Self {
            dbs,
            routing,
            wrapping,
        })
    }

    pub(super) async fn write(
        &mut self,
        write: BlobWrite,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        use BlobWrite::*;
        match write {
            New(data) => self.store(data, msg_id, origin, proxies).await,
            DeletePrivate(address) => self.delete(address, msg_id, origin, proxies).await,
        }
    }

    async fn store(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        let target_holders = if let Ok(metadata) = self.get_metadata_for(*data.address()) {
            if metadata.holders.len() == CHUNK_COPY_COUNT {
                if data.is_pub() {
                    trace!("{}: All good, {:?}, chunk already exists.", self, data);
                    return Ok(NodeMessagingDuty::NoOp);
                } else {
                    return self
                        .wrapping
                        .send_to_section(
                            Message::CmdError {
                                error: CmdError::Data(ErrorMessage::DataExists),
                                id: MessageId::new(),
                                cmd_origin: origin.address(),
                                correlation_id: msg_id,
                            },
                            true,
                        )
                        .await;
                }
            } else {
                let mut existing_holders = metadata.holders;
                let closest_holders = self
                    .get_holders_for_chunk(data.name())
                    .await
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();

                for holder_xorname in closest_holders {
                    if !existing_holders.contains(&holder_xorname)
                        && existing_holders.len() < CHUNK_COPY_COUNT
                    {
                        let _ = existing_holders.insert(holder_xorname);
                    }
                }
                existing_holders
            }
        } else {
            self.get_holders_for_chunk(data.name())
                .await
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        };

        info!("Storing {} copies of the data", target_holders.len());

        let results: Vec<_> = (&target_holders)
            .iter()
            .map(|holder| self.set_chunk_holder(*data.address(), *holder, origin.id().public_key()))
            .filter(|res| res.is_err())
            .collect();
        if !results.is_empty() {
            info!("Results is not empty!");
        }
        let message = Message::NodeCmd {
            cmd: NodeCmd::Data(NodeDataCmd::Blob(BlobWrite::New(data))),
            id: msg_id,
        };
        //     ,
        //     origin,
        //     proxies,
        // };
        self.wrapping
            .send_to_adults(target_holders, message, true, origin, proxies)
            .await
    }

    async fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        let cmd_error = |error: Error| {
            let message_error = convert_to_error_message(error);
            self.wrapping.send_to_section(
                Message::CmdError {
                    error: CmdError::Data(message_error),
                    id: MessageId::new(),
                    cmd_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return cmd_error(error).await,
        };

        // todo: use signature verification instead
        if let Some(data_owner) = metadata.owner {
            let pk = origin.id().public_key();
            if data_owner != pk {
                return cmd_error(Error::NetworkData(DtError::AccessDenied(pk))).await;
            }
        };

        let results: Vec<_> = (&metadata.holders)
            .iter()
            .map(|holder_name| self.remove_chunk_holder(address, *holder_name))
            .collect();
        if !results.is_empty() {}

        let message = Message::NodeCmd {
            cmd: NodeCmd::Data(NodeDataCmd::Blob(BlobWrite::DeletePrivate(address))),
            id: msg_id,
        };
        self.wrapping
            .send_to_adults(metadata.holders, message, true, origin, proxies)
            .await
    }

    fn set_chunk_holder(
        &mut self,
        blob_address: BlobAddress,
        holder: XorName,
        origin: PublicKey,
    ) -> Result<()> {
        // TODO -
        // - if Err, we need to flag this sender as "full" (i.e. add to self.full_adults, try on
        //   next closest non-full adult, or elder if none.  Also update the metadata for this
        //   chunk.  Not known yet where we'll get the chunk from to do that.
        info!("Setting chunk holder");

        let db_key = blob_address.to_db_key()?;
        let mut metadata = self.get_metadata_for(blob_address).unwrap_or_default();
        if blob_address.is_unpub() {
            metadata.owner = Some(origin);
        }

        let _ = metadata.holders.insert(holder);

        if let Err(error) = self.dbs.metadata.borrow_mut().set(&db_key, &metadata) {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
            return Err(error.into());
        }

        // We're acting as data handler, received request from client handlers
        let mut holders_metadata = self.get_holder(holder).unwrap_or_default();
        let _ = holders_metadata.chunks.insert(blob_address);

        if let Err(error) = self
            .dbs
            .holders
            .borrow_mut()
            .set(&holder.to_db_key()?, &holders_metadata)
        {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
            return Err(error.into());
        }
        Ok(())
    }

    fn remove_chunk_holder(
        &mut self,
        blob_address: BlobAddress,
        holder_name: XorName,
    ) -> Result<()> {
        let db_key = blob_address.to_db_key()?;
        let metadata = self.get_metadata_for(blob_address);
        if let Ok(mut metadata) = metadata {
            let holder = self.get_holder(holder_name);

            // Remove the chunk from the holder metadata
            if let Ok(mut holder) = holder {
                let _ = holder.chunks.remove(&blob_address);
                if holder.chunks.is_empty() {
                    if let Err(error) = self.dbs.holders.borrow_mut().rem(&holder_name.to_db_key()?)
                    {
                        warn!(
                            "{}: Failed to delete holder metadata from DB: {:?}",
                            self, error
                        );
                    }
                } else if let Err(error) = self
                    .dbs
                    .holders
                    .borrow_mut()
                    .set(&holder_name.to_db_key()?, &holder)
                {
                    warn!(
                        "{}: Failed to write holder metadata to DB: {:?}",
                        self, error
                    );
                }
            }

            // Remove the holder from the chunk metadata
            let _ = metadata.holders.remove(&holder_name);
            if metadata.holders.is_empty() {
                if let Err(error) = self.dbs.metadata.borrow_mut().rem(&db_key) {
                    warn!(
                        "{}: Failed to delete chunk metadata from DB: {:?}",
                        self, error
                    );
                }
            } else if let Err(error) = self.dbs.metadata.borrow_mut().set(&db_key, &metadata) {
                warn!(
                    "{}: Failed to write chunk metadata to DB: {:?}",
                    self, error
                );
            }
        }
        Ok(())
    }

    pub(super) async fn replicate_chunks(&mut self, holder: XorName) -> Result<NodeOperation> {
        trace!("Replicating chunks of holder {:?}", holder);

        let chunks_stored = match self.remove_holder(holder) {
            Ok(chunks) => chunks,
            _ => return Ok(NodeOperation::NoOp),
        };
        let mut cmds = Vec::new();
        for (address, holders) in chunks_stored {
            cmds.extend(self.get_replication_msgs(address, holders).await);
        }
        Ok(cmds.into())
    }

    async fn get_replication_msgs(
        &self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
    ) -> Vec<NodeOperation> {
        use NodeCmd::*;
        use NodeDataCmd::*;
        let mut node_ops = Vec::new();
        let messages = self
            .get_new_holders_for_chunk(&address)
            .await
            .into_iter()
            .map(|new_holder| {
                let message_id = MessageId::combine(vec![*address.name(), new_holder]);
                info!("Sending replicate-chunk cmd to NewHolder {:?}", new_holder);
                Message::NodeCmd {
                    cmd: Data(ReplicateChunk {
                        new_holder,
                        address,
                        current_holders: current_holders.clone(),
                    }),
                    id: message_id,
                }
            })
            .collect::<Vec<_>>();
        for message in messages {
            match self.wrapping.send_to_node(message.clone()).await {
                Ok(op) => node_ops.push(op.into()),
                Err(e) => warn!("Error: {}. Failed to send msg to node: {:?}", e, message),
            }
        }
        node_ops
    }

    pub(super) async fn read(
        &self,
        read: &BlobRead,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        use BlobRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, origin, proxies).await,
        }
    }

    async fn get(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        let query_error = |error: Error| async {
            let message_error = convert_to_error_message(error);
            let err_msg = Message::QueryResponse {
                response: QueryResponse::GetBlob(Err(message_error)),
                id: MessageId::in_response_to(&msg_id),
                query_origin: origin.address(),
                correlation_id: msg_id,
            };
            // short circuit sending the response directly to client if there are no intermediaries
            if proxies.is_empty() && origin.is_client() {
                self.wrapping.send_to_client(err_msg).await
            } else {
                self.wrapping.send_to_section(err_msg, false).await
            }
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return query_error(error).await,
        };

        if let Some(data_owner) = metadata.owner {
            if data_owner != origin.id().public_key() {
                return query_error(Error::NetworkData(DtError::AccessDenied(
                    origin.id().public_key(),
                )))
                .await;
            }
        };
        let message = Message::Query {
            query: Query::Data(DataQuery::Blob(BlobRead::Get(address))),
            id: msg_id,
        };
        self.wrapping
            .send_to_adults(metadata.holders, message, true, origin, proxies)
            .await
    }

    #[allow(unused)]
    pub(super) fn update_holders(
        &mut self,
        address: BlobAddress,
        holder: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Result<NodeMessagingDuty> {
        let mut chunk_metadata = self.get_metadata_for(address).unwrap_or_default();
        let _ = chunk_metadata.holders.insert(holder);
        if let Err(error) = self
            .dbs
            .metadata
            .borrow_mut()
            .set(&address.to_db_key()?, &chunk_metadata)
        {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
        }
        let mut holders_metadata = self.get_holder(holder).unwrap_or_default();
        let _ = holders_metadata.chunks.insert(address);
        if let Err(error) = self
            .dbs
            .holders
            .borrow_mut()
            .set(&holder.to_db_key()?, &holders_metadata)
        {
            warn!(
                "{}: Failed to write holder metadata to DB: {:?}",
                self, error
            );
        }
        info!("Replication process completed for: {:?}", message_id);
        Ok(NodeMessagingDuty::NoOp)
    }

    // Updates the metadata of the chunks help by a node that left.
    // Returns the list of chunks that were held along with the remaining holders.
    fn remove_holder(&mut self, node: XorName) -> Result<BTreeMap<BlobAddress, BTreeSet<XorName>>> {
        let mut blob_addresses: BTreeMap<BlobAddress, BTreeSet<XorName>> = BTreeMap::new();
        let chunk_holder = self.get_holder(node);

        if let Ok(holder) = chunk_holder {
            for chunk_address in holder.chunks {
                let db_key = chunk_address.to_db_key()?;
                // .map_err(|e| DtError::NetworkOther(e.to_string()))?;
                let chunk_metadata = self.get_metadata_for(chunk_address);

                if let Ok(mut metadata) = chunk_metadata {
                    if !metadata.holders.remove(&node) {
                        warn!("doesn't contain the holder",);
                    }

                    let _ = blob_addresses.insert(chunk_address, metadata.holders.clone());

                    if metadata.holders.is_empty() {
                        if let Err(error) = self.dbs.metadata.borrow_mut().rem(&db_key) {
                            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                        }
                    } else if let Err(error) =
                        self.dbs.metadata.borrow_mut().set(&db_key, &metadata)
                    {
                        warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                    }
                }
            }
        }

        // Since the node has left the section, remove it from the holders DB
        if let Err(error) = self.dbs.holders.borrow_mut().rem(
            &node.to_db_key()?, // .map_err(|e| DtError::NetworkOther(e.to_string()))?,
        ) {
            warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
        };

        Ok(blob_addresses)
    }

    fn get_holder(&self, holder: XorName) -> Result<HolderMetadata> {
        match self.dbs.holders.borrow().get::<HolderMetadata>(
            &holder.to_db_key()?, // .map_err(|e| DtError::NetworkOther(e.to_string()))?,
        ) {
            Some(metadata) => {
                if metadata.chunks.is_empty() {
                    warn!("{}: is not responsible for any chunk", holder);
                    Err(Error::NoSuchChunk)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                info!("{}: is not responsible for any chunk", holder);
                Err(Error::NoSuchChunk)
            }
        }
    }

    fn get_metadata_for(&self, address: BlobAddress) -> Result<ChunkMetadata> {
        match self.dbs.metadata.borrow().get::<ChunkMetadata>(
            &address.to_db_key()?, // .map_err(|e| DtError::NetworkOther(e.to_string()))?,
        ) {
            Some(metadata) => {
                if metadata.holders.is_empty() {
                    warn!("{}: Metadata holders is empty for: {:?}", self, address);
                    Err(Error::NoSuchChunk)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                warn!("{}: Failed to get metadata from DB: {:?}", self, address);
                Err(Error::NoSuchChunk)
            }
        }
    }

    // Returns `XorName`s of the target holders for an Blob chunk.
    // Used to fetch the list of holders for a new chunk.
    async fn get_holders_for_chunk(&self, target: &XorName) -> Vec<XorName> {
        //let closest_adults =
        self.routing
            .our_adults_sorted_by_distance_to(&target, CHUNK_COPY_COUNT)
            .await

        // TODO: Investigate elder blob storage
        // if closest_adults.len() < CHUNK_COPY_COUNT {
        //     let take = CHUNK_COPY_COUNT - closest_adults.len();
        //     let mut closest_elders = self
        //         .routing
        //         .our_elder_names_sorted_by_distance_to(&target, take)
        //         .await;
        //     closest_adults.append(&mut closest_elders);
        //     closest_adults
        // } else {
        //     closest_adults
        // }

        //closest_adults
    }

    // Returns `XorName`s of the new target holders for an Blob chunk.
    // Used to fetch the additional list of holders for existing chunks.
    async fn get_new_holders_for_chunk(&self, target: &BlobAddress) -> BTreeSet<XorName> {
        let closest_holders = self
            .get_holders_for_chunk(target.name())
            .await
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Ok(metadata) = self.get_metadata_for(*target) {
            return closest_holders
                .difference(&metadata.holders)
                .cloned()
                .collect();
        }
        closest_holders
    }
}

impl Display for BlobRegister {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "BlobRegister")
    }
}
