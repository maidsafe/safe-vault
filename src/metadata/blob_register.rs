// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::ChunkHolderDbs,
    error::convert_to_error_message,
    network::Network,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    to_db_key::ToDbKey,
    Error, Result,
};
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};
use sn_data_types::{Blob, BlobAddress, Error as DtError, PublicKey, Result as NdResult};
use sn_messaging::{
    client::{
        BlobRead, BlobWrite, CmdError, Error as ErrorMessage, Message, NodeCmd, NodeQuery,
        NodeSystemCmd, NodeSystemQuery, QueryResponse,
    },
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

use super::adult_reader::AdultReader;

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
    reader: AdultReader,
}

impl BlobRegister {
    pub(super) fn new(dbs: ChunkHolderDbs, reader: AdultReader) -> Self {
        Self { dbs, reader }
    }

    pub(super) async fn write(
        &mut self,
        write: BlobWrite,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use BlobWrite::*;
        match write {
            New(data) => self.store(data, msg_id, origin).await,
            DeletePrivate(address) => self.delete(address, msg_id, origin).await,
        }
    }

    async fn store(&mut self, data: Blob, msg_id: MessageId, origin: EndUser) -> Result<NodeDuty> {
        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        let target_holders = if let Ok(metadata) = self.get_metadata_for(*data.address()).await {
            if metadata.holders.len() < CHUNK_COPY_COUNT {
                self.get_new_holders_for_chunk(data.address()).await
            } else if data.is_public() {
                trace!("{}: All good, {:?}, chunk already exists.", self, data);
                return Ok(NodeDuty::NoOp);
            } else {
                return Ok(NodeDuty::Send(OutgoingMsg {
                    msg: Message::CmdError {
                        error: CmdError::Data(ErrorMessage::DataExists),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                        target_section_pk: None,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: DstLocation::EndUser(origin),
                    aggregation: Aggregation::AtDestination,
                }));
            }
        } else {
            self.get_holders_for_chunk(data.name())
                .await
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        };

        info!("Storing {} copies of the data", target_holders.len());

        let mut owner = None;
        if data.address().is_private() {
            owner = Some(*origin.id());
        }
        for holder in &target_holders {
            // TODO: This error needs to be handled in some way.
            if let Err(e) = self.set_chunk_holder(*data.address(), *holder, owner).await {
                warn!(
                    "Error ({:?}) setting chunk holder ({:?}) of {:?}, sent by origin: {:?}",
                    e,
                    *holder,
                    *data.address(),
                    origin
                )
            }
        }

        Ok(NodeDuty::SendToNodes {
            targets: target_holders,
            msg: Message::NodeCmd {
                cmd: NodeCmd::Chunks {
                    cmd: BlobWrite::New(data),
                    origin,
                },
                id: msg_id,
                target_section_pk: None,
            },
            aggregation: Aggregation::AtDestination,
        })
    }

    async fn send_blob_cmd_error(
        &self,
        error: Error,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let message_error = convert_to_error_message(error)?;
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::CmdError {
                error: CmdError::Data(message_error),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an error..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::AtDestination,
        }))
    }

    async fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let metadata = match self.get_metadata_for(address).await {
            Ok(metadata) => metadata,
            Err(error) => return self.send_blob_cmd_error(error, msg_id, origin).await,
        };

        // todo: use signature verification instead
        if let Some(data_owner) = metadata.owner {
            if &data_owner != origin.id() {
                return self
                    .send_blob_cmd_error(
                        Error::NetworkData(DtError::AccessDenied(*origin.id())),
                        msg_id,
                        origin,
                    )
                    .await;
            }
        };

        let mut results = vec![];
        for holder_name in &metadata.holders {
            results.push(self.remove_chunk_holder(address, *holder_name).await)
        }

        if !results.is_empty() {}

        let msg = Message::NodeCmd {
            cmd: NodeCmd::Chunks {
                cmd: BlobWrite::DeletePrivate(address),
                origin,
            },
            id: msg_id,
            target_section_pk: None,
        };
        Ok(NodeDuty::SendToNodes {
            msg,
            targets: metadata.holders,
            aggregation: Aggregation::AtDestination,
        })
    }

    async fn set_chunk_holder(
        &mut self,
        blob_address: BlobAddress,
        holder: XorName,
        owner: Option<PublicKey>,
    ) -> Result<()> {
        // TODO -
        // - if Err, we need to flag this sender as "full" (i.e. add to self.full_adults, try on
        //   next closest non-full adult, or elder if none.  Also update the metadata for this
        //   chunk.  Not known yet where we'll get the chunk from to do that.
        info!("Setting chunk holder");

        let db_key = blob_address.to_db_key()?;
        let mut metadata = self
            .get_metadata_for(blob_address)
            .await
            .unwrap_or_default();

        metadata.owner = owner;
        let _ = metadata.holders.insert(holder);

        if let Err(error) = self.dbs.metadata.lock().await.set(&db_key, &metadata) {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
            return Err(error.into());
        }

        // We're acting as data handler, received request from client handlers
        let mut holders_metadata = self.get_holder(holder).await.unwrap_or_default();
        let _ = holders_metadata.chunks.insert(blob_address);

        if let Err(error) = self
            .dbs
            .holders
            .lock()
            .await
            .set(&holder.to_db_key()?, &holders_metadata)
        {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
            return Err(error.into());
        }
        Ok(())
    }

    async fn remove_chunk_holder(
        &mut self,
        blob_address: BlobAddress,
        holder_name: XorName,
    ) -> Result<()> {
        let db_key = blob_address.to_db_key()?;
        let metadata = self.get_metadata_for(blob_address).await;
        if let Ok(mut metadata) = metadata {
            let holder = self.get_holder(holder_name).await;

            // Remove the chunk from the holder metadata
            if let Ok(mut holder) = holder {
                let _ = holder.chunks.remove(&blob_address);
                if holder.chunks.is_empty() {
                    if let Err(error) = self.dbs.holders.lock().await.rem(&holder_name.to_db_key()?)
                    {
                        warn!(
                            "{}: Failed to delete holder metadata from DB: {:?}",
                            self, error
                        );
                    }
                } else if let Err(error) = self
                    .dbs
                    .holders
                    .lock()
                    .await
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
                if let Err(error) = self.dbs.metadata.lock().await.rem(&db_key) {
                    warn!(
                        "{}: Failed to delete chunk metadata from DB: {:?}",
                        self, error
                    );
                }
            } else if let Err(error) = self.dbs.metadata.lock().await.set(&db_key, &metadata) {
                warn!(
                    "{}: Failed to write chunk metadata to DB: {:?}",
                    self, error
                );
            }
        }
        Ok(())
    }

    pub(super) async fn begin_replicate_chunks(&mut self, holder: XorName) -> Result<NodeDuties> {
        info!("Replicating chunks");
        let chunks_stored = match self.remove_holder(holder).await {
            Ok(chunks) => chunks,
            _ => return Ok(vec![]),
        };
        let mut cmds = Vec::new();
        for (address, holders) in chunks_stored {
            cmds.extend(self.get_chunk_queries(address, holders).await?);
        }
        Ok(cmds)
    }

    pub(super) async fn replicate_chunk(&mut self, data: Blob) -> Result<NodeDuty> {
        info!("Replicating chunk");
        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        let (owner, target_holders) =
            if let Ok(metadata) = self.get_metadata_for(*data.address()).await {
                if metadata.holders.len() < CHUNK_COPY_COUNT {
                    (
                        metadata.owner,
                        self.get_new_holders_for_chunk(data.address()).await,
                    )
                } else {
                    trace!(
                        "{}: All good, {:?}, chunk copy count already satisfied.",
                        self,
                        data
                    );
                    return Ok(NodeDuty::NoOp);
                }
            } else {
                trace!(
                    "{}: Did not find any metadata for the chunk, {:?}. No replication performed.",
                    self,
                    data
                );
                return Ok(NodeDuty::NoOp);
            };

        info!("Storing {} copies of the data", target_holders.len());

        for holder in &target_holders {
            // TODO: This error needs to be handled in some way.
            if let Err(e) = self.set_chunk_holder(*data.address(), *holder, owner).await {
                warn!(
                    "Error ({:?}) when replicating chunk and setting chunk holder ({:?}) of {:?}, owned by: {:?}",
                    e,
                    *holder,
                    *data.address(),
                    owner
                )
            }
        }

        // deterministic msg id for aggregation
        let msg_id = MessageId::from_content(&(*data.name(), owner))?;

        Ok(NodeDuty::SendToNodes {
            targets: target_holders,
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk(data)),
                id: msg_id,
                target_section_pk: None,
            },
            aggregation: Aggregation::AtDestination,
        })
    }

    async fn get_chunk_replication_cmd(
        &mut self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
    ) -> Result<NodeDuties> {
        use NodeCmd::*;
        let mut node_ops = Vec::new();
        let messages = current_holders
            .into_iter()
            .map(|holder| {
                info!("Sending get-chunk query to holder {:?}", holder);
                (
                    Message::NodeQuery {
                        query: NodeQuery::System(NodeSystemQuery::GetChunk(address)),
                        id: MessageId::combine(vec![*address.name(), holder]),
                        target_section_pk: None,
                    },
                    holder,
                )
            })
            .collect::<Vec<_>>();
        for (msg, dst) in messages {
            node_ops.push(NodeDuty::Send(OutgoingMsg {
                msg,
                section_source: true, // i.e. errors go to our section
                dst: DstLocation::Node(dst),
                aggregation: Aggregation::AtDestination,
            }));
        }
        Ok(node_ops)
    }

    async fn get_chunk_queries(
        &mut self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
    ) -> Result<NodeDuties> {
        use NodeCmd::*;
        let mut node_ops = Vec::new();
        let messages = current_holders
            .into_iter()
            .map(|holder| {
                info!("Sending get-chunk query to holder {:?}", holder);
                (
                    Message::NodeQuery {
                        query: NodeQuery::System(NodeSystemQuery::GetChunk(address)),
                        id: MessageId::combine(vec![*address.name(), holder]),
                        target_section_pk: None,
                    },
                    holder,
                )
            })
            .collect::<Vec<_>>();
        for (msg, dst) in messages {
            node_ops.push(NodeDuty::Send(OutgoingMsg {
                msg,
                section_source: true, // i.e. errors go to our section
                dst: DstLocation::Node(dst),
                aggregation: Aggregation::AtDestination,
            }));
        }
        Ok(node_ops)
    }

    pub(super) async fn read(
        &self,
        read: &BlobRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use BlobRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, origin).await,
        }
    }

    async fn get(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let query_error = |error: Error| async {
            let message_error = convert_to_error_message(error)?;
            let err_msg = Message::QueryResponse {
                response: QueryResponse::GetBlob(Err(message_error)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                target_section_pk: None,
            };
            Ok(NodeDuty::Send(OutgoingMsg {
                msg: err_msg,
                section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                dst: DstLocation::EndUser(origin),
                aggregation: Aggregation::AtDestination,
            }))
        };

        let metadata = match self.get_metadata_for(address).await {
            Ok(metadata) => metadata,
            Err(error) => return query_error(error).await,
        };

        if let Some(data_owner) = metadata.owner {
            if &data_owner != origin.id() {
                return query_error(Error::NetworkData(DtError::AccessDenied(*origin.id()))).await;
            }
        };
        let msg = Message::NodeQuery {
            query: NodeQuery::Chunks {
                query: BlobRead::Get(address),
                origin,
            },
            id: msg_id,
            target_section_pk: None,
        };
        Ok(NodeDuty::SendToNodes {
            msg,
            targets: metadata.holders,
            aggregation: Aggregation::AtDestination,
        })
    }

    async fn update_holders(&mut self, address: BlobAddress, holder: XorName) -> Result<()> {
        let mut chunk_metadata = self.get_metadata_for(address).await.unwrap_or_default();
        let _ = chunk_metadata.holders.insert(holder);
        if let Err(error) = self
            .dbs
            .metadata
            .lock()
            .await
            .set(&address.to_db_key()?, &chunk_metadata)
        {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
        }
        let mut holders_metadata = self.get_holder(holder).await.unwrap_or_default();
        let _ = holders_metadata.chunks.insert(address);
        if let Err(error) = self
            .dbs
            .holders
            .lock()
            .await
            .set(&holder.to_db_key()?, &holders_metadata)
        {
            warn!(
                "{}: Failed to write holder metadata to DB: {:?}",
                self, error
            );
        }
        info!(
            "Requested replication of chunk {:?} to new holder {:?}",
            address, holder
        );
        Ok(())
    }

    // Updates the metadata of the chunks help by a node that left.
    // Returns the list of chunks that were held along with the remaining holders.
    async fn remove_holder(
        &mut self,
        node: XorName,
    ) -> Result<BTreeMap<BlobAddress, BTreeSet<XorName>>> {
        let mut blob_addresses: BTreeMap<BlobAddress, BTreeSet<XorName>> = BTreeMap::new();
        let chunk_holder = self.get_holder(node).await;

        if let Ok(holder) = chunk_holder {
            for chunk_address in holder.chunks {
                let db_key = chunk_address.to_db_key()?;
                let chunk_metadata = self.get_metadata_for(chunk_address).await;

                if let Ok(mut metadata) = chunk_metadata {
                    if !metadata.holders.remove(&node) {
                        warn!("doesn't contain the holder",);
                    }

                    let _ = blob_addresses.insert(chunk_address, metadata.holders.clone());

                    if metadata.holders.is_empty() {
                        if let Err(error) = self.dbs.metadata.lock().await.rem(&db_key) {
                            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                        }
                    } else if let Err(error) =
                        self.dbs.metadata.lock().await.set(&db_key, &metadata)
                    {
                        warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                    }
                }
            }
        }

        // Since the node has left the section, remove it from the holders DB
        if let Err(error) = self.dbs.holders.lock().await.rem(&node.to_db_key()?) {
            warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
        };

        Ok(blob_addresses)
    }

    async fn get_holder(&self, holder: XorName) -> Result<HolderMetadata> {
        match self
            .dbs
            .holders
            .lock()
            .await
            .get::<HolderMetadata>(&holder.to_db_key()?)
        {
            Some(metadata) => {
                if metadata.chunks.is_empty() {
                    warn!("{}: is not responsible for any chunk", holder);
                    Err(Error::NodeDoesNotHoldChunks)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                warn!("{}: is not responsible for any chunk", holder);
                Err(Error::NodeDoesNotHoldChunks)
            }
        }
    }

    async fn get_metadata_for(&self, address: BlobAddress) -> Result<ChunkMetadata> {
        match self
            .dbs
            .metadata
            .lock()
            .await
            .get::<ChunkMetadata>(&address.to_db_key()?)
        {
            Some(metadata) => {
                if metadata.holders.is_empty() {
                    warn!("{}: Metadata holders is empty for: {:?}", self, address);
                    Err(Error::NoHoldersOfChunk)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                warn!(
                    "{}: Did not find metadata in DB for chunk: {:?}",
                    self, address
                );
                Err(Error::NoSuchChunk)
            }
        }
    }

    // Returns `XorName`s of the target holders for an Blob chunk.
    // Used to fetch the list of holders for a new chunk.
    async fn get_holders_for_chunk(&self, target: &XorName) -> Vec<XorName> {
        self.reader
            .our_adults_sorted_by_distance_to(&target, CHUNK_COPY_COUNT)
            .await
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
        if let Ok(metadata) = self.get_metadata_for(*target).await {
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
