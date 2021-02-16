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
    node::node_ops::{NetworkDuties, NodeMessagingDuty, OutgoingMsg},
    ElderState, Error, Result, ToDbKey,
};
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};
use sn_data_types::{Blob, BlobAddress, Error as DtError, PublicKey, Result as NdResult};
use sn_messaging::{
    client::{
        BlobRead, BlobWrite, CmdError, DataQuery, Error as ErrorMessage, Message, NodeCmd,
        NodeSystemCmd, Query, QueryResponse,
    },
    DstLocation, EndUser, MessageId, SrcLocation,
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
    elder_state: ElderState,
}

impl BlobRegister {
    pub(super) fn new(dbs: ChunkHolderDbs, elder_state: ElderState) -> Self {
        Self { dbs, elder_state }
    }

    pub(super) async fn write(
        &mut self,
        write: BlobWrite,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeMessagingDuty> {
        use BlobWrite::*;
        match write {
            New(data) => self.store(data, msg_id, origin).await,
            DeletePrivate(address) => self.delete(address, msg_id, origin).await,
        }
    }

    async fn store(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeMessagingDuty> {
        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        let target_holders = if let Ok(metadata) = self.get_metadata_for(*data.address()) {
            if metadata.holders.len() == CHUNK_COPY_COUNT {
                if data.is_public() {
                    trace!("{}: All good, {:?}, chunk already exists.", self, data);
                    return Ok(NodeMessagingDuty::NoOp);
                } else {
                    return Ok(NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::CmdError {
                            error: CmdError::Data(ErrorMessage::DataExists),
                            id: MessageId::new(),
                            cmd_origin: SrcLocation::EndUser(origin),
                            correlation_id: msg_id,
                        },
                        dst: DstLocation::EndUser(origin),
                        to_be_aggregated: false,
                    }));
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
            .map(|holder| self.set_chunk_holder(*data.address(), *holder, origin))
            .filter(|res| res.is_err())
            .collect();
        if !results.is_empty() {
            info!("Results is not empty!");
        }
        let msg = Message::NodeCmd {
            cmd: NodeCmd::Chunks {
                cmd: BlobWrite::New(data),
                origin,
            },
            id: msg_id,
        };
        Ok(NodeMessagingDuty::SendToAdults {
            targets: target_holders,
            msg,
        })
    }

    async fn send_blob_cmd_error(
        &self,
        error: Error,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeMessagingDuty> {
        let message_error = convert_to_error_message(error)?;
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::CmdError {
                error: CmdError::Data(message_error),
                id: MessageId::new(),
                cmd_origin: SrcLocation::EndUser(origin),
                correlation_id: msg_id,
            },
            dst: DstLocation::EndUser(origin),
            to_be_aggregated: false,
        }))
    }

    async fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeMessagingDuty> {
        let metadata = match self.get_metadata_for(address) {
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

        let results: Vec<_> = (&metadata.holders)
            .iter()
            .map(|holder_name| self.remove_chunk_holder(address, *holder_name))
            .collect();
        if !results.is_empty() {}

        let msg = Message::NodeCmd {
            cmd: NodeCmd::Chunks {
                cmd: BlobWrite::DeletePrivate(address),
                origin,
            },
            id: msg_id,
        };
        Ok(NodeMessagingDuty::SendToAdults {
            targets: metadata.holders,
            msg,
        })
    }

    fn set_chunk_holder(
        &mut self,
        blob_address: BlobAddress,
        holder: XorName,
        origin: EndUser,
    ) -> Result<()> {
        // TODO -
        // - if Err, we need to flag this sender as "full" (i.e. add to self.full_adults, try on
        //   next closest non-full adult, or elder if none.  Also update the metadata for this
        //   chunk.  Not known yet where we'll get the chunk from to do that.
        info!("Setting chunk holder");

        let db_key = blob_address.to_db_key()?;
        let mut metadata = self.get_metadata_for(blob_address).unwrap_or_default();
        if blob_address.is_private() {
            metadata.owner = Some(*origin.id());
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

    pub(super) async fn replicate_chunks(&mut self, holder: XorName) -> Result<NetworkDuties> {
        trace!("Replicating chunks of holder {:?}", holder);

        let chunks_stored = match self.remove_holder(holder) {
            Ok(chunks) => chunks,
            _ => return Ok(vec![]),
        };
        let mut cmds = Vec::new();
        for (address, holders) in chunks_stored {
            cmds.extend(self.get_replication_msgs(address, holders).await);
        }
        Ok(cmds)
    }

    async fn get_replication_msgs(
        &self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
    ) -> NetworkDuties {
        use NodeCmd::*;
        let mut node_ops = Vec::new();
        let messages = self
            .get_new_holders_for_chunk(&address)
            .await
            .into_iter()
            .map(|new_holder| {
                let message_id = MessageId::combine(vec![*address.name(), new_holder]);
                info!("Sending replicate-chunk cmd to NewHolder {:?}", new_holder);
                (
                    Message::NodeCmd {
                        cmd: System(NodeSystemCmd::ReplicateChunk {
                            new_holder,
                            address,
                            current_holders: current_holders.clone(),
                        }),
                        id: message_id,
                    },
                    new_holder,
                )
            })
            .collect::<Vec<_>>();
        for (msg, dst) in messages {
            node_ops.push(
                NodeMessagingDuty::Send(OutgoingMsg {
                    msg,
                    dst: DstLocation::Node(dst),
                    to_be_aggregated: false,
                })
                .into(),
            );
        }
        node_ops
    }

    pub(super) async fn read(
        &self,
        read: &BlobRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeMessagingDuty> {
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
    ) -> Result<NodeMessagingDuty> {
        let query_error = |error: Error| async {
            let message_error = convert_to_error_message(error)?;
            let err_msg = Message::QueryResponse {
                response: QueryResponse::GetBlob(Err(message_error)),
                id: MessageId::in_response_to(&msg_id),
                query_origin: SrcLocation::EndUser(origin),
                correlation_id: msg_id,
            };
            Ok(NodeMessagingDuty::Send(OutgoingMsg {
                msg: err_msg,
                dst: DstLocation::EndUser(origin),
                to_be_aggregated: false, // TODO: to_be_aggregated: true,
            }))
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return query_error(error).await,
        };

        if let Some(data_owner) = metadata.owner {
            if &data_owner != origin.id() {
                return query_error(Error::NetworkData(DtError::AccessDenied(*origin.id()))).await;
            }
        };
        let msg = Message::Query {
            query: Query::Data(DataQuery::Blob(BlobRead::Get(address))),
            id: msg_id,
        };
        Ok(NodeMessagingDuty::SendToAdults {
            targets: metadata.holders,
            msg,
        })
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
        if let Err(error) = self.dbs.holders.borrow_mut().rem(&node.to_db_key()?) {
            warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
        };

        Ok(blob_addresses)
    }

    fn get_holder(&self, holder: XorName) -> Result<HolderMetadata> {
        match self
            .dbs
            .holders
            .borrow()
            .get::<HolderMetadata>(&holder.to_db_key()?)
        {
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
        match self
            .dbs
            .metadata
            .borrow()
            .get::<ChunkMetadata>(&address.to_db_key()?)
        {
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
        self.elder_state
            .adults_sorted_by_distance_to(&target, CHUNK_COPY_COUNT)
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
