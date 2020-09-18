// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::ChunkHolderDbs,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{NodeMessagingDuty, NodeOperation},
    Network, Result, ToDbKey,
};
use log::{info, trace, warn};
use serde::{Deserialize, Serialize};
use sn_data_types::{
    Blob, BlobAddress, BlobRead, BlobWrite, Cmd, CmdError, DataQuery, DebitAgreementProof,
    Error as NdError, Message, MessageId, MsgEnvelope, MsgSender, NodeCmd, NodeDataCmd, PublicKey,
    Query, QueryResponse, Result as NdResult,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
};
use tiny_keccak::sha3_256;
use xor_name::XorName;

// The number of separate copies of a blob chunk which should be maintained.
const CHUNK_COPY_COUNT: usize = 4;
const CHUNK_ADULT_COPY_COUNT: usize = 3;

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

    pub(super) fn write(
        &mut self,
        write: BlobWrite,
        msg_id: MessageId,
        origin: MsgSender,
        payment: DebitAgreementProof,
        proxies: Vec<MsgSender>,
    ) -> Option<NodeMessagingDuty> {
        use BlobWrite::*;
        match write {
            New(data) => self.store(data, msg_id, origin, payment, proxies),
            DeletePrivate(address) => self.delete(address, msg_id, origin, payment, proxies),
        }
    }

    fn store(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        origin: MsgSender,
        payment: DebitAgreementProof,
        proxies: Vec<MsgSender>,
    ) -> Option<NodeMessagingDuty> {
        let cmd_error = |error: NdError| {
            self.wrapping.send(Message::CmdError {
                error: CmdError::Data(error),
                id: MessageId::new(),
                cmd_origin: origin.address(),
                correlation_id: msg_id,
            })
        };

        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        let target_holders = if let Ok(metadata) = self.get_metadata_for(*data.address()) {
            if metadata.holders.len() == CHUNK_COPY_COUNT {
                if data.is_pub() {
                    trace!("{}: All good, {:?}, chunk already exists.", self, data);
                    return None;
                } else {
                    return cmd_error(NdError::DataExists);
                }
            } else {
                let mut existing_holders = metadata.holders;
                let closest_holders = self
                    .get_holders_for_chunk(data.name())
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
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        };

        info!("Storing {} copies of the data", target_holders.len());

        let results: Vec<_> = (&target_holders)
            .iter()
            .map(|holder| self.set_chunk_holder(*data.address(), *holder, origin.id()))
            .filter(|res| res.is_err())
            .collect();
        if !results.is_empty() {}
        let msg = MsgEnvelope {
            message: Message::Cmd {
                cmd: Cmd::Data {
                    cmd: sn_data_types::DataCmd::Blob(BlobWrite::New(data)),
                    payment,
                },
                id: msg_id,
            },
            origin,
            proxies,
        };
        self.wrapping.send_to_adults(target_holders, &msg)
    }

    fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: MsgSender,
        payment: DebitAgreementProof,
        proxies: Vec<MsgSender>,
    ) -> Option<NodeMessagingDuty> {
        let cmd_error = |error: NdError| {
            self.wrapping.send(Message::CmdError {
                error: CmdError::Data(error),
                id: MessageId::new(),
                cmd_origin: origin.address(),
                correlation_id: msg_id,
            })
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return cmd_error(error),
        };

        if let Some(data_owner) = metadata.owner {
            if data_owner != origin.id() {
                return cmd_error(NdError::AccessDenied);
            }
        };

        let results: Vec<_> = (&metadata.holders)
            .iter()
            .map(|holder_name| self.remove_chunk_holder(address, *holder_name))
            .collect();
        if !results.is_empty() {}

        let msg = MsgEnvelope {
            message: Message::Cmd {
                cmd: Cmd::Data {
                    cmd: sn_data_types::DataCmd::Blob(BlobWrite::DeletePrivate(address)),
                    payment,
                },
                id: msg_id,
            },
            origin,
            proxies,
        };
        self.wrapping.send_to_adults(metadata.holders, &msg)
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

        let db_key = blob_address.to_db_key();
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
            .set(&holder.to_db_key(), &holders_metadata)
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
        let db_key = blob_address.to_db_key();
        let metadata = self.get_metadata_for(blob_address);
        if let Ok(mut metadata) = metadata {
            let holder = self.get_holder(holder_name);

            // Remove the chunk from the holder metadata
            if let Ok(mut holder) = holder {
                let _ = holder.chunks.remove(&blob_address);
                if holder.chunks.is_empty() {
                    if let Err(error) = self.dbs.holders.borrow_mut().rem(&holder_name.to_db_key())
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
                    .set(&holder_name.to_db_key(), &holder)
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

    pub(super) fn duplicate_chunks(&mut self, holder: XorName) -> Option<NodeOperation> {
        trace!("Duplicating chunks of holder {:?}", holder);

        let chunks_stored = match self.remove_holder(holder) {
            Ok(chunks) => chunks,
            _ => return None,
        };
        let cmds: Vec<_> = chunks_stored
            .into_iter()
            .map(|(address, holders)| self.get_duplication_msgs(address, holders))
            .flatten()
            .collect();

        Some(cmds.into())
    }

    fn get_duplication_msgs(
        &self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
    ) -> Vec<NodeOperation> {
        use NodeCmd::*;
        use NodeDataCmd::*;

        self.get_new_holders_for_chunk(&address)
            .into_iter()
            .map(|new_holder| {
                let mut hash_bytes = Vec::new();
                hash_bytes.extend_from_slice(&address.name().0);
                hash_bytes.extend_from_slice(&new_holder.0);
                let message_id = MessageId(XorName(sha3_256(&hash_bytes)));
                Message::NodeCmd {
                    cmd: Data(DuplicateChunk {
                        new_holder,
                        address,
                        fetch_from_holders: current_holders.clone(),
                    }),
                    id: message_id,
                }
            })
            .filter_map(|message| self.wrapping.send(message).map(|c| c.into()))
            .collect()
    }

    pub(super) fn read(
        &self,
        read: &BlobRead,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Option<NodeMessagingDuty> {
        use BlobRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, origin, proxies),
        }
    }

    fn get(
        &self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Option<NodeMessagingDuty> {
        let query_error = |error: NdError| {
            self.wrapping.send(Message::QueryResponse {
                response: QueryResponse::GetBlob(Err(error)),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return query_error(error),
        };

        if let Some(data_owner) = metadata.owner {
            if data_owner != origin.id() {
                return query_error(NdError::AccessDenied);
            }
        };
        let msg = MsgEnvelope {
            message: Message::Query {
                query: Query::Data(DataQuery::Blob(BlobRead::Get(address))),
                id: msg_id,
            },
            origin,
            proxies,
        };
        self.wrapping.send_to_adults(metadata.holders, &msg)
    }

    #[allow(unused)]
    pub(super) fn update_holders(
        &mut self,
        address: BlobAddress,
        holder: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<NodeMessagingDuty> {
        let mut chunk_metadata = self.get_metadata_for(address).unwrap_or_default();
        let _ = chunk_metadata.holders.insert(holder);
        if let Err(error) = self
            .dbs
            .metadata
            .borrow_mut()
            .set(&address.to_db_key(), &chunk_metadata)
        {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
        }
        let mut holders_metadata = self.get_holder(holder).unwrap_or_default();
        let _ = holders_metadata.chunks.insert(address);
        if let Err(error) = self
            .dbs
            .holders
            .borrow_mut()
            .set(&holder.to_db_key(), &holders_metadata)
        {
            warn!(
                "{}: Failed to write holder metadata to DB: {:?}",
                self, error
            );
        }
        info!("Duplication process completed for: {:?}", message_id);
        None
    }

    // Updates the metadata of the chunks help by a node that left.
    // Returns the list of chunks that were held along with the remaining holders.
    fn remove_holder(
        &mut self,
        node: XorName,
    ) -> NdResult<BTreeMap<BlobAddress, BTreeSet<XorName>>> {
        let mut blob_addresses: BTreeMap<BlobAddress, BTreeSet<XorName>> = BTreeMap::new();
        let chunk_holder = self.get_holder(node);

        if let Ok(holder) = chunk_holder {
            for chunk_address in holder.chunks {
                let db_key = chunk_address.to_db_key();
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
        if let Err(error) = self.dbs.holders.borrow_mut().rem(&node.to_db_key()) {
            warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
        };

        Ok(blob_addresses)
    }

    fn get_holder(&self, holder: XorName) -> NdResult<HolderMetadata> {
        match self
            .dbs
            .holders
            .borrow()
            .get::<HolderMetadata>(&holder.to_db_key())
        {
            Some(metadata) => {
                if metadata.chunks.is_empty() {
                    warn!("{}: is not responsible for any chunk", holder);
                    Err(NdError::NoSuchData)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                info!("{}: is not responsible for any chunk", holder);
                Err(NdError::NoSuchData)
            }
        }
    }

    fn get_metadata_for(&self, address: BlobAddress) -> NdResult<ChunkMetadata> {
        match self
            .dbs
            .metadata
            .borrow()
            .get::<ChunkMetadata>(&address.to_db_key())
        {
            Some(metadata) => {
                if metadata.holders.is_empty() {
                    warn!("{}: Metadata holders is empty for: {:?}", self, address);
                    Err(NdError::NoSuchData)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                warn!("{}: Failed to get metadata from DB: {:?}", self, address);
                Err(NdError::NoSuchData)
            }
        }
    }

    // Returns `XorName`s of the target holders for an Blob chunk.
    // Used to fetch the list of holders for a new chunk.
    fn get_holders_for_chunk(&self, target: &XorName) -> Vec<XorName> {
        let take = CHUNK_ADULT_COPY_COUNT;
        let mut closest_adults = self.routing.our_adults_sorted_by_distance_to(&target, take);
        if closest_adults.len() < CHUNK_COPY_COUNT {
            let take = CHUNK_COPY_COUNT - closest_adults.len();
            let mut closest_elders = self
                .routing
                .our_elder_names_sorted_by_distance_to(&target, take);
            closest_adults.append(&mut closest_elders);
            closest_adults
        } else {
            closest_adults
        }
    }

    // Returns `XorName`s of the new target holders for an Blob chunk.
    // Used to fetch the additional list of holders for existing chunks.
    fn get_new_holders_for_chunk(&self, target: &BlobAddress) -> BTreeSet<XorName> {
        let closest_holders = self
            .get_holders_for_chunk(target.name())
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
