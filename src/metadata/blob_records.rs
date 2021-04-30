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
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    to_db_key::{from_db_key, ToDbKey},
    Error, Result,
};
use log::{debug, error, info, trace, warn};
use sn_data_types::{Blob, BlobAddress, DataAddress, Error as DtError, PublicKey};
use sn_messaging::{
    client::{
        BlobDataExchange, BlobRead, BlobWrite, ChunkMetadata, CmdError, Error as ErrorMessage,
        HolderMetadata, Message, NodeCmd, NodeQuery, NodeSystemCmd, NodeSystemQuery, QueryResponse,
    },
    Aggregation, DstLocation, EndUser, MessageId,
};

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

use super::adult_liveness::AdultLiveness;
use super::adult_reader::AdultReader;

// The number of separate copies of a blob chunk which should be maintained.
const CHUNK_COPY_COUNT: usize = 4;

/// Operations over the data type Blob.
pub(super) struct BlobRecords {
    dbs: ChunkHolderDbs,
    reader: AdultReader,
    adult_liveness: AdultLiveness,
}

impl BlobRecords {
    pub(super) fn new(dbs: ChunkHolderDbs, reader: AdultReader) -> Self {
        Self {
            dbs,
            reader,
            adult_liveness: AdultLiveness::new(),
        }
    }

    pub async fn get_all_data(&self) -> Result<BlobDataExchange> {
        debug!("Getting Blob records");
        // Prepare full_adult details
        let adult_details = &self.dbs.full_adults.lock().await;
        let all_full_adults_keys = adult_details.get_all();
        let mut full_adults = BTreeMap::new();
        for key in all_full_adults_keys {
            let val: String = adult_details
                .get(&key)
                .ok_or_else(|| Error::Logic("Error fetching full Adults".to_string()))?;
            let _ = full_adults.insert(key, val);
        }

        Ok(BlobDataExchange { full_adults })
    }

    pub async fn update(&self, blob_data: BlobDataExchange) -> Result<()> {
        debug!("Updating Blob records");
        let mut orig_full_adults = self.dbs.full_adults.lock().await;

        let BlobDataExchange { full_adults } = blob_data;

        for (key, value) in full_adults {
            orig_full_adults.set(&key, &value)?;
        }

        Ok(())
    }

    /// Registered holders not present in provided list of members
    /// will be removed from dbs and no longer tracked for liveness.
    pub async fn retain_members_only(&mut self, members: Vec<XorName>) -> Result<()> {
        let member_names_as_string = members
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>();

        // full adults
        let mut full_adults_db = self.dbs.full_adults.lock().await;
        let full_adults = full_adults_db.get_all();
        let absent_adults = full_adults
            .into_iter()
            .filter(|key| !member_names_as_string.contains(key))
            .collect::<Vec<_>>();

        for adult in absent_adults {
            let _ = full_adults_db.rem(&adult);
        }

        // // stop tracking liveness of absent holders
        // self.adult_liveness.stop_tracking(absent_holders);

        Ok(())
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

    /// Adds a given node to the list of full nodes.
    pub async fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<()> {
        info!("No. of Full Nodes: {:?}", self.full_nodes().await);
        info!("Increasing full_node count");
        let _ = self
            .dbs
            .full_adults
            .lock()
            .await
            .lcreate(&XorName::from(node_id).to_string())?
            .ladd(&"Node Full");
        Ok(())
    }

    /// Removes a given node from the list of full nodes.
    async fn decrease_full_node_count_if_present(&mut self, node_name: XorName) -> Result<()> {
        info!("No. of Full Nodes: {:?}", self.full_nodes().await);
        info!("Checking if {:?} is present as full_node", node_name);
        match self
            .dbs
            .full_adults
            .lock()
            .await
            .rem(&node_name.to_string())
        {
            Ok(true) => {
                info!("Node present in DB, remove successful");
                Ok(())
            }
            Ok(false) => {
                info!("Node not found on full_nodes db");
                Ok(())
            }
            Err(e) => {
                error!("Error removing from full_nodes db");
                Err(Error::PickleDb(e))
            }
        }
    }

    /// Number of full chunk storing nodes in the section.
    async fn full_nodes(&self) -> u8 {
        self.dbs.full_adults.lock().await.total_keys() as u8
    }

    async fn send_chunks_to_adults(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        // TODO: filter out full adults
        let target_holders = self
            .get_holders_for_chunk(data.name())
            .await
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        info!("Storing {} copies of the data", target_holders.len());

        let blob_write = BlobWrite::New(data);

        if self
            .adult_liveness
            .new_write(msg_id, blob_write.clone(), target_holders.clone())
        {
            Ok(NodeDuty::SendToNodes {
                targets: target_holders,
                msg: Message::NodeCmd {
                    cmd: NodeCmd::Chunks {
                        cmd: blob_write,
                        origin,
                    },
                    id: msg_id,
                },
                aggregation: Aggregation::AtDestination,
            })
        } else {
            info!(
                "Operation with MessageId {:?} is already in progress",
                msg_id
            );
            Ok(NodeDuty::NoOp)
        }
    }

    async fn store(&mut self, data: Blob, msg_id: MessageId, origin: EndUser) -> Result<NodeDuty> {
        let result = validate_data_owner(&data, &origin);
        if result.is_err() {
            return self.ok_or_error(result, msg_id, origin);
        }

        self.send_chunks_to_adults(data, msg_id, origin).await
    }

    pub async fn record_adult_write_liveness(
        &mut self,
        correlation_id: MessageId,
        result: Result<(), CmdError>,
        src: XorName,
    ) -> Result<NodeDuty> {
        if let Some(blob_write) = self
            .adult_liveness
            .record_adult_write_liveness(correlation_id, src)
        {
            if let Err(err) = result {
                error!("Error at Adult while performing a BlobWrite: {:?}", err);
                // Depending on error, we might have to take action here.
            } else {
                info!(
                    "AdultWrite operation {:?} MessageId {:?} at {:?} was successful",
                    blob_write, correlation_id, src
                );
            }
        }
        let mut unresponsive_adults = Vec::new();
        for (name, count) in self.adult_liveness.find_unresponsive_adults() {
            warn!(
                "Adult {} has {} pending ops. It might be unresponsive",
                name, count
            );
            unresponsive_adults.push(name);
        }
        Ok(NodeDuty::ProposeOffline(unresponsive_adults))
    }

    pub async fn record_adult_read_liveness(
        &mut self,
        correlation_id: MessageId,
        response: QueryResponse,
        src: XorName,
    ) -> Result<NodeDuty> {
        if !matches!(response, QueryResponse::GetBlob(_)) {
            return Err(Error::Logic(format!(
                "Got {:?}, but only `GetBlob` query responses are supposed to exist in this flow.",
                response
            )));
        }
        if let Some((_address, end_user)) = self
            .adult_liveness
            .record_adult_read_liveness(correlation_id, src)
        {
            return Ok(NodeDuty::Send(OutgoingMsg {
                msg: Message::QueryResponse {
                    response,
                    id: MessageId::in_response_to(&correlation_id),
                    correlation_id,
                },
                dst: DstLocation::EndUser(end_user),
                section_source: false,
                aggregation: Aggregation::AtDestination,
            }));
        }
        let mut unresponsive_adults = Vec::new();
        for (name, count) in self.adult_liveness.find_unresponsive_adults() {
            warn!(
                "Adult {} has {} pending ops. It might be unresponsive",
                name, count
            );
            unresponsive_adults.push(name);
        }
        Ok(NodeDuty::ProposeOffline(unresponsive_adults))
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
        let targets = self.get_holders_for_chunk(address.name()).await;
        // let full_adults = self.get_full_adults();

        let targets = targets.iter().cloned()
        // .chain(full_adults) TODO
        .collect::<BTreeSet<_>>();

        if self
            .adult_liveness
            .new_write(msg_id, BlobWrite::DeletePrivate(address), targets.clone())
        {
            let msg = Message::NodeCmd {
                cmd: NodeCmd::Chunks {
                    cmd: BlobWrite::DeletePrivate(address),
                    origin,
                },
                id: msg_id,
            };
            Ok(NodeDuty::SendToNodes {
                msg,
                targets,
                aggregation: Aggregation::AtDestination,
            })
        } else {
            info!(
                "Operation with MessageId {:?} is already in progress",
                msg_id
            );
            Ok(NodeDuty::NoOp)
        }
    }

    pub(super) async fn remove_and_replicate_chunks(
        &mut self,
        holder: XorName,
    ) -> Result<NodeDuties> {
        info!("Replicating chunks");
        // let chunks_stored = match self.remove_holder(holder).await {
        //     Ok(chunks) => chunks,
        //     _ => return Ok(vec![]),
        // };
        // let mut cmds = Vec::new();
        // for (address, holders) in chunks_stored {
        //     cmds.extend(self.get_chunk_queries(address, holders).await?);
        // }
        Ok(vec![])
    }

    pub(super) async fn replicate_chunk(&mut self, data: Blob) -> Result<NodeDuty> {
        info!("Replicating chunk");
        let owner = data.owner();

        // deterministic msg id for aggregation
        let msg_id = MessageId::from_content(&(*data.name(), owner))?;

        let target_holders = self
            .get_holders_for_chunk(data.name())
            .await
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        Ok(NodeDuty::SendToNodes {
            targets: target_holders,
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk(data)),
                id: msg_id,
            },
            aggregation: Aggregation::AtDestination,
        })
    }

    async fn get_chunk_queries(
        &mut self,
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
    ) -> Result<NodeDuties> {
        let mut node_ops = Vec::new();
        let messages = current_holders
            .into_iter()
            .map(|holder| {
                info!("Sending get-chunk query to holder {:?}", holder);
                (
                    Message::NodeQuery {
                        query: NodeQuery::System(NodeSystemQuery::GetChunk(address)),
                        id: MessageId::combine(vec![*address.name(), holder]),
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
        &mut self,
        read: &BlobRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        match read {
            BlobRead::Get(address) => self.get(*address, msg_id, origin).await,
        }
    }

    async fn get(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let targets = self.get_holders_for_chunk(address.name()).await;

        let targets = targets.into_iter()
        // .chain(full_adults) TODO
        .collect::<BTreeSet<_>>();

        if self
            .adult_liveness
            .new_read(msg_id, address, origin, targets.clone())
        {
            let msg = Message::NodeQuery {
                query: NodeQuery::Chunks {
                    query: BlobRead::Get(address),
                    origin,
                },
                id: msg_id,
            };

            Ok(NodeDuty::SendToNodes {
                msg,
                targets,
                aggregation: Aggregation::None,
            })
        } else {
            info!(
                "Operation with MessageId {:?} is already in progress",
                msg_id
            );
            Ok(NodeDuty::NoOp)
        }
    }

    // Returns `XorName`s of the target holders for an Blob chunk.
    // Used to fetch the list of holders for a new chunk.
    async fn get_holders_for_chunk(&self, target: &XorName) -> Vec<XorName> {
        self.reader
            .our_adults_sorted_by_distance_to(&target, CHUNK_COPY_COUNT)
            .await
    }

    fn ok_or_error(
        &self,
        result: Result<()>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        if let Err(error) = result {
            info!("BlobRecords: Writing chunk Failed. {:?}", error);
            let messaging_error = convert_to_error_message(error)?;

            Ok(NodeDuty::Send(OutgoingMsg {
                msg: Message::CmdError {
                    error: CmdError::Data(messaging_error),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                },
                section_source: false, // strictly this is not correct, but we don't expect responses to a response..
                dst: DstLocation::EndUser(origin),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            }))
        } else {
            Ok(NodeDuty::NoOp)
        }
    }
}

fn validate_data_owner(data: &Blob, origin: &EndUser) -> Result<()> {
    if data.is_private() {
        data.owner()
            .ok_or_else(|| Error::InvalidOwners(*origin.id()))
            .and_then(|data_owner| {
                if data_owner != origin.id() {
                    Err(Error::InvalidOwners(*origin.id()))
                } else {
                    Ok(())
                }
            })
    } else {
        Ok(())
    }
}

impl Display for BlobRecords {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "BlobRecords")
    }
}
