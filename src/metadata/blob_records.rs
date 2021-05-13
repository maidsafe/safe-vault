// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::AdultsStorageInfo,
    error::convert_to_error_message,
    node_ops::{NodeDuties, NodeDuty},
    Error, Result,
};
use log::{debug, error, info, warn};
use sn_data_types::{Blob, BlobAddress, PublicKey};
use sn_messaging::{
    client::{BlobDataExchange, BlobRead, BlobWrite, CmdError, QueryResponse},
    node::{NodeCmd, NodeMsg, NodeQuery, NodeSystemCmd},
    Aggregation, EndUser, MessageId,
};
use sn_routing::Prefix;

use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
};
use xor_name::XorName;

use super::{
    adult_liveness::AdultLiveness, adult_reader::AdultReader, build_client_error_response,
    build_client_query_response,
};

// The number of separate copies of a blob chunk which should be maintained.
pub(crate) const CHUNK_COPY_COUNT: usize = 4;

/// Operations over the data type Blob.
pub(super) struct BlobRecords {
    adult_storage_info: AdultsStorageInfo,
    reader: AdultReader,
    adult_liveness: AdultLiveness,
}

impl BlobRecords {
    pub(super) fn new(adult_storage_info: AdultsStorageInfo, reader: AdultReader) -> Self {
        Self {
            adult_storage_info,
            reader,
            adult_liveness: AdultLiveness::new(),
        }
    }

    pub async fn get_data_of(&self, prefix: Prefix) -> BlobDataExchange {
        // Prepare full_adult details
        let full_adults = self
            .adult_storage_info
            .full_adults
            .read()
            .await
            .iter()
            .filter(|name| prefix.matches(name))
            .copied()
            .collect();
        BlobDataExchange { full_adults }
    }

    pub async fn update(&self, blob_data: BlobDataExchange) -> Result<()> {
        debug!("Updating Blob records");
        let mut orig_full_adults = self.adult_storage_info.full_adults.write().await;

        let BlobDataExchange { full_adults } = blob_data;

        for adult in full_adults {
            let _ = orig_full_adults.insert(adult);
        }

        Ok(())
    }

    /// Registered holders not present in provided list of members
    /// will be removed from adult_storage_info and no longer tracked for liveness.
    pub async fn retain_members_only(&mut self, members: BTreeSet<XorName>) -> Result<()> {
        // full adults
        let mut full_adults = self.adult_storage_info.full_adults.write().await;
        let absent_adults = full_adults
            .iter()
            .filter(|key| !members.contains(key))
            .cloned()
            .collect::<Vec<_>>();

        for adult in &absent_adults {
            let _ = full_adults.remove(adult);
        }

        // stop tracking liveness of absent holders
        self.adult_liveness.retain_members_only(members);

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
            .adult_storage_info
            .full_adults
            .write()
            .await
            .insert(XorName::from(node_id));
        Ok(())
    }

    /// Removes a given node from the list of full nodes.
    #[allow(unused)] // TODO: Remove node from full list at 50% ?
    async fn decrease_full_node_count_if_present(&mut self, node_name: XorName) -> Result<()> {
        info!("No. of Full Nodes: {:?}", self.full_nodes().await);
        info!("Checking if {:?} is present as full_node", node_name);
        match self
            .adult_storage_info
            .full_adults
            .write()
            .await
            .remove(&node_name)
        {
            true => {
                info!("Node present in DB, remove successful");
                Ok(())
            }
            false => {
                info!("Node not found on full_nodes db");
                Ok(())
            }
        }
    }

    /// Number of full chunk storing nodes in the section.
    async fn full_nodes(&self) -> u8 {
        self.adult_storage_info.full_adults.read().await.len() as u8
    }

    async fn send_chunks_to_adults(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let target_holders = self
            .get_holders_for_chunk(data.name())
            .await
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        info!("Storing {} copies of the data", target_holders.len());

        if target_holders.is_empty() {
            return self
                .send_error(
                    Error::NoAdults(self.reader.our_prefix().await),
                    msg_id,
                    origin,
                )
                .await;
        }

        let blob_address = *data.address();
        let blob_write = BlobWrite::New(data);

        if self
            .adult_liveness
            .new_write(msg_id, Some(origin), blob_address, &target_holders)
        {
            Ok(NodeDuty::SendToNodes {
                targets: target_holders,
                msg: NodeMsg::NodeCmd {
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
        if let Err(error) = validate_data_owner(&data, &origin) {
            return self.send_error(error, msg_id, origin).await;
        }

        self.send_chunks_to_adults(data, msg_id, origin).await
    }

    pub async fn record_adult_write_liveness(
        &mut self,
        correlation_id: MessageId,
        result: Result<(), CmdError>,
        src: XorName,
    ) -> NodeDuties {
        let mut duties = vec![];
        if let Some((address, origin)) = self
            .adult_liveness
            .record_adult_write_liveness(correlation_id, src)
        {
            if let Err(error) = result {
                error!("Error at Adult while performing a BlobWrite: {:?}", &error);
                // Depending on error, we might have to take action here.
                if let Some(end_user) = origin {
                    duties.push(NodeDuty::Send(build_client_error_response(
                        error,
                        correlation_id,
                        end_user,
                    )))
                }
            } else {
                info!(
                    "AdultWrite operation at {:?} MessageId {:?} at {:?} was successful",
                    address, correlation_id, src
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
        if !unresponsive_adults.is_empty() {
            duties.push(NodeDuty::ProposeOffline(unresponsive_adults))
        }
        duties
    }

    pub async fn record_adult_read_liveness(
        &mut self,
        correlation_id: MessageId,
        response: QueryResponse,
        src: XorName,
    ) -> Result<NodeDuties> {
        if !matches!(response, QueryResponse::GetBlob(_)) {
            return Err(Error::Logic(format!(
                "Got {:?}, but only `GetBlob` query responses are supposed to exist in this flow.",
                response
            )));
        }
        let mut duties = vec![];
        if let Some((_address, end_user)) = self
            .adult_liveness
            .record_adult_read_liveness(correlation_id, src)
        {
            return Ok(vec![NodeDuty::Send(build_client_query_response(
                response,
                correlation_id,
                end_user,
            ))]);
        }
        let mut unresponsive_adults = Vec::new();
        for (name, count) in self.adult_liveness.find_unresponsive_adults() {
            warn!(
                "Adult {} has {} pending ops. It might be unresponsive",
                name, count
            );
            unresponsive_adults.push(name);
        }
        if !unresponsive_adults.is_empty() {
            duties.push(NodeDuty::ProposeOffline(unresponsive_adults));
        }
        Ok(duties)
    }

    async fn send_error(
        &self,
        error: Error,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let error = convert_to_error_message(error);
        Ok(NodeDuty::Send(build_client_error_response(
            CmdError::Data(error),
            msg_id,
            origin,
        )))
    }

    async fn delete(
        &mut self,
        address: BlobAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let targets = self.get_holders_for_chunk(address.name()).await;
        let targets = targets.iter().cloned().collect::<BTreeSet<_>>();

        if self
            .adult_liveness
            .new_write(msg_id, Some(origin), address, &targets)
        {
            let msg = NodeMsg::NodeCmd {
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

    pub(super) async fn republish_chunk(&mut self, data: Blob) -> Result<NodeDuty> {
        let owner = data.owner();

        let target_holders = self
            .get_holders_for_chunk(data.name())
            .await
            .into_iter()
            .collect::<BTreeSet<_>>();

        // deterministic msg id for aggregation
        let msg_id = MessageId::from_content(&(*data.name(), owner, &target_holders))?;

        info!(
            "Republishing chunk {:?} to holders {:?} with MessageId {:?}",
            data.address(),
            &target_holders,
            msg_id
        );

        if self
            .adult_liveness
            .new_write(msg_id, None, *data.address(), &target_holders)
        {
            Ok(NodeDuty::SendToNodes {
                targets: target_holders,
                msg: NodeMsg::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk(data)),
                    id: msg_id,
                },
                aggregation: Aggregation::None,
            })
        } else {
            info!("Skipping chunk republish since it's already in progress");
            Ok(NodeDuty::NoOp)
        }
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

        let targets = targets.into_iter().collect::<BTreeSet<_>>();

        if targets.is_empty() {
            return self
                .send_error(
                    Error::NoAdults(self.reader.our_prefix().await),
                    msg_id,
                    origin,
                )
                .await;
        }

        if self
            .adult_liveness
            .new_read(msg_id, address, origin, targets.clone())
        {
            let msg = NodeMsg::NodeQuery {
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
        let full_adults = self.adult_storage_info.full_adults.read().await;
        self.reader
            .non_full_adults_closest_to(&target, &full_adults, CHUNK_COPY_COUNT)
            .await
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
