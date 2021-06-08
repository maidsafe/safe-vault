// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    btree_set,
    capacity::{Capacity, CHUNK_COPY_COUNT},
    error::convert_to_error_message,
    node_ops::{NodeDuties, NodeDuty},
    Error, Result,
};
use log::{info, warn};
use sn_data_types::{Blob, BlobAddress, PublicKey};
use sn_messaging::{
    client::{BlobDataExchange, BlobRead, BlobWrite, ClientSigned, CmdError, QueryResponse},
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
    adult_liveness::AdultLiveness, build_client_error_response, build_client_query_response,
};

/// Operations over the data type Blob.
pub(super) struct BlobRecords {
    capacity: Capacity,
    adult_liveness: AdultLiveness,
}

impl BlobRecords {
    pub(super) fn new(capacity: Capacity) -> Self {
        Self {
            capacity,
            adult_liveness: AdultLiveness::new(),
        }
    }

    pub async fn get_data_of(&self, prefix: Prefix) -> BlobDataExchange {
        // Prepare full_adult details
        let full_adults = self.capacity.full_adults_matching(prefix).await;
        BlobDataExchange { full_adults }
    }

    pub async fn update(&self, blob_data: BlobDataExchange) {
        let BlobDataExchange { full_adults } = blob_data;
        self.capacity.insert_full_adults(full_adults).await
    }

    /// Registered holders not present in provided list of members
    /// will be removed from adult_storage_info and no longer tracked for liveness.
    pub async fn retain_members_only(&mut self, members: BTreeSet<XorName>) -> Result<()> {
        // full adults
        self.capacity.retain_members_only(&members).await;

        // stop tracking liveness of absent holders
        self.adult_liveness.retain_members_only(members);

        Ok(())
    }

    pub(super) async fn write(
        &mut self,
        write: BlobWrite,
        msg_id: MessageId,
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use BlobWrite::*;
        match write {
            New(data) => self.store(data, msg_id, client_signed, origin).await,
            DeletePrivate(address) => self.delete(address, msg_id, client_signed, origin).await,
        }
    }

    /// Adds a given node to the list of full nodes.
    pub async fn increase_full_node_count(&mut self, node_id: PublicKey) {
        info!(
            "No. of full Adults: {:?}",
            self.capacity.full_adults_count().await
        );
        info!("Increasing full Adults count");
        self.capacity
            .insert_full_adults(btree_set!(XorName::from(node_id)))
            .await;
    }

    /// Removes a given node from the list of full nodes.
    #[allow(unused)] // TODO: Remove node from full list at 50% ?
    async fn decrease_full_adults_count_if_present(&mut self, node_name: XorName) {
        info!(
            "No. of Full Nodes: {:?}",
            self.capacity.full_adults_count().await
        );
        info!("Checking if {:?} is present as full_node", node_name);
        self.capacity
            .remove_full_adults(btree_set!(node_name))
            .await;
    }

    async fn send_chunks_to_adults(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let target_holders = self.capacity.get_chunk_holder_adults(data.name()).await;

        info!("Storing {} copies of the data", target_holders.len());

        if CHUNK_COPY_COUNT > target_holders.len() {
            return self
                .send_error(
                    Error::NoAdults(self.capacity.our_prefix().await),
                    msg_id,
                    origin,
                )
                .await;
        }

        let blob_write = BlobWrite::New(data);

        Ok(NodeDuty::SendToNodes {
            targets: target_holders,
            msg: NodeMsg::NodeCmd {
                cmd: NodeCmd::Chunks {
                    cmd: blob_write,
                    client_signed,
                    origin,
                },
                id: msg_id,
            },
            aggregation: Aggregation::AtDestination,
        })
    }

    async fn store(
        &mut self,
        data: Blob,
        msg_id: MessageId,
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        if let Err(error) = validate_data_owner(&data, &client_signed.public_key) {
            return self.send_error(error, msg_id, origin).await;
        }

        self.send_chunks_to_adults(data, msg_id, client_signed, origin)
            .await
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
        if let Some((_address, end_user)) = self.adult_liveness.record_adult_read_liveness(
            correlation_id,
            &src,
            response.is_success(),
        ) {
            // If a full adult responds with error. Drop the response
            if !response.is_success() && self.capacity.is_full(&src).await {
                // We've already responded already with a success
                // so do nothing
            } else {
                duties.push(NodeDuty::Send(build_client_query_response(
                    response,
                    correlation_id,
                    end_user,
                )));
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
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let targets = self.capacity.get_chunk_holder_adults(address.name()).await;

        let msg = NodeMsg::NodeCmd {
            cmd: NodeCmd::Chunks {
                cmd: BlobWrite::DeletePrivate(address),
                client_signed,
                origin,
            },
            id: msg_id,
        };
        Ok(NodeDuty::SendToNodes {
            msg,
            targets,
            aggregation: Aggregation::AtDestination,
        })
    }

    pub(super) async fn republish_chunk(&mut self, data: Blob) -> Result<NodeDuty> {
        let owner = data.owner();
        let target_holders = self.capacity.get_chunk_holder_adults(data.name()).await;
        // deterministic msg id for aggregation
        let msg_id = MessageId::from_content(&(*data.name(), owner, &target_holders))?;

        info!(
            "Republishing chunk {:?} to holders {:?} with MessageId {:?}",
            data.address(),
            &target_holders,
            msg_id
        );

        Ok(NodeDuty::SendToNodes {
            targets: target_holders,
            msg: NodeMsg::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk(data)),
                id: msg_id,
            },
            aggregation: Aggregation::None,
        })
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
        let targets = self.capacity.get_chunk_holder_adults(address.name()).await;

        if targets.is_empty() {
            return self
                .send_error(
                    Error::NoAdults(self.capacity.our_prefix().await),
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
}

fn validate_data_owner(data: &Blob, requester: &PublicKey) -> Result<()> {
    if data.is_private() {
        data.owner()
            .ok_or_else(|| Error::InvalidOwner(*requester))
            .and_then(|data_owner| {
                if data_owner != requester {
                    Err(Error::InvalidOwner(*requester))
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
