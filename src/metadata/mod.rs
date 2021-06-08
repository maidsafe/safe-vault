// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adult_liveness;
pub mod adult_reader;
mod blob_records;
mod elder_stores;
mod map_storage;
mod register_storage;
mod sequence_storage;

use crate::{
    capacity::Capacity,
    node_ops::{MsgType, NodeDuties, NodeDuty, OutgoingMsg},
    Result,
};
use blob_records::BlobRecords;
use elder_stores::ElderStores;
use map_storage::MapStorage;
use register_storage::RegisterStorage;
use sequence_storage::SequenceStorage;
use sn_data_types::{Blob, PublicKey};
use sn_messaging::{
    client::{
        ClientMsg, ClientSigned, CmdError, DataCmd, DataExchange, DataQuery, ProcessMsg,
        QueryResponse,
    },
    Aggregation, DstLocation, EndUser, MessageId,
};
use sn_routing::Prefix;
use std::{
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    path::Path,
};
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
    pub async fn new(path: &Path, max_capacity: u64, capacity: Capacity) -> Result<Self> {
        let blob_records = BlobRecords::new(capacity);
        let map_storage = MapStorage::new(path, max_capacity).await?;
        let sequence_storage = SequenceStorage::new(path, max_capacity).await?;
        let register_storage = RegisterStorage::new(path, max_capacity).await?;
        let elder_stores = ElderStores::new(
            blob_records,
            map_storage,
            sequence_storage,
            register_storage,
        );
        Ok(Self { elder_stores })
    }

    pub async fn read(
        &mut self,
        query: DataQuery,
        id: MessageId,
        requester: PublicKey,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        self.elder_stores.read(query, id, requester, origin).await
    }

    pub async fn record_adult_read_liveness(
        &mut self,
        correlation_id: MessageId,
        result: QueryResponse,
        src: XorName,
    ) -> Result<NodeDuties> {
        self.elder_stores
            .blob_records_mut()
            .record_adult_read_liveness(correlation_id, result, src)
            .await
    }

    pub async fn retain_members_only(&mut self, members: BTreeSet<XorName>) -> Result<()> {
        self.elder_stores
            .blob_records_mut()
            .retain_members_only(members)
            .await?;
        Ok(())
    }

    pub async fn write(
        &mut self,
        cmd: DataCmd,
        id: MessageId,
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        self.elder_stores
            .write(cmd, id, client_signed, origin)
            .await
    }

    /// Adds a given node to the list of full nodes.
    pub async fn increase_full_node_count(&mut self, node_id: PublicKey) {
        self.elder_stores
            .blob_records_mut()
            .increase_full_node_count(node_id)
            .await
    }

    // When receiving the chunk from remaining holders, we ask new holders to store it.
    pub async fn republish_chunk(&mut self, data: Blob) -> Result<NodeDuty> {
        self.elder_stores
            .blob_records_mut()
            .republish_chunk(data)
            .await
    }

    pub async fn get_data_exchange_packet(&self, prefix: Prefix) -> Result<DataExchange> {
        self.elder_stores.get_data_of(prefix).await
    }

    pub async fn update(&mut self, data: DataExchange) -> Result<()> {
        self.elder_stores.update(data).await
    }
}

impl Display for Metadata {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Metadata")
    }
}

fn build_client_query_response(
    response: QueryResponse,
    msg_id: MessageId,
    origin: EndUser,
) -> OutgoingMsg {
    OutgoingMsg {
        msg: MsgType::Client(ClientMsg::Process(ProcessMsg::QueryResponse {
            id: MessageId::in_response_to(&msg_id),
            response,
            correlation_id: msg_id,
        })),
        section_source: false, // strictly this is not correct, but we don't expect responses to a response..
        dst: DstLocation::EndUser(origin),
        aggregation: Aggregation::None,
    }
}

fn build_client_error_response(error: CmdError, msg_id: MessageId, origin: EndUser) -> OutgoingMsg {
    OutgoingMsg {
        msg: MsgType::Client(ClientMsg::Process(ProcessMsg::CmdError {
            id: MessageId::in_response_to(&msg_id),
            error,
            correlation_id: msg_id,
        })),
        section_source: false, // strictly this is not correct, but we don't expect responses to an error..
        dst: DstLocation::EndUser(origin),
        aggregation: Aggregation::None,
    }
}
