// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Read operations on data.

use super::{
    blob_records::BlobRecords, elder_stores::ElderStores, map_storage::MapStorage,
    register_storage::RegisterStorage, sequence_storage::SequenceStorage,
};
use crate::{node_ops::NodeDuty, Result};
use sn_messaging::{
    client::{BlobRead, DataQuery, MapRead, RegisterRead, SequenceRead},
    EndUser, MessageId,
};

pub(super) async fn get_result(
    query: DataQuery,
    msg_id: MessageId,
    origin: EndUser,
    stores: &mut ElderStores,
) -> Result<NodeDuty> {
    use DataQuery::*;
    match &query {
        Blob(read) => blob(read, stores.blob_records_mut(), msg_id, origin).await,
        Map(read) => map(read, stores.map_storage(), msg_id, origin).await,
        Sequence(read) => sequence(read, stores.sequence_storage(), msg_id, origin).await,
        Register(read) => register(read, stores.register_storage(), msg_id, origin).await,
    }
}

async fn blob(
    read: &BlobRead,
    register: &mut BlobRecords,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    register.read(read, msg_id, origin).await
}

async fn map(
    read: &MapRead,
    storage: &MapStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    storage.read(read, msg_id, origin).await
}

async fn sequence(
    read: &SequenceRead,
    storage: &SequenceStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    storage.read(read, msg_id, origin).await
}

async fn register(
    read: &RegisterRead,
    storage: &RegisterStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    storage.read(read, msg_id, origin).await
}
