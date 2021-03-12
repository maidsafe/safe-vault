// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Read operations on data.

use super::{
    blob_register::BlobRegister, elder_stores::ElderStores, map_storage::MapStorage,
    sequence_storage::SequenceStorage,
};
use crate::node::node_ops::{NetworkDuties, NodeMessagingDuty};
use crate::Result;
use sn_messaging::{
    client::{BlobRead, DataQuery, MapRead, SequenceRead},
    EndUser, MessageId,
};

pub(super) async fn get_result(
    query: DataQuery,
    msg_id: MessageId,
    origin: EndUser,
    stores: &ElderStores,
) -> Result<NetworkDuties> {
    use DataQuery::*;
    let duty = match &query {
        Blob(read) => blob(read, stores.blob_register(), msg_id, origin).await?,
        Map(read) => map(read, stores.map_storage(), msg_id, origin).await?,
        Sequence(read) => sequence(read, stores.sequence_storage(), msg_id, origin).await?,
    };

    Ok(NetworkDuties::from(duty))
}

async fn blob(
    read: &BlobRead,
    register: &BlobRegister,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeMessagingDuty> {
    register.read(read, msg_id, origin).await
}

async fn map(
    read: &MapRead,
    storage: &MapStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeMessagingDuty> {
    storage.read(read, msg_id, origin).await
}

async fn sequence(
    read: &SequenceRead,
    storage: &SequenceStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeMessagingDuty> {
    storage.read(read, msg_id, origin).await
}
