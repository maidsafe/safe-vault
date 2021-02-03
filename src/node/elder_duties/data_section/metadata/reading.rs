// Copyright 2020 MaidSafe.net limited.
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
use crate::node::node_ops::NodeMessagingDuty;
use crate::{Error, Result};
use log::info;
use sn_messaging::client::{
    BlobRead, DataQuery, MapRead, Message, MessageId, MsgEnvelope, MsgSender, Query, SequenceRead,
};

pub(super) async fn get_result(
    msg: MsgEnvelope,
    stores: &ElderStores,
) -> Result<NodeMessagingDuty> {
    use DataQuery::*;
    let msg_id = msg.id();
    let origin = msg.origin;
    let proxies = msg.proxies;
    let res = match msg.message {
        Message::Query {
            query: Query::Data(data_query),
            ..
        } => match &data_query {
            Blob(read) => blob(read, stores.blob_register(), msg_id, origin, proxies).await,
            Map(read) => map(read, stores.map_storage(), msg_id, origin).await,
            Sequence(read) => sequence(read, stores.sequence_storage(), msg_id, origin).await,
        },
        _ => Err(Error::Logic(
            "Unreachable pattern when reading data.".to_string(),
        )),
    };
    if res.is_ok() {
        info!("Read data queried by message: '{:?}' successfully!", msg_id);
    }
    res
}

async fn blob(
    read: &BlobRead,
    register: &BlobRegister,
    msg_id: MessageId,
    origin: MsgSender,
    proxies: Vec<MsgSender>,
) -> Result<NodeMessagingDuty> {
    register.read(read, msg_id, origin, proxies).await // since the data is sent on to adults, the entire msg is passed in
}

async fn map(
    read: &MapRead,
    storage: &MapStorage,
    msg_id: MessageId,
    origin: MsgSender,
) -> Result<NodeMessagingDuty> {
    storage.read(read, msg_id, &origin).await // map data currently stay at elders, so the msg is not needed
}

async fn sequence(
    read: &SequenceRead,
    storage: &SequenceStorage,
    msg_id: MessageId,
    origin: MsgSender,
) -> Result<NodeMessagingDuty> {
    storage.read(read, msg_id, &origin).await // sequence data currently stay at elders, so the msg is not needed
}
