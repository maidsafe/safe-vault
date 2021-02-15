// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    blob_register::BlobRegister, elder_stores::ElderStores, map_storage::MapStorage,
    sequence_storage::SequenceStorage,
};
use crate::node::node_ops::{IntoNodeOp, NodeMessagingDuty, };
use crate::Result;
use log::info;
use sn_messaging::{
    client::{BlobWrite, DataCmd, MapWrite, SequenceWrite},
    EndUser, MessageId,
};

pub(super) async fn get_result(
    cmd: DataCmd,
    msg_id: MessageId,
    origin: EndUser,
    stores: &mut ElderStores,
) -> Result<Vec<NetworkDuty>> {
    use DataCmd::*;
    info!("Writing Data");
    match cmd {
        Blob(write) => {
            info!("Writing Blob");
            blob(write, stores.blob_register_mut(), msg_id, origin).await
        }
        Map(write) => {
            info!("Writing Map");
            map(write, stores.map_storage_mut(), msg_id, origin).await
        }
        Sequence(write) => {
            info!("Writing Sequence");
            sequence(write, stores.sequence_storage_mut(), msg_id, origin).await
        }
    }
    .convert()
}

async fn blob(
    write: BlobWrite,
    register: &mut BlobRegister,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeMessagingDuty> {
    register.write(write, msg_id, origin).await
}

async fn map(
    write: MapWrite,
    storage: &mut MapStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeMessagingDuty> {
    storage.write(write, msg_id, origin).await
}

async fn sequence(
    write: SequenceWrite,
    storage: &mut SequenceStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeMessagingDuty> {
    storage.write(write, msg_id, origin).await
}
