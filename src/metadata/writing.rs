// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    blob_records::BlobRecords, elder_stores::ElderStores, map_storage::MapStorage,
    register_storage::RegisterStorage, sequence_storage::SequenceStorage,
};
use crate::{node_ops::NodeDuty, Result};
use log::info;
use sn_messaging::{
    client::{BlobWrite, DataCmd, MapWrite, RegisterWrite, SequenceWrite},
    EndUser, MessageId,
};

pub(super) async fn get_result(
    cmd: DataCmd,
    msg_id: MessageId,
    origin: EndUser,
    stores: &mut ElderStores,
) -> Result<NodeDuty> {
    use DataCmd::*;
    info!("Writing Data");
    match cmd {
        Blob(write) => {
            info!("Writing Blob");
            blob(write, stores.blob_records_mut(), msg_id, origin).await
        }
        Map(write) => {
            info!("Writing Map");
            map(write, stores.map_storage_mut(), msg_id, origin).await
        }
        Sequence(write) => {
            info!("Writing Sequence");
            sequence(write, stores.sequence_storage_mut(), msg_id, origin).await
        }
        Register(write) => {
            info!("Writing Register");
            register(write, stores.register_storage_mut(), msg_id, origin).await
        }
    }
}

async fn blob(
    write: BlobWrite,
    register: &mut BlobRecords,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    register.write(write, msg_id, origin).await
}

async fn map(
    write: MapWrite,
    storage: &mut MapStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    storage.write(write, msg_id, origin).await
}

async fn sequence(
    write: SequenceWrite,
    storage: &mut SequenceStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    storage.write(write, msg_id, origin).await
}

async fn register(
    write: RegisterWrite,
    storage: &mut RegisterStorage,
    msg_id: MessageId,
    origin: EndUser,
) -> Result<NodeDuty> {
    storage.write(write, msg_id, origin).await
}
