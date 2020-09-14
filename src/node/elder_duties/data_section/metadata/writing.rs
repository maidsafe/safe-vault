// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    account_storage::AccountStorage, blob_register::BlobRegister, elder_stores::ElderStores,
    map_storage::MapStorage, sequence_storage::SequenceStorage,
};
use crate::node::node_ops::{NodeMessagingDuty, NodeOperation};
use sn_data_types::{
    AccountWrite, BlobWrite, Cmd, DataCmd, DebitAgreementProof, MapWrite, Message, MessageId,
    MsgEnvelope, MsgSender, SequenceWrite,
};

pub(super) async fn get_result(msg: MsgEnvelope, stores: &mut ElderStores) -> Option<NodeOperation> {
    use DataCmd::*;
    let msg_id = msg.id();
    let msg_origin = msg.origin;
    let proxies = msg.proxies;
    let result = match msg.message {
        Message::Cmd {
            cmd: Cmd::Data {
                cmd: data_cmd,
                payment,
            },
            ..
        } => match data_cmd {
            Blob(write) => blob(
                write,
                stores.blob_register_mut(),
                msg_id,
                msg_origin,
                payment,
                proxies,
            ).await,
            Map(write) => map(write, stores.map_storage_mut(), msg_id, msg_origin),
            Sequence(write) => sequence(write, stores.sequence_storage_mut(), msg_id, msg_origin),
            Account(write) => account(write, stores.account_storage_mut(), msg_id, msg_origin),
        },
        _ => unreachable!("Logic error"),
    };
    result.map(|c| c.into())
}

async fn blob(
    write: BlobWrite,
    register: &mut BlobRegister,
    msg_id: MessageId,
    origin: MsgSender,
    payment: DebitAgreementProof,
    proxies: Vec<MsgSender>,
) -> Option<NodeMessagingDuty> {
    register.write(write, msg_id, origin, payment, proxies).await
}

fn map(
    write: MapWrite,
    storage: &mut MapStorage,
    msg_id: MessageId,
    origin: MsgSender,
) -> Option<NodeMessagingDuty> {
    storage.write(write, msg_id, &origin)
}

fn sequence(
    write: SequenceWrite,
    storage: &mut SequenceStorage,
    msg_id: MessageId,
    origin: MsgSender,
) -> Option<NodeMessagingDuty> {
    storage.write(write, msg_id, &origin)
}

fn account(
    write: AccountWrite,
    storage: &mut AccountStorage,
    msg_id: MessageId,
    origin: MsgSender,
) -> Option<NodeMessagingDuty> {
    storage.write(write, msg_id, &origin)
}
