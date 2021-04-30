// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Mapping, MsgContext};
use crate::{
    error::convert_to_error_message,
    node_ops::{NodeDuty, OutgoingMsg},
    Error,
};
use sn_messaging::{
    client::{Cmd, CmdError, Message, Query, TransferCmd, TransferQuery},
    Aggregation, EndUser, MessageId, SrcLocation,
};

pub fn map_client_msg(msg: Message, origin: EndUser) -> Mapping {
    match msg.to_owned() {
        Message::Query {
            query: Query::Data(query),
            id,
            ..
        } => Mapping {
            op: NodeDuty::ProcessRead { query, id, origin },
            ctx: Some(super::MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        Message::Cmd {
            cmd: Cmd::Data { .. },
            ..
        } => Mapping {
            op: NodeDuty::ProcessDataPayment {
                msg: msg.clone(),
                origin,
            },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        Message::Cmd {
            cmd: Cmd::Transfer(TransferCmd::ValidateTransfer(signed_transfer)),
            id,
            ..
        } => Mapping {
            op: NodeDuty::ValidateClientTransfer {
                signed_transfer,
                origin: SrcLocation::EndUser(origin),
                msg_id: id,
            },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        // TODO: Map more transfer cmds
        Message::Cmd {
            cmd: Cmd::Transfer(TransferCmd::SimulatePayout(transfer)),
            id,
            ..
        } => Mapping {
            op: NodeDuty::SimulatePayout {
                transfer,
                origin: SrcLocation::EndUser(origin),
                msg_id: id,
            },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        Message::Cmd {
            cmd: Cmd::Transfer(TransferCmd::RegisterTransfer(proof)),
            id,
            ..
        } => Mapping {
            op: NodeDuty::RegisterTransfer { proof, msg_id: id },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        // TODO: Map more transfer queries
        Message::Query {
            query: Query::Transfer(TransferQuery::GetHistory { at, since_version }),
            id,
            ..
        } => Mapping {
            op: NodeDuty::GetTransfersHistory {
                at,
                since_version,
                origin: SrcLocation::EndUser(origin),
                msg_id: id,
            },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        Message::Query {
            query: Query::Transfer(TransferQuery::GetBalance(at)),
            id,
            ..
        } => Mapping {
            op: NodeDuty::GetBalance {
                at,
                origin: SrcLocation::EndUser(origin),
                msg_id: id,
            },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        Message::Query {
            query: Query::Transfer(TransferQuery::GetStoreCost { bytes, .. }),
            id,
            ..
        } => Mapping {
            op: NodeDuty::GetStoreCost {
                bytes,
                origin: SrcLocation::EndUser(origin),
                msg_id: id,
            },
            ctx: Some(MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        _ => {
            let msg_id = msg.id();
            let error_data = convert_to_error_message(Error::InvalidMessage(
                msg.id(),
                format!("Unknown user msg: {:?}", msg),
            ));
            let src = SrcLocation::EndUser(origin);

            Mapping {
                ctx: Some(MsgContext::Msg { msg, src }),
                op: NodeDuty::Send(OutgoingMsg {
                    msg: Message::CmdError {
                        error: CmdError::Data(error_data),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: src.to_dst(),
                    aggregation: Aggregation::None,
                }),
            }
        }
    }
}
