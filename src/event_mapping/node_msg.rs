// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Mapping;
use crate::{
    error::convert_to_error_message,
    event_mapping::MsgContext,
    node_ops::{MsgType, NodeDuty, OutgoingMsg},
    Error,
};
use log::debug;
use sn_messaging::{
    node::{
        NodeCmd, NodeDataQueryResponse, NodeEvent, NodeMsg, NodeQuery, NodeQueryResponse,
        NodeRewardQuery, NodeSystemCmd, NodeSystemQuery, NodeTransferCmd, NodeTransferQuery,
    },
    Aggregation, DstLocation, MessageId, Msg, SrcLocation,
};

pub fn map_node_msg(msg: NodeMsg, src: SrcLocation, dst: DstLocation) -> Mapping {
    debug!(
        "Handling Node message received event with id {}: {:?}",
        msg.id(),
        msg
    );

    match &dst {
        DstLocation::Section(_) | DstLocation::Node(_) => Mapping {
            op: match_node_msg(msg.clone(), src),
            ctx: Some(MsgContext {
                msg: Msg::Node(msg),
                src,
            }),
        },
        _ => {
            let msg_id = msg.id();
            let error = convert_to_error_message(Error::InvalidMessage(
                msg_id,
                format!("Invalid dst: {:?}", msg),
            ));

            if let SrcLocation::EndUser(_) = src {
                log::error!("Logic error! EndUser cannot send NodeMsgs. ({:?})", msg);
                return Mapping {
                    op: NodeDuty::NoOp,
                    ctx: None,
                };
            }

            Mapping {
                op: NodeDuty::Send(OutgoingMsg {
                    msg: MsgType::Node(NodeMsg::NodeMsgError {
                        error,
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                    }),
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: src.to_dst(),
                    aggregation: Aggregation::AtDestination,
                }),
                ctx: Some(MsgContext {
                    msg: Msg::Node(msg),
                    src,
                }),
            }
        }
    }
}

fn match_node_msg(msg: NodeMsg, origin: SrcLocation) -> NodeDuty {
    match msg {
        // ------ wallet register ------
        NodeMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(wallet_id)),
            ..
        } => NodeDuty::SetNodeWallet {
            wallet_id,
            node_id: origin.name(),
        },
        // Churn synch
        NodeMsg::NodeCmd {
            cmd:
                NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards,
                    user_wallets,
                    metadata,
                }),
            ..
        } => NodeDuty::SynchState {
            node_rewards,
            user_wallets,
            metadata,
        },
        NodeMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeRewardPayout(proposal)),
            ..
        } => NodeDuty::ReceiveRewardProposal(proposal),
        NodeMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateRewardPayout(accumulation)),
            ..
        } => NodeDuty::ReceiveRewardAccumulation(accumulation),
        // ------ section funds -----
        NodeMsg::NodeQuery {
            query: NodeQuery::Rewards(NodeRewardQuery::GetNodeWalletKey(node_name)),
            id,
            ..
        } => NodeDuty::GetNodeWalletKey {
            node_name,
            msg_id: id,
            origin,
        },
        //
        // ------ transfers --------
        NodeMsg::NodeCmd {
            cmd: NodeCmd::Transfers(NodeTransferCmd::PropagateTransfer(proof)),
            id,
            ..
        } => NodeDuty::PropagateTransfer {
            proof,
            msg_id: id,
            origin,
        },
        // ------ metadata ------
        NodeMsg::NodeQuery {
            query:
                NodeQuery::Metadata {
                    query,
                    client_signed,
                    origin,
                },
            id,
            ..
        } => {
            // FIXME: ******** validate client signature!!!! *********

            NodeDuty::ProcessRead {
                query,
                msg_id: id,
                client_signed,
                origin,
            }
        }
        NodeMsg::NodeCmd {
            cmd:
                NodeCmd::Metadata {
                    cmd,
                    client_signed,
                    origin,
                },
            id,
            ..
        } => {
            // FIXME: ******** validate client signature!!!! *********

            NodeDuty::ProcessWrite {
                cmd,
                msg_id: id,
                client_signed,
                origin,
            }
        }
        //
        // ------ Adult ------
        NodeMsg::NodeQuery {
            query: NodeQuery::Chunks { query, .. },
            id,
            ..
        } => NodeDuty::ReadChunk {
            read: query,
            msg_id: id,
        },
        NodeMsg::NodeCmd {
            cmd: NodeCmd::Chunks {
                cmd, client_signed, ..
            },
            id,
            ..
        } => NodeDuty::WriteChunk {
            write: cmd,
            msg_id: id,
            client_signed,
        },
        // this cmd is accumulated, thus has authority
        NodeMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk(data)),
            id,
        } => NodeDuty::ReplicateChunk { data, msg_id: id },
        NodeMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::RepublishChunk(data)),
            id,
        } => NodeDuty::ProcessRepublish {
            chunk: data,
            msg_id: id,
        },
        // Aggregated by us, for security
        NodeMsg::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id,
            ..
        } => NodeDuty::GetSectionElders { msg_id: id, origin },
        //
        // ------ system cmd ------
        NodeMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::StorageFull { node_id, .. }),
            ..
        } => NodeDuty::IncrementFullNodeCount { node_id },
        //
        // ------ transfers ------
        NodeMsg::NodeQuery {
            query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents),
            id,
            ..
        } => NodeDuty::GetTransferReplicaEvents { msg_id: id, origin },
        // --- Adult Operation response ---
        NodeMsg::NodeEvent {
            event: NodeEvent::ChunkWriteHandled(result),
            correlation_id,
            ..
        } => NodeDuty::RecordAdultWriteLiveness {
            result,
            correlation_id,
            src: origin.name(),
        },
        NodeMsg::NodeQueryResponse {
            response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(res)),
            correlation_id,
            ..
        } => NodeDuty::RecordAdultReadLiveness {
            response: sn_messaging::client::QueryResponse::GetBlob(res),
            correlation_id,
            src: origin.name(),
        },
        _ => {
            let msg_id = msg.id();
            let error = convert_to_error_message(Error::InvalidMessage(
                msg_id,
                format!("Invalid dst: {:?}", msg),
            ));

            NodeDuty::Send(OutgoingMsg {
                msg: MsgType::Node(NodeMsg::NodeMsgError {
                    error,
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                }),
                section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                dst: origin.to_dst(),
                aggregation: Aggregation::AtDestination,
            })
        }
    }
}
