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
    client::{
        CmdError, Message, NodeCmd, NodeDataQueryResponse, NodeEvent, NodeQuery, NodeQueryResponse,
        NodeRewardQuery, NodeSystemCmd, NodeSystemQuery, NodeTransferCmd, NodeTransferQuery,
        QueryResponse,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};

pub fn map_node_msg(msg: Message, src: SrcLocation, dst: DstLocation) -> Mapping {
    match &dst {
        DstLocation::Section(_) | DstLocation::Node(_) => match match_node_msg(&msg, src) {
            NodeDuty::NoOp => {
                let msg_id = msg.id();
                let error_data = convert_to_error_message(Error::InvalidMessage(
                    msg.id(),
                    format!("Unknown msg: {:?}", msg),
                ));

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
            op => Mapping {
                op,
                ctx: Some(MsgContext::Msg { msg, src }),
            },
        },
        _ => {
            let msg_id = msg.id();
            let error_data = convert_to_error_message(Error::InvalidMessage(
                msg_id,
                format!("Invalid dst: {:?}", msg),
            ));

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

fn match_node_msg(msg: &Message, origin: SrcLocation) -> NodeDuty {
    match msg {
        // ------ wallet register ------
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(wallet)),
            ..
        } => NodeDuty::SetNodeWallet {
            wallet_id: *wallet,
            node_id: origin.name(),
        },
        // Churn synch
        Message::NodeCmd {
            cmd:
                NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards,
                    user_wallets,
                    metadata,
                }),
            ..
        } => NodeDuty::SynchState {
            node_rewards: node_rewards.to_owned(),
            user_wallets: user_wallets.to_owned(),
            metadata: metadata.to_owned(),
        },
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeRewardPayout(proposal)),
            ..
        } => NodeDuty::ReceiveRewardProposal(proposal.clone()),
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateRewardPayout(accumulation)),
            ..
        } => NodeDuty::ReceiveRewardAccumulation(accumulation.clone()),
        // ------ section funds -----
        Message::NodeQuery {
            query: NodeQuery::Rewards(NodeRewardQuery::GetNodeWalletKey(node_name)),
            id,
            ..
        } => NodeDuty::GetNodeWalletKey {
            node_name: *node_name,
            msg_id: *id,
            origin,
        },
        //
        // ------ transfers --------
        Message::NodeCmd {
            cmd: NodeCmd::Transfers(NodeTransferCmd::PropagateTransfer(proof)),
            id,
            ..
        } => NodeDuty::PropagateTransfer {
            proof: proof.to_owned(),
            msg_id: *id,
            origin,
        },
        // ------ metadata ------
        Message::NodeQuery {
            query: NodeQuery::Metadata { query, origin },
            id,
            ..
        } => NodeDuty::ProcessRead {
            query: query.clone(),
            id: *id,
            origin: *origin,
        },
        Message::NodeCmd {
            cmd: NodeCmd::Metadata { cmd, origin },
            id,
            ..
        } => NodeDuty::ProcessWrite {
            cmd: cmd.clone(),
            id: *id,
            origin: *origin,
        },
        //
        // ------ adult ------
        Message::NodeQuery {
            query: NodeQuery::Chunks { query, origin },
            id,
            ..
        } => NodeDuty::ReadChunk {
            read: query.clone(),
            msg_id: *id,
            origin: *origin,
        },
        Message::NodeCmd {
            cmd: NodeCmd::Chunks { cmd, origin },
            id,
            ..
        } => NodeDuty::WriteChunk {
            write: cmd.clone(),
            msg_id: *id,
            origin: *origin,
        },
        //
        // ------ chunk replication ------
        Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetChunk(address)),
            id,
            ..
        } => NodeDuty::ReturnChunkToElders {
            address: *address,
            section: origin.name(),
            id: *id,
        },
        // this cmd is accumulated, thus has authority
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk(data)),
            ..
        } => NodeDuty::ReplicateChunk(data.clone()),
        // Aggregated by us, for security
        Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id,
            ..
        } => NodeDuty::GetSectionElders {
            msg_id: *id,
            origin,
        },
        //
        // ------ system cmd ------
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::StorageFull { node_id, .. }),
            ..
        } => NodeDuty::IncrementFullNodeCount { node_id: *node_id },
        // ------ chunk replication ------
        // query response from adult cannot be accumulated
        Message::NodeQueryResponse {
            response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(result)),
            ..
        } => {
            if let Ok(data) = result {
                NodeDuty::FinishReplication(data.clone())
            } else {
                log::warn!("Got error when reading chunk for replication: {:?}", result);
                NodeDuty::NoOp
            }
        }
        //
        // ------ transfers ------
        Message::NodeQuery {
            query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents),
            id,
            ..
        } => NodeDuty::GetTransferReplicaEvents {
            msg_id: *id,
            origin,
        },
        // --- Adult Operation response ---
        Message::NodeEvent {
            event: NodeEvent::ChunkWriteHandled(result),
            correlation_id,
            ..
        } => NodeDuty::RecordAdultWriteLiveness {
            result: result.clone(),
            correlation_id: *correlation_id,
            src: origin.name(),
        },
        Message::QueryResponse {
            response,
            correlation_id,
            ..
        } if matches!(response, QueryResponse::GetBlob(_)) => NodeDuty::RecordAdultReadLiveness {
            response: response.clone(),
            correlation_id: *correlation_id,
            src: origin.name(),
        },
        _ => NodeDuty::NoOp,
    }
}
