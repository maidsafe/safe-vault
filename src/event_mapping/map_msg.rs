// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{LazyError, Mapping, MsgContext};
use crate::{node_ops::NodeDuty, Error};
use sn_messaging::{
    client::{
        BlobWrite, Cmd, Message, NodeCmd, NodeDataQueryResponse, NodeEvent, NodeQuery,
        NodeQueryResponse, NodeRewardQuery, NodeSystemCmd, NodeSystemQuery, NodeTransferCmd,
        NodeTransferQuery, Query, QueryResponse, TransferCmd, TransferQuery,
    },
    DstLocation, EndUser, SrcLocation,
};

pub fn match_user_sent_msg(msg: Message, origin: EndUser) -> Mapping {
    match msg.to_owned() {
        Message::Query {
            query: Query::Data(query),
            id,
            ..
        } => Mapping::Ok {
            op: NodeDuty::ProcessRead { query, id, origin },
            ctx: Some(super::MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            }),
        },
        Message::Cmd {
            cmd: Cmd::Data { .. },
            ..
        } => Mapping::Ok {
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
        } => Mapping::Ok {
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
        } => Mapping::Ok {
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
        } => Mapping::Ok {
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
        } => Mapping::Ok {
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
        } => Mapping::Ok {
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
        } => Mapping::Ok {
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
        _ => Mapping::Error(LazyError {
            error: Error::InvalidMessage(msg.id(), format!("Unknown user msg: {:?}", msg)),
            msg: MsgContext::Msg {
                msg,
                src: SrcLocation::EndUser(origin),
            },
        }),
    }
}

pub fn map_node_msg(msg: Message, src: SrcLocation, dst: DstLocation) -> Mapping {
    //debug!(">>>>>>>>>>>> Evaluating received msg. {:?}.", msg);
    match &dst {
        DstLocation::Section(_name) | DstLocation::Node(_name) => match_or_err(msg, src),
        _ => Mapping::Error(LazyError {
            error: Error::InvalidMessage(msg.id(), format!("Invalid dst: {:?}", msg)),
            msg: MsgContext::Msg { msg, src },
        }),
    }
}

fn match_or_err(msg: Message, src: SrcLocation) -> Mapping {
    match match_node_msg(msg.clone(), src) {
        NodeDuty::NoOp => Mapping::Error(LazyError {
            error: Error::InvalidMessage(msg.id(), format!("Unknown msg: {:?}", msg)),
            msg: MsgContext::Msg { msg, src },
        }),
        op => Mapping::Ok {
            op,
            ctx: Some(MsgContext::Msg { msg, src }),
        },
    }
}

fn match_node_msg(msg: Message, origin: SrcLocation) -> NodeDuty {
    match &msg {
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
        Message::NodeCmd {
            cmd: NodeCmd::Republish { chunk },
            id,
        } => NodeDuty::ReplicateChunk(chunk.clone()),
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
