// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::thread::current;

use super::{LazyError, Mapping, MsgContext};
use crate::{
    node_ops::{NodeDuties, NodeDuty},
    Error, Result,
};
use log::debug;
use sn_messaging::{
    client::{
        Cmd, Message, NodeCmd, NodeDataQueryResponse, NodeEvent, NodeQuery, NodeQueryResponse,
        NodeRewardQuery, NodeRewardQueryResponse, NodeSystemCmd, NodeSystemQuery,
        NodeSystemQueryResponse, NodeTransferCmd, NodeTransferQuery, NodeTransferQueryResponse,
        Query,
    },
    DstLocation, EndUser, SrcLocation,
};

pub fn match_user_sent_msg(msg: Message, dst: DstLocation, origin: EndUser) -> Mapping {
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
            id,
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
        // Message::Cmd {
        //     cmd: Cmd::Transfer(cmd),
        //     id,
        //     ..
        // } => NetworkDuties::from(TransferDuty::ProcessCmd {
        //     cmd: cmd.into(),
        //     msg_id: id,
        //     origin: SrcLocation::EndUser(origin),
        // }),
        // Message::Query {
        //     query: Query::Transfer(query),
        //     id,
        //     ..
        // } => NetworkDuties::from(TransferDuty::ProcessQuery {
        //     query: query.into(),
        //     msg_id: id,
        //     origin: SrcLocation::EndUser(origin),
        // }),
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
    debug!(">>>>>>>>>>>> Evaluating received msg. {:?}.", msg);

    match &dst {
        DstLocation::Section(_name) => match match_section_msg(msg.clone(), src) {
            NodeDuty::NoOp => Mapping::Error(LazyError {
                error: Error::InvalidMessage(msg.id(), format!("Unknown msg: {:?}", msg)),
                msg: MsgContext::Msg { msg, src },
            }),
            op => Mapping::Ok {
                op,
                ctx: Some(MsgContext::Msg { msg, src }),
            },
        },
        DstLocation::Node(_name) => match match_node_msg(msg.clone(), src) {
            NodeDuty::NoOp => Mapping::Error(LazyError {
                error: Error::InvalidMessage(msg.id(), format!("Unknown msg: {:?}", msg)),
                msg: MsgContext::Msg { msg, src },
            }),
            op => Mapping::Ok {
                op,
                ctx: Some(MsgContext::Msg { msg, src }),
            },
        },
        _ => Mapping::Error(LazyError {
            error: Error::InvalidMessage(msg.id(), format!("Invalid dst: {:?}", msg)),
            msg: MsgContext::Msg { msg, src },
        }),
    }
}

fn match_section_msg(msg: Message, origin: SrcLocation) -> NodeDuty {
    debug!("Evaluating section message: {:?}", msg);

    match &msg {
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis { credit, sig }),
            ..
        } => NodeDuty::ReceiveGenesisProposal {
            credit: credit.clone(),
            sig: sig.clone(),
        },
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis { signed_credit, sig }),
            ..
        } => NodeDuty::ReceiveGenesisAccumulation {
            signed_credit: signed_credit.clone(),
            sig: sig.clone(),
        },

        // ------ section funds -----
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeNewWallet { credit, sig }),
            ..
        } => NodeDuty::ReceiveWalletProposal {
            credit: credit.clone(),
            sig: sig.clone(),
        },
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateNewWallet { signed_credit, sig }),
            ..
        } => NodeDuty::ReceiveWalletAccumulation {
            signed_credit: signed_credit.clone(),
            sig: sig.clone(),
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
            query:
                NodeQuery::System(NodeSystemQuery::GetChunk {
                    new_holder,
                    address,
                    current_holders,
                }),
            id,
            ..
        } => NodeDuty::GetChunkForReplication {
            address: *address,
            new_holder: *new_holder,
            id: *id,
        },
        // this cmd is accumulated, thus has authority
        Message::NodeCmd {
            cmd:
                NodeCmd::System(NodeSystemCmd::ReplicateChunk {
                    address,
                    current_holders,
                    ..
                }),
            id,
            ..
        } => NodeDuty::ReplicateChunk {
            address: *address,
            current_holders: current_holders.clone(),
            id: *id,
        },
        //
        // ------ Rewards ------
        Message::NodeQuery {
            query:
                NodeQuery::Rewards(NodeRewardQuery::GetNodeWalletId {
                    old_node_id,
                    new_node_id,
                }),
            id,
            ..
        } => NodeDuty::GetNodeWalletKey {
            old_node_id: *old_node_id,
            new_node_id: *new_node_id,
            msg_id: *id,
            origin,
        },
        // trivial to accumulate
        Message::NodeQueryResponse {
            response:
                NodeQueryResponse::Rewards(NodeRewardQueryResponse::GetNodeWalletId(Ok((
                    wallet_id,
                    new_node_id,
                )))),
            id,
            ..
        } => NodeDuty::PayoutNodeRewards {
            id: *wallet_id,
            node_id: *new_node_id,
            msg_id: *id,
            origin,
        },
        //
        // ------ transfers --------
        // doesn't need to be accumulated, but makes it a bit slimmer..
        Message::NodeCmd {
            cmd: NodeCmd::Transfers(NodeTransferCmd::PropagateTransfer(proof)),
            id,
            ..
        } => NodeDuty::PropagateTransfer {
            proof: proof.credit_proof(),
            msg_id: *id,
            origin,
        },
        /// TODO: fix the result in the payload..
        // // tricky to accumulate, since it has a vec of events.. but we try anyway for now..
        // Message::NodeQueryResponse {
        //     response:
        //         NodeQueryResponse::Transfers(NodeTransferQueryResponse::GetReplicaEvents(events)),
        //     id,
        //     ..
        // } => NodeDuty::InitiateReplica {
        //     events: events.clone()?,
        //     msg_id: *id,
        //     origin,
        // }
        // doesn't need to be accumulated, but makes it a bit slimmer..
        Message::NodeCmd {
            cmd: NodeCmd::Transfers(NodeTransferCmd::RegisterSectionPayout(debit_agreement)),
            id,
            ..
        } => NodeDuty::RegisterSectionPayout {
            debit_agreement: debit_agreement.clone(),
            msg_id: *id,
            origin,
        },
        // Aggregated by us, for security
        Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id,
            ..
        } => NodeDuty::GetSectionElders {
            msg_id: *id,
            origin,
        },
        // Message::NodeEvent {
        //     event: NodeEvent::SectionPayoutRegistered { from, to },
        //     ..
        // } => NodeDuty::CompleteElderChange {
        //     previous_key: *from,
        //     new_key: *to,
        // }
        // .into(),
        Message::NodeCmd {
            cmd:
                NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards,
                    user_wallets,
                }),
            ..
        } => NodeDuty::ContinueLevelUp {
            node_rewards: node_rewards.to_owned(),
            user_wallets: user_wallets.to_owned(),
        },
        Message::NodeEvent {
            event: NodeEvent::SectionWalletCreated(wallet),
            ..
        } => NodeDuty::CompleteLevelUp(wallet.to_owned()),
        _ => NodeDuty::NoOp,
    }
}

fn match_node_msg(msg: Message, origin: SrcLocation) -> NodeDuty {
    debug!("Evaluating node msg: {:?}", msg);

    match &msg {
        // ------ wallet register ------
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(wallet)),
            id,
            ..
        } => NodeDuty::SetNodeWallet {
            wallet_id: *wallet,
            node_id: origin.to_dst().name().unwrap(),
            msg_id: *id,
            origin,
        },
        //
        // ------ system cmd ------
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::StorageFull { node_id, .. }),
            ..
        } => NodeDuty::IncrementFullNodeCount { node_id: *node_id },
        //
        // ------ node duties ------
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis { credit, sig }),
            ..
        } => NodeDuty::ReceiveGenesisProposal {
            credit: credit.clone(),
            sig: sig.clone(),
        },
        Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis { signed_credit, sig }),
            ..
        } => NodeDuty::ReceiveGenesisAccumulation {
            signed_credit: signed_credit.clone(),
            sig: sig.clone(),
        },
        //
        // ------ chunk replication ------
        // query response from adult cannot be accumulated
        Message::NodeQueryResponse {
            response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(result)),
            correlation_id,
            ..
        } => {
            log::info!("Verifying GetChunk NodeQueryResponse!");
            if let Ok(data) = result {
                NodeDuty::StoreChunkForReplication {
                    data: data.clone(),
                    correlation_id: *correlation_id,
                }
            } else {
                log::warn!("Got error when reading chunk for replication: {:?}", result);
                NodeDuty::NoOp
            }
        }
        //
        // ------ nonacc rewards ------
        // validated event cannot be accumulated at routing, since it has sig shares
        Message::NodeEvent {
            event: NodeEvent::RewardPayoutValidated(validation),
            id,
            ..
        } => NodeDuty::ReceivePayoutValidation {
            validation: validation.clone(),
            msg_id: *id,
            origin,
        },
        //
        // ------ nonacc transfers ------
        // queries are from single source, so cannot be accumulated
        Message::NodeQuery {
            query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents),
            id,
            ..
        } => NodeDuty::GetTransferReplicaEvents {
            msg_id: *id,
            origin,
        },
        // cannot be accumulated due to having sig share
        Message::NodeCmd {
            cmd: NodeCmd::Transfers(NodeTransferCmd::ValidateSectionPayout(signed_transfer)),
            id,
            ..
        } => {
            debug!(">>>> validating section payout to {:?}", signed_transfer);
            NodeDuty::ValidateSectionPayout {
                signed_transfer: signed_transfer.clone(),
                msg_id: *id,
                origin,
            }
        }
        // // from a single src, so cannot be accumulated
        // Message::NodeQuery {
        //     query: NodeQuery::Rewards(NodeRewardQuery::GetSectionWalletHistory),
        //     id,
        //     ..
        // } => RewardDuty::ProcessQuery {
        //     query: RewardQuery::GetSectionWalletHistory,
        //     msg_id: *id,
        //     origin,
        // }
        // .into(),
        // --- Adult ---
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
        // tricky to accumulate, since it has a vec of events.. but we try anyway for now..
        Message::NodeQueryResponse {
            response: NodeQueryResponse::System(NodeSystemQueryResponse::GetSectionElders(replicas)),
            id,
            ..
        } => {
            debug!(">>>>> Should be handling ContinueWalletChurn, after GetSectionElders query response");
            NodeDuty::ContinueWalletChurn {
                replicas: replicas.to_owned(),
                msg_id: *id,
                origin,
            }
        }
        _ => NodeDuty::NoOp,
    }
}
