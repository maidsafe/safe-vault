// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{LazyError, Mapping, MsgContext};
use crate::{
    node_ops::{NodeDuties, NodeDuty},
    Error, Result,
};
use log::debug;
use sn_messaging::{
    client::{
        Cmd, Message, NodeCmd, NodeEvent, NodeQuery, NodeQueryResponse, NodeRewardQuery,
        NodeRewardQueryResponse, NodeSystemCmd, NodeSystemQuery, NodeSystemQueryResponse,
        NodeTransferCmd, NodeTransferQuery, NodeTransferQueryResponse, Query,
    },
    DstLocation, EndUser, SrcLocation,
};

pub fn match_user_sent_msg(msg: Message, dst: DstLocation, origin: EndUser) -> Mapping {
    let msg_id = msg.id();

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
            op: NodeDuty::ProcessPaymentForDataCmd {
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
        _ => {
            let info = format!("Unknown user msg: {:?}", msg);
            Mapping::Error(LazyError {
                msg: MsgContext::Msg {
                    msg,
                    src: SrcLocation::EndUser(origin),
                },
                error: Error::InvalidMessage(msg_id, info),
            })
        }
    }
}

pub fn map_node_msg(msg: Message, src: SrcLocation, dst: DstLocation) -> Mapping {
    debug!(">>>>>>>>>>>> Evaluating received msg. {:?}.", msg);
    let msg_id = msg.id();

    match &dst {
        DstLocation::Section(_name) => match match_section_msg(msg.clone(), src) {
            NodeDuty::NoOp => Mapping::Error(LazyError {
                error: Error::InvalidMessage(msg_id, format!("Unknown msg: {:?}", msg)),
                msg: MsgContext::Msg { msg, src },
            }),
            op => Mapping::Ok {
                op,
                ctx: Some(MsgContext::Msg { msg, src }),
            },
        },
        DstLocation::Node(_name) => match match_node_msg(msg.clone(), src) {
            NodeDuty::NoOp => Mapping::Error(LazyError {
                error: Error::InvalidMessage(msg_id, format!("Unknown msg: {:?}", msg)),
                msg: MsgContext::Msg { msg, src },
            }),
            op => Mapping::Ok {
                op,
                ctx: Some(MsgContext::Msg { msg, src }),
            },
        },
        _ => {
            let info = format!("Invalid dst: {:?}", msg);
            Mapping::Error(LazyError {
                msg: MsgContext::Msg { msg, src },
                error: Error::InvalidMessage(msg_id, info),
            })
        }
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

        // ------ metadata ------
        // Message::NodeQuery {
        //     query: NodeQuery::Metadata { query, origin },
        //     id,
        //     ..
        // } => MetadataDuty::ProcessRead {
        //     query: query.clone(),
        //     id: *id,
        //     origin: *origin,
        // }
        // .into(),
        // Message::NodeCmd {
        //     cmd: NodeCmd::Metadata { cmd, origin },
        //     id,
        //     ..
        // } => MetadataDuty::ProcessWrite {
        //     cmd: cmd.clone(),
        //     id: *id,
        //     origin: *origin,
        // }
        // .into(),
        // //
        // // ------ adult ------
        // Message::NodeQuery {
        //     query: NodeQuery::Chunks { query, origin },
        //     id,
        //     ..
        // } => AdultDuty::RunAsChunkStore(ChunkStoreDuty::ReadChunk {
        //     read: query.clone(),
        //     id: *id,
        //     origin: *origin,
        // })
        // .into(),
        // Message::NodeCmd {
        //     cmd: NodeCmd::Chunks { cmd, origin },
        //     id,
        //     ..
        // } => AdultDuty::RunAsChunkStore(ChunkStoreDuty::WriteChunk {
        //     write: cmd.clone(),
        //     id: *id,
        //     origin: *origin,
        // })
        // .into(),
        // //
        // // ------ chunk replication ------
        // Message::NodeQuery {
        //     query:
        //         NodeQuery::System(NodeSystemQuery::GetChunk {
        //             //section_authority,
        //             new_holder,
        //             address,
        //             current_holders,
        //         }),
        //     ..
        // } => {
        //     info!("Verifying GetChunk query!");
        //     let _proof_chain = self.adult_state()?.section_chain();

        //     // Recreate original MessageId from Section
        //     let msg_id = MessageId::combine(vec![*address.name(), *new_holder]);

        //     // Recreate cmd that was sent by the section.
        //     let _message = Message::NodeCmd {
        //         cmd: NodeCmd::System(NodeSystemCmd::ReplicateChunk {
        //             new_holder: *new_holder,
        //             address: *address,
        //             current_holders: current_holders.clone(),
        //         }),
        //         id: msg_id,
        //         target_section_pk: None,
        //     };

        //     info!("Internal ChunkReplicationQuery ProcessQuery");
        //     AdultDuty::RunAsChunkReplication(ChunkReplicationDuty::ProcessQuery {
        //         query: ChunkReplicationQuery::GetChunk(*address),
        //         msg_id,
        //         origin,
        //     })
        //     .into()
        // }
        // // this cmd is accumulated, thus has authority
        // Message::NodeCmd {
        //     cmd:
        //         NodeCmd::System(NodeSystemCmd::ReplicateChunk {
        //             address,
        //             current_holders,
        //             ..
        //         }),
        //     id,
        //     ..
        // } => AdultDuty::RunAsChunkReplication(ChunkReplicationDuty::ProcessCmd {
        //     cmd: ChunkReplicationCmd::ReplicateChunk {
        //         current_holders: current_holders.clone(),
        //         address: *address,
        //     },
        //     msg_id: *id,
        //     origin,
        // })
        // .into(),
        // //
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
        } => NodeDuty::ActivateNodeRewards {
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
        Message::NodeEvent {
            event:
                NodeEvent::PromotedToElder {
                    section_wallet,
                    node_rewards,
                    user_wallets,
                },
            ..
        } => NodeDuty::CompleteTransitionToElder {
            section_wallet: section_wallet.to_owned(),
            node_rewards: node_rewards.to_owned(),
            user_wallets: user_wallets.to_owned(),
        },
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
        // //
        // // ------ chunk replication ------
        // // query response from adult cannot be accumulated
        // Message::NodeQueryResponse {
        //     response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(result)),
        //     correlation_id,
        //     ..
        // } => {
        //     let blob = result.to_owned()?;
        //     info!("Verifying GetChunk NodeQueryResponse!");
        //     // Recreate original MessageId from Section
        //     let msg_id =
        //         MessageId::combine(vec![*blob.address().name(), self.state.node_name()]);
        //     if msg_id == *correlation_id {
        //         AdultDuty::RunAsChunkReplication(ChunkReplicationDuty::ProcessCmd {
        //             cmd: ChunkReplicationCmd::StoreReplicatedBlob(blob),
        //             msg_id,
        //             origin,
        //         })
        //         .into()
        //     } else {
        //         info!("Given blob is incorrect.");
        //         panic!()
        //     }
        // }
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
            debug!(">>>>> Should be handling CompleteWalletTransition, after GetSectionElders query response");
            NodeDuty::CompleteWalletTransition {
                replicas: replicas.to_owned(),
                msg_id: *id,
                origin,
            }
        }
        _ => NodeDuty::NoOp,
    }
}
