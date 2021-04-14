// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::messaging::{send, send_to_nodes};
use crate::{
    chunks::Chunks,
    metadata::Metadata,
    network::Network,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{
        reward_process::RewardProcess,
        reward_stage::{CreditAccumulation, RewardStage},
        reward_wallets::RewardWallets,
        Credits, SectionFunds,
    },
    state::{AdultStateCommand, ElderStateCommand, State},
    transfers::Transfers,
    Error, Node, Result,
};
use dashmap::DashMap;
use log::{debug, info};
use sn_data_types::{
    CreditAgreementProof, CreditId, NodeAge, PublicKey, SectionElders, WalletHistory,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, Query},
    Aggregation, DstLocation, MessageId,
};
use std::collections::{BTreeMap, VecDeque};
use xor_name::XorName;

pub(crate) struct DutyHandler {
    pub network_api: Network,
    pub state: State,
}

impl DutyHandler {
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        info!("Handling NodeDuty: {:?}", duty);
        match duty {
            NodeDuty::Genesis => {
                self.level_up().await?;
                Ok(vec![])
            }
            NodeDuty::EldersChanged {
                our_key,
                our_prefix,
                newbie,
            } => {
                if newbie {
                    info!("Promoted to Elder on Churn");
                    self.level_up().await?;
                    Ok(vec![])
                } else {
                    info!("Updating our replicas on Churn");
                    self.update_replicas().await?;
                    let msg_id =
                        MessageId::combine(vec![our_prefix.name(), XorName::from(our_key)]);

                    Ok(vec![self.push_state(our_prefix, msg_id).await])
                }
            }
            NodeDuty::SectionSplit {
                our_key,
                our_prefix,
                sibling_key,
                newbie,
            } => {
                if newbie {
                    info!("Beginning split as Newbie");
                    self.begin_split_as_newbie(our_key, our_prefix).await?;
                    Ok(vec![])
                } else {
                    info!("Beginning split as Oldie");
                    self.begin_split_as_oldie(our_prefix, our_key, sibling_key)
                        .await
                }
            }
            // a remote section asks for the replicas of their wallet
            NodeDuty::GetSectionElders { msg_id, origin } => {
                Ok(vec![self.get_section_elders(msg_id, origin).await?])
            }
            NodeDuty::ReceiveRewardProposal(proposal) => {
                // if it fails it means we are an adult, so ignore this msg
                self.state
                    .elder_command(ElderStateCommand::ReceiveChurnProposal(proposal))
                    .await
                    .or_else(|_| Ok(vec![]))
            }
            NodeDuty::ReceiveRewardAccumulation(accumulation) => {
                let section_key = self.network_api.section_public_key().await?;
                if let Ok(ops) = self
                    .state
                    .elder_command(ElderStateCommand::ReceiveWalletAccumulation {
                        accumulation,
                        section_key,
                    })
                    .await
                {
                    Ok(ops)
                } else {
                    // we are an adult, so ignore this error
                    Ok(vec![])
                }
            }
            //
            // ------- reward reg -------
            NodeDuty::SetNodeWallet {
                wallet_id,
                node_id,
                msg_id,
                origin,
            } => {
                let members = self.network_api.our_members().await;
                if let Some(age) = members.get(&node_id) {
                    let mut node_wallets = BTreeMap::<XorName, (NodeAge, PublicKey)>::new();
                    let _ = node_wallets.insert(node_id, (*age, wallet_id));

                    self.state
                        .elder_command(ElderStateCommand::SetNodeRewardsWallets(node_wallets))
                        .await
                } else {
                    debug!(
                        "{:?}: Couldn't find node id {} when adding wallet {}",
                        self.network_api.our_prefix().await,
                        node_id,
                        wallet_id
                    );
                    Err(Error::NodeNotFoundForReward)
                }
            }
            NodeDuty::GetNodeWalletKey {
                node_name,
                msg_id,
                origin,
            } => Ok(vec![]),
            NodeDuty::ProcessLostMember { name, .. } => {
                info!("Member Lost: {:?}", name);
                let mut ops = vec![];

                info!("Setting JoinsAllowed to `True` for replacing the member left");
                ops.push(NodeDuty::SetNodeJoinsAllowed(true));

                let _ = self
                    .state
                    .elder_command(ElderStateCommand::RemoveNodeWallet(name))
                    .await?;

                let _ = self
                    .state
                    .elder_command(ElderStateCommand::DecreaseFullNodeCount(name))
                    .await?;

                let additional_ops = self
                    .state
                    .elder_command(ElderStateCommand::TriggerChunkReplication(name))
                    .await?;

                ops.extend(additional_ops);

                Ok(ops)
            }
            //
            // ---------- Levelling --------------
            NodeDuty::SynchState {
                node_rewards,
                user_wallets,
            } => Ok(vec![self.synch_state(node_rewards, user_wallets).await?]),
            NodeDuty::LevelDown => {
                info!("Getting Demoted");
                self.state.demote_to_adult_role().await?;

                Ok(vec![])
            }
            //
            // ----------- Transfers -----------
            NodeDuty::GetTransferReplicaEvents { msg_id, origin } => {
                self.state
                    .elder_command(ElderStateCommand::GetTransferReplicaEvents { msg_id, origin })
                    .await
            }
            NodeDuty::PropagateTransfer {
                proof,
                msg_id,
                origin,
            } => {
                self.state
                    .elder_command(ElderStateCommand::ReceivePropagated {
                        proof,
                        msg_id,
                        origin,
                    })
                    .await
            }
            NodeDuty::ValidateClientTransfer {
                signed_transfer,
                msg_id,
                origin,
            } => {
                self.state
                    .elder_command(ElderStateCommand::ValidateTransfer {
                        signed_transfer,
                        msg_id,
                        origin,
                    })
                    .await
            }
            NodeDuty::SimulatePayout {
                transfer,
                msg_id,
                origin,
            } => {
                self.state
                    .elder_command(ElderStateCommand::CreditWithoutProof(transfer))
                    .await
            }
            NodeDuty::GetTransfersHistory {
                at,
                since_version,
                msg_id,
                origin,
            } => {
                debug!(">>>> TODO: GET TRANSFER HISTORY, ADD limit with since_version....");
                self.state
                    .elder_command(ElderStateCommand::GetTransfersHistory { at, msg_id, origin })
                    .await
            }
            NodeDuty::GetBalance { at, msg_id, origin } => {
                self.state
                    .elder_command(ElderStateCommand::GetTransfersBalance { at, msg_id, origin })
                    .await
            }
            NodeDuty::GetStoreCost {
                requester,
                bytes,
                msg_id,
                origin,
            } => {
                self.state
                    .elder_command(ElderStateCommand::GetStoreCost {
                        bytes,
                        msg_id,
                        origin,
                    })
                    .await
            }
            NodeDuty::RegisterTransfer { proof, msg_id } => {
                self.state
                    .elder_command(ElderStateCommand::RegisterTransfer { proof, msg_id })
                    .await
            }
            //
            // -------- Immutable chunks --------
            NodeDuty::ReadChunk {
                read,
                msg_id,
                origin,
            } => {
                // TODO: remove this conditional branching
                // routing should take care of this
                let data_section_addr = read.dst_address();
                if self
                    .network_api
                    .our_prefix()
                    .await
                    .matches(&&data_section_addr)
                {
                    let mut ops = self
                        .state
                        .adult_command(AdultStateCommand::ReadChunk {
                            read,
                            msg_id,
                            origin,
                        })
                        .await?;

                    ops.extend(
                        self.state
                            .adult_command(AdultStateCommand::CheckStorage)
                            .await?,
                    );

                    Ok(ops)
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: Message::NodeQuery {
                            query: NodeQuery::Chunks {
                                query: read,
                                origin,
                            },
                            id: msg_id,
                            target_section_pk: None,
                        },
                        dst: DstLocation::Section(data_section_addr),
                        // TBD
                        section_source: false,
                        aggregation: Aggregation::None,
                    })])
                }
            }
            NodeDuty::WriteChunk {
                write,
                msg_id,
                origin,
            } => {
                self.state
                    .adult_command(AdultStateCommand::WriteChunk {
                        write,
                        msg_id,
                        origin,
                    })
                    .await
            }
            NodeDuty::ReachingMaxCapacity => Ok(vec![self.notify_section_of_our_storage().await?]),
            //
            // ------- Misc ------------
            NodeDuty::IncrementFullNodeCount { node_id } => {
                let _ = self
                    .state
                    .elder_command(ElderStateCommand::IncreaseFullNodeCount(node_id))
                    .await?;
                // Accept a new node in place for the full node.
                Ok(vec![NodeDuty::SetNodeJoinsAllowed(true)])
            }
            NodeDuty::Send(msg) => {
                send(msg, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SendToNodes {
                msg,
                targets,
                aggregation,
            } => {
                send_to_nodes(&msg, targets, aggregation, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SetNodeJoinsAllowed(joins_allowed) => {
                self.network_api.set_joins_allowed(joins_allowed).await?;
                Ok(vec![])
            }
            //
            // ------- Data ------------
            NodeDuty::ProcessRead { query, id, origin } => {
                // TODO: remove this conditional branching
                // routing should take care of this
                let data_section_addr = query.dst_address();
                if self
                    .network_api
                    .our_prefix()
                    .await
                    .matches(&data_section_addr)
                {
                    self.state
                        .elder_command(ElderStateCommand::ReadDataCmd { query, id, origin })
                        .await
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: Message::NodeQuery {
                            query: NodeQuery::Metadata { query, origin },
                            id,
                            target_section_pk: None,
                        },
                        dst: DstLocation::Section(data_section_addr),
                        // TBD
                        section_source: false,
                        aggregation: Aggregation::None,
                    })])
                }
            }
            NodeDuty::ProcessWrite { cmd, id, origin } => {
                self.state
                    .elder_command(ElderStateCommand::WriteDataCmd { cmd, id, origin })
                    .await
            }
            NodeDuty::ProcessDataPayment { msg, origin } => {
                self.state
                    .elder_command(ElderStateCommand::ProcessPayment { msg, origin })
                    .await
            }
            NodeDuty::AddPayment(credit) => {
                self.state
                    .elder_command(ElderStateCommand::AddPayment(credit))
                    .await
            }
            NodeDuty::ReplicateChunk(data) => {
                self.state
                    .adult_command(AdultStateCommand::StoreChunkForReplication(data))
                    .await
            }
            NodeDuty::ReturnChunkToElders {
                address,
                id,
                section,
            } => {
                self.state
                    .adult_command(AdultStateCommand::GetChunkForReplication {
                        address,
                        id,
                        section,
                    })
                    .await
            }
            NodeDuty::FinishReplication(data) => {
                self.state
                    .elder_command(ElderStateCommand::FinishChunkReplication(data))
                    .await
            }
            NodeDuty::NoOp => Ok(vec![]),
        }
    }
}
