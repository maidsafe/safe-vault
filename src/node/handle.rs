// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    interaction::push_state,
    messaging::{send, send_error, send_support, send_to_nodes},
    role::{AdultRole, Role},
};
use crate::{
    chunks::Chunks,
    event_mapping::MsgContext,
    node_ops::{NodeDuties, NodeDuty},
    section_funds::{reward_stage::RewardStage, Credits, SectionFunds},
    Error, Node, Result,
};
use log::{debug, info};
use sn_messaging::{
    client::{Cmd, ProcessMsg},
    node::{NodeMsg, NodeQuery},
    Aggregation, MessageId,
};
use sn_routing::ELDER_SIZE;
use std::sync::Arc;
use tokio::{sync::RwLock, task::JoinHandle};
use xor_name::XorName;

const DATA_SECTION_TARGET_COUNT: usize = 3;

pub enum NodeTask {
    None,
    Result(Box<(NodeDuties, Option<MsgContext>)>),
    Thread(JoinHandle<Result<NodeTask>>),
}

impl From<NodeDuties> for NodeTask {
    fn from(duties: NodeDuties) -> Self {
        Self::Result(Box::new((duties, None)))
    }
}

impl Node {
    ///
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeTask> {
        if !matches!(duty, NodeDuty::NoOp) {
            debug!("Handling NodeDuty: {:?}", duty);
        }

        match duty {
            NodeDuty::Genesis => {
                self.level_up().await?;
                let elder = self.role.as_elder_mut()?;
                *elder.received_initial_sync.write().await = true;
                Ok(NodeTask::None)
            }
            NodeDuty::EldersChanged {
                our_key,
                our_prefix,
                new_elders,
                newbie,
            } => {
                if newbie {
                    info!("Promoted to Elder on Churn");
                    self.level_up().await?;
                    if self.network_api.our_prefix().await.is_empty()
                        && self.network_api.section_chain().await.len() <= ELDER_SIZE
                    {
                        let elder = self.role.as_elder_mut()?;
                        *elder.received_initial_sync.write().await = true;
                    }
                    Ok(NodeTask::None)
                } else {
                    info!("Updating our replicas on Churn");
                    let elder = self.role.as_elder_mut()?.clone();
                    let network = self.network_api.clone();
                    let handle = tokio::spawn(async move {
                        Self::update_replicas(&elder, &network).await?;
                        let msg_id =
                            MessageId::combine(&[our_prefix.name().0, XorName::from(our_key).0]);
                        let ops = vec![push_state(&elder, our_prefix, msg_id, new_elders).await?];
                        let our_adults = network.our_adults().await;
                        elder
                            .meta_data
                            .write()
                            .await
                            .retain_members_only(our_adults)
                            .await?;
                        Ok(NodeTask::from(ops))
                    });
                    Ok(NodeTask::Thread(handle))
                }
            }
            NodeDuty::AdultsChanged {
                added,
                removed,
                remaining,
            } => {
                let our_name = self.our_name().await;
                let mut adult_role = self.role.as_adult()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(
                        adult_role
                            .reorganize_chunks(our_name, added, removed, remaining)
                            .await,
                    ))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::SectionSplit {
                our_key,
                our_prefix,
                our_new_elders,
                their_new_elders,
                sibling_key,
                newbie,
            } => {
                if newbie {
                    info!("Beginning split as Newbie");
                    self.begin_split_as_newbie(our_key, our_prefix).await?;
                    Ok(NodeTask::None)
                } else {
                    info!("Beginning split as Oldie");
                    let elder = self.role.as_elder()?.clone();
                    let network = self.network_api.clone();
                    let handle = tokio::spawn(async move {
                        Ok(NodeTask::from(
                            Self::begin_split_as_oldie(
                                &elder,
                                &network,
                                our_prefix,
                                our_key,
                                sibling_key,
                                our_new_elders,
                                their_new_elders,
                            )
                            .await?,
                        ))
                    });
                    Ok(NodeTask::Thread(handle))
                }
            }
            NodeDuty::ProposeOffline(unresponsive_adults) => {
                for adult in unresponsive_adults {
                    self.network_api.propose_offline(adult).await?;
                }
                Ok(NodeTask::None)
            }
            // a remote section asks for the replicas of their wallet
            NodeDuty::GetSectionElders { msg_id, origin } => {
                let network = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(
                        Self::get_section_elders(&network, msg_id, origin).await?,
                    ))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ReceiveRewardProposal(proposal) => {
                info!("Handling Churn proposal as an Elder");
                let elder = self.role.as_elder_mut()?;
                let mut churn_process = elder
                    .section_funds
                    .write()
                    .await
                    .as_churning_mut()?
                    .0
                    .clone();
                let duties = vec![churn_process.receive_churn_proposal(proposal).await?];
                Ok(NodeTask::Result(Box::new((duties, None))))
            }
            NodeDuty::ReceiveRewardAccumulation(accumulation) => {
                let elder = self.role.as_elder_mut()?.clone();
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    let mut section_funds = elder.section_funds.write().await;
                    let (churn_process, reward_wallets) = section_funds.as_churning_mut()?;

                    let mut ops = vec![
                        churn_process
                            .clone()
                            .receive_wallet_accumulation(accumulation)
                            .await?,
                    ];

                    if let RewardStage::Completed(credit_proofs) = churn_process.stage().clone() {
                        let reward_sum = credit_proofs.sum();
                        ops.extend(Self::propagate_credits(credit_proofs)?);
                        // update state
                        *elder.section_funds.write().await =
                            SectionFunds::KeepingNodeWallets(reward_wallets.clone());
                        let section_key = network_api.section_public_key().await?;
                        info!(
                            "COMPLETED SPLIT. New section: ({}). Total rewards paid: {}.",
                            section_key, reward_sum
                        );
                        ops.push(NodeDuty::SetNodeJoinsAllowed(true));
                    }

                    Ok(NodeTask::from(ops))
                });
                Ok(NodeTask::Thread(handle))
            }
            //
            // ------- reward reg -------
            NodeDuty::SetNodeWallet { wallet_id, node_id } => {
                let elder = self.role.as_elder_mut()?.clone();
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    let members = network_api.our_members().await;
                    let result = if let Some(age) = members.get(&node_id) {
                        elder
                            .section_funds
                            .write()
                            .await
                            .set_node_wallet(node_id, wallet_id, *age);
                        Ok(vec![])
                    } else {
                        debug!(
                            "{:?}: Couldn't find node id {} when adding wallet {}",
                            network_api.our_prefix().await,
                            node_id,
                            wallet_id
                        );
                        Err(Error::NodeNotFoundForReward)
                    }?;
                    Ok(NodeTask::from(result))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::GetNodeWalletKey { node_name, .. } => {
                let elder = self.role.as_elder_mut()?.clone();
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    let members = network_api.our_members().await;
                    let result = if members.get(&node_name).is_some() {
                        let _wallet = elder.section_funds.read().await.get_node_wallet(&node_name);
                        Ok(vec![]) // not yet implemented
                    } else {
                        debug!(
                            "{:?}: Couldn't find node {} when getting wallet.",
                            network_api.our_prefix().await,
                            node_name,
                        );
                        Err(Error::NodeNotFoundForReward)
                    }?;
                    Ok(NodeTask::from(result))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ProcessLostMember { name, .. } => {
                info!("Member Lost: {:?}", name);
                let elder = self.role.as_elder_mut()?.clone();
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    elder.section_funds.read().await.remove_node_wallet(name);
                    let our_adults = network_api.our_adults().await;
                    elder
                        .meta_data
                        .write()
                        .await
                        .retain_members_only(our_adults)
                        .await?;
                    Ok(NodeTask::from(vec![NodeDuty::SetNodeJoinsAllowed(true)]))
                });
                Ok(NodeTask::Thread(handle))
            }
            //
            // ---------- Levelling --------------
            NodeDuty::SynchState {
                node_rewards,
                user_wallets,
                metadata,
            } => {
                let elder = self.role.as_elder()?.clone();
                let network_api = self.network_api.clone();
                let reward_key = self.node_info.reward_key;
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        Self::synch_state(
                            &elder,
                            reward_key,
                            &network_api,
                            node_rewards,
                            user_wallets,
                            metadata,
                        )
                        .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::LevelDown => {
                info!("Getting Demoted");
                let capacity = self.used_space.max_capacity().await;
                self.role = Role::Adult(AdultRole {
                    chunks: Arc::new(RwLock::new(
                        Chunks::new(self.node_info.root_dir.as_path(), capacity).await?,
                    )),
                });
                Ok(NodeTask::None)
            }
            //
            // ----------- Transfers -----------
            NodeDuty::GetTransferReplicaEvents { msg_id, origin } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .read()
                            .await
                            .all_events(msg_id, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::PropagateTransfer {
                proof,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .read()
                            .await
                            .receive_propagated(&proof, msg_id, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ValidateClientTransfer {
                signed_transfer,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .read()
                            .await
                            .validate(signed_transfer, msg_id, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::SimulatePayout { transfer, .. } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .write()
                            .await
                            .credit_without_proof(transfer)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::GetTransfersHistory {
                at, msg_id, origin, ..
            } => {
                // TODO: add limit with since_version
                let elder = self.role.as_elder()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .read()
                            .await
                            .history(&at, msg_id, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::GetBalance { at, msg_id, origin } => {
                let elder = self.role.as_elder()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .read()
                            .await
                            .balance(at, msg_id, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::GetStoreCost {
                bytes,
                msg_id,
                origin,
                ..
            } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(
                        elder
                            .transfers
                            .write()
                            .await
                            .get_store_cost(bytes, msg_id, origin)
                            .await,
                    ))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::RegisterTransfer {
                proof,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .transfers
                            .read()
                            .await
                            .register(&proof, msg_id, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            //
            // -------- Immutable chunks --------
            NodeDuty::ReadChunk { read, msg_id } => {
                let adult = self.role.as_adult()?.clone();
                let handle = tokio::spawn(async move {
                    let mut ops = vec![adult.chunks.write().await.read(&read, msg_id)];
                    ops.extend(adult.chunks.read().await.check_storage().await?);
                    Ok(NodeTask::from(ops))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::WriteChunk {
                write,
                msg_id,
                client_signed,
            } => {
                let adult = self.role.as_adult()?.clone();
                let handle = tokio::spawn(async move {
                    let mut ops = vec![
                        adult
                            .chunks
                            .write()
                            .await
                            .write(&write, msg_id, client_signed.public_key)
                            .await?,
                    ];
                    ops.extend(adult.chunks.read().await.check_storage().await?);
                    Ok(NodeTask::from(ops))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ProcessRepublish { chunk, msg_id, .. } => {
                info!("Processing republish with MessageId: {:?}", msg_id);
                let elder = self.role.as_elder()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder.meta_data.write().await.republish_chunk(chunk).await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ReachingMaxCapacity => {
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        Self::notify_section_of_our_storage(&network_api).await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            //
            // ------- Misc ------------
            NodeDuty::IncrementFullNodeCount { node_id } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    let propose_offline = NodeDuty::ProposeOffline(vec![node_id.into()]);
                    elder
                        .meta_data
                        .write()
                        .await
                        .increase_full_node_count(node_id)
                        .await?;
                    // Accept a new node in place for the full node.
                    Ok(NodeTask::from(vec![
                        NodeDuty::SetNodeJoinsAllowed(true),
                        propose_offline,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::Send(msg) => {
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    send(msg, &network_api).await?;
                    Ok(NodeTask::None)
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::SendError(msg) => {
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    send_error(msg, &network_api).await?;
                    Ok(NodeTask::None)
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::SendSupport(msg) => {
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    send_support(msg, &network_api).await?;
                    Ok(NodeTask::None)
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::SendToNodes {
                msg,
                targets,
                aggregation,
            } => {
                let network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    send_to_nodes(&msg, targets, aggregation, &network_api).await?;
                    Ok(NodeTask::None)
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::SetNodeJoinsAllowed(joins_allowed) => {
                let mut network_api = self.network_api.clone();
                let handle = tokio::spawn(async move {
                    #[cfg(feature = "always-joinable")]
                    {
                        network_api.set_joins_allowed(true).await?;
                        return Ok(NodeTask::None)
                    }
                    network_api.set_joins_allowed(joins_allowed).await?;
                    Ok(NodeTask::None)
                });
                Ok(NodeTask::Thread(handle))
            }
            //
            // ------- Data ------------
            NodeDuty::ProcessRead {
                query,
                msg_id,
                client_signed,
                origin,
            } => {
                // TODO: remove this conditional branching
                // routing should take care of this
                let data_section_addr = query.dst_address();
                let network_api = self.network_api.clone();
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    let duties = if network_api.our_prefix().await.matches(&data_section_addr) {
                        vec![
                            elder
                                .meta_data
                                .write()
                                .await
                                .read(query, msg_id, client_signed.public_key, origin)
                                .await?,
                        ]
                    } else {
                        let targets = network_api
                            .get_closest_elders_to(&data_section_addr, DATA_SECTION_TARGET_COUNT)
                            .await?;
                        vec![NodeDuty::SendToNodes {
                            msg: NodeMsg::NodeQuery {
                                query: NodeQuery::Metadata {
                                    query,
                                    client_signed,
                                    origin,
                                },
                                id: msg_id,
                            },
                            targets,
                            aggregation: Aggregation::None,
                        }]
                    };
                    Ok(NodeTask::from(duties))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ProcessWrite {
                cmd,
                msg_id,
                origin,
                client_signed,
            } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        elder
                            .meta_data
                            .write()
                            .await
                            .write(cmd, msg_id, client_signed, origin)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            // --- Completion of Adult operations ---
            NodeDuty::RecordAdultReadLiveness {
                response,
                correlation_id,
                src,
            } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(
                        elder
                            .meta_data
                            .write()
                            .await
                            .record_adult_read_liveness(correlation_id, response, src)
                            .await?,
                    ))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ProcessDataPayment {
                msg:
                    ProcessMsg::Cmd {
                        id,
                        cmd: Cmd::Data { payment, cmd },
                        client_signed,
                    },
                origin,
                ..
            } => {
                let elder = self.role.as_elder_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(
                        elder
                            .transfers
                            .read()
                            .await
                            .process_payment(id, payment, cmd, client_signed, origin)
                            .await?,
                    ))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::ProcessDataPayment { .. } => Ok(NodeTask::None),
            NodeDuty::ReplicateChunk { data, .. } => {
                let adult = self.role.as_adult_mut()?.clone();
                let handle = tokio::spawn(async move {
                    Ok(NodeTask::from(vec![
                        adult
                            .chunks
                            .write()
                            .await
                            .store_for_replication(data)
                            .await?,
                    ]))
                });
                Ok(NodeTask::Thread(handle))
            }
            NodeDuty::NoOp => Ok(NodeTask::None),
        }
    }
}
