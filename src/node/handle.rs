// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::{BTreeMap, VecDeque};

use super::{
    genesis::begin_forming_genesis_section,
    genesis::receive_genesis_accumulation,
    genesis::receive_genesis_proposal,
    genesis_stage::GenesisStage,
    interaction::CompletedWalletChurn,
    messaging::{send, send_error, send_to_nodes},
};
use crate::{
    chunks::Chunks,
    metadata::Metadata,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{
        churn_payout_stage::ChurnPayoutStage, churn_process::ChurnProcess,
        reward_wallets::RewardWallets, section_wallet::SectionWallet, SectionFunds,
    },
    transfers::Transfers,
    Error, Node, Result,
};
use log::{debug, info};
use sn_data_types::{PublicKey, SectionElders, WalletHistory};
use sn_messaging::{
    client::{NodeCmd, NodeQuery, ProcessMsg, Query},
    Aggregation, DstLocation, MessageId,
};
use xor_name::XorName;

impl Node {
    ///
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        match duty {
            NodeDuty::ChurnMembers {
                our_key,
                our_prefix,
                sibling_key,
                newbie,
            } => {
                if newbie {
                    self.begin_churn_as_newbie(our_key, our_prefix, sibling_key)
                        .await
                } else {
                    self.begin_churn_as_oldie(our_prefix, our_key, sibling_key)
                        .await
                }
            }
            // a remote section asks for the replicas of their wallet
            NodeDuty::GetSectionElders { msg_id, origin } => {
                Ok(vec![self.get_section_elders(msg_id, origin).await?])
            }
            // we get to know who our new wallet replicas are, thus continue the churn
            NodeDuty::ContinueWalletChurn {
                replicas,
                msg_id,
                origin,
            } => {
                let members = super::level_up::section_elders(&self.network_api).await?;
                let (reward_wallets, churn_process, existing_replicas) =
                    self.get_churning_funds()?;

                if existing_replicas.is_none() {
                    match churn_process.stage().clone() {
                        ChurnPayoutStage::AwaitingThreshold
                        | ChurnPayoutStage::ProposingCredits(_)
                        | ChurnPayoutStage::AccumulatingCredits(_) => {
                            debug!("handling ContinueWalletChurn: Setting SectionFunds::Churning");
                            self.section_funds = Some(SectionFunds::Churning {
                                process: churn_process.clone(),
                                wallets: reward_wallets.clone(),
                                replicas: Some(replicas),
                            });
                        }
                        ChurnPayoutStage::Completed(credit_proofs) => {
                            let recipient = credit_proofs.section_wallet.recipient();
                            let ops = Self::propagate_credits(credit_proofs)?;
                            // update state
                            self.section_funds = Some(SectionFunds::KeepingNodeWallets {
                                section_wallet: SectionWallet::new(members, replicas),
                                wallets: reward_wallets.clone(),
                            });
                            info!("COMPLETED({}): We have our new section wallet! (Credit came before replicas.)", recipient);
                            return Ok(ops);
                        }
                        ChurnPayoutStage::None => return Err(Error::InvalidGenesisStage),
                    }
                }
                Ok(vec![])
            }
            NodeDuty::ReceiveChurnProposal(proposal) => {
                debug!("handle: ReceiveChurnProposal");
                if let Ok((_, churn_process, _)) = self.get_churning_funds() {
                    Ok(vec![churn_process.receive_churn_proposal(proposal).await?])
                } else {
                    // we are an adult, so ignore this msg
                    Ok(vec![])
                }
            }
            NodeDuty::ReceiveChurnAccumulation(accumulation) => {
                let members = super::level_up::section_elders(&self.network_api).await?;
                if let Ok((reward_wallets, churn_process, replicas)) = self.get_churning_funds() {
                    let mut ops = vec![];

                    ops.push(
                        churn_process
                            .receive_wallet_accumulation(accumulation)
                            .await?,
                    );

                    if let ChurnPayoutStage::Completed(credit_proofs) =
                        churn_process.stage().clone()
                    {
                        if let Some(replicas) = replicas.clone() {
                            let recipient = credit_proofs.section_wallet.recipient();
                            ops.extend(Self::propagate_credits(credit_proofs)?);
                            // update state
                            self.section_funds = Some(SectionFunds::KeepingNodeWallets {
                                section_wallet: SectionWallet::new(members, replicas),
                                wallets: reward_wallets.clone(),
                            });
                            info!("COMPLETED({}): We have our new section wallet! (Replicas came before credit.)", recipient);
                        }
                    }

                    Ok(ops)
                } else {
                    // else we are an adult, so ignore this msg
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
                let rewards = self.get_section_funds()?;
                if let Some(age) = members.get(&node_id) {
                    rewards.set_node_wallet(node_id, wallet_id, *age);
                    Ok(vec![])
                } else {
                    debug!("Couldn't find node id!");
                    Err(Error::NodeNotFoundForReward)
                }
            }
            NodeDuty::GetNodeWalletKey {
                node_name,
                msg_id,
                origin,
            } => {
                //let rewards = self.get_section_funds()?;
                Ok(vec![
                    // rewards
                    //     .get_node_wallet(node_name, msg_id, origin)
                    //     .await?,
                ])
            }
            NodeDuty::ProcessLostMember { name, age } => {
                let rewards = self.get_section_funds()?;
                rewards.remove_node_wallet(name)?;

                let metadata = self.get_metadata()?;
                Ok(metadata.trigger_chunk_replication(name).await?)
            }
            //
            // ----- Genesis ----------
            NodeDuty::BeginFormingGenesisSection => {
                self.genesis_stage = begin_forming_genesis_section(&self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::ReceiveGenesisProposal { credit, sig } => {
                self.genesis_stage = receive_genesis_proposal(
                    credit,
                    sig,
                    self.genesis_stage.clone(),
                    &self.network_api,
                )
                .await?;
                Ok(vec![])
            }
            NodeDuty::ReceiveGenesisAccumulation { signed_credit, sig } => {
                self.genesis_stage = receive_genesis_accumulation(
                    signed_credit,
                    sig,
                    self.genesis_stage.clone(),
                    &self.network_api,
                )
                .await?;
                let genesis_tx = match &self.genesis_stage {
                    GenesisStage::Completed(genesis_tx) => genesis_tx.clone(),
                    _ => return Ok(vec![]),
                };
                Ok(vec![self.genesis(genesis_tx).await?])
            }
            //
            // ---------- Levelling --------------
            NodeDuty::SynchState {
                node_rewards,
                user_wallets,
            } => Ok(vec![self.synch_state(node_rewards, user_wallets).await?]),
            NodeDuty::LevelDown => {
                self.meta_data = None;
                self.transfers = None;
                self.section_funds = None;
                self.chunks = Some(
                    Chunks::new(
                        self.node_info.node_name,
                        self.node_info.root_dir.as_path(),
                        self.used_space.clone(),
                    )
                    .await?,
                );
                Ok(vec![])
            }
            //
            // ----------- Transfers -----------
            NodeDuty::GetTransferReplicaEvents { msg_id, origin } => {
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.all_events(msg_id, origin).await?])
            }
            NodeDuty::PropagateTransfer {
                proof,
                msg_id,
                origin,
            } => {
                let transfers = self.get_transfers()?;
                Ok(vec![
                    transfers.receive_propagated(&proof, msg_id, origin).await?,
                ])
            }
            NodeDuty::ValidateClientTransfer {
                signed_transfer,
                msg_id,
                origin,
            } => {
                let transfers = self.get_transfers()?;
                Ok(vec![
                    transfers.validate(signed_transfer, msg_id, origin).await?,
                ])
            }
            NodeDuty::SimulatePayout {
                transfer,
                msg_id,
                origin,
            } => {
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.credit_without_proof(transfer).await?])
            }
            NodeDuty::GetTransfersHistory {
                at,
                since_version,
                msg_id,
                origin,
            } => {
                debug!(">>>> TODO: GET TRANSFER HISTORY, ADD limit with since_version....");
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.history(&at, msg_id, origin).await?])
            }
            NodeDuty::GetBalance { at, msg_id, origin } => {
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.balance(at, msg_id, origin).await?])
            }
            NodeDuty::GetStoreCost {
                requester,
                bytes,
                msg_id,
                origin,
            } => {
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.get_store_cost(bytes, msg_id, origin).await])
            }
            NodeDuty::RegisterTransfer { proof, msg_id } => {
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.register(&proof, msg_id).await?])
            }
            //
            // -------- Immutable chunks --------
            NodeDuty::ReadChunk {
                read,
                msg_id,
                origin,
            } => {
                let data_section_addr = read.dst_address();
                if self
                    .network_api
                    .our_prefix()
                    .await
                    .matches(&&data_section_addr)
                {
                    let chunks = self.get_chunks()?;
                    Ok(vec![chunks.read(&read, msg_id, origin).await?])
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: ProcessMsg::NodeQuery {
                            query: NodeQuery::Chunks {
                                query: read,
                                origin,
                            },
                            id: msg_id,
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
                let data_section_addr = write.dst_address();
                if self
                    .network_api
                    .our_prefix()
                    .await
                    .matches(&&data_section_addr)
                {
                    let chunks = self.get_chunks()?;
                    Ok(vec![chunks.write(&write, msg_id, origin).await?])
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: ProcessMsg::NodeCmd {
                            cmd: NodeCmd::Chunks { cmd: write, origin },
                            id: msg_id,
                        },
                        dst: DstLocation::Section(data_section_addr),
                        // TBD
                        section_source: false,
                        aggregation: Aggregation::None,
                    })])
                }
            }
            NodeDuty::ReachingMaxCapacity => Ok(vec![self.notify_section_of_our_storage().await?]),
            //
            // ------- Misc ------------
            NodeDuty::IncrementFullNodeCount { node_id } => {
                let transfers = self.get_transfers()?;
                transfers.increase_full_node_count(node_id).await?;
                Ok(vec![])
            }
            NodeDuty::Send(msg) => {
                send(msg, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SendError(msg) => {
                send_error(msg, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SwitchNodeJoin(_) => Ok(vec![]),
            //
            // ------- Data ------------
            NodeDuty::ProcessRead { query, id, origin } => {
                let data_section_addr = query.dst_address();
                if self
                    .network_api
                    .our_prefix()
                    .await
                    .matches(&data_section_addr)
                {
                    let meta_data = self.get_metadata()?;
                    Ok(vec![meta_data.read(query, id, origin).await?])
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: ProcessMsg::NodeQuery {
                            query: NodeQuery::Metadata { query, origin },
                            id,
                        },
                        dst: DstLocation::Section(data_section_addr),
                        // TBD
                        section_source: false,
                        aggregation: Aggregation::None,
                    })])
                }
            }
            NodeDuty::ProcessWrite { cmd, id, origin } => {
                let data_section_addr = cmd.dst_address();
                if self
                    .network_api
                    .our_prefix()
                    .await
                    .matches(&data_section_addr)
                {
                    let meta_data = self.get_metadata()?;
                    Ok(vec![meta_data.write(cmd, id, origin).await?])
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: ProcessMsg::NodeCmd {
                            cmd: NodeCmd::Metadata { cmd, origin },
                            id,
                        },
                        dst: DstLocation::Section(data_section_addr),
                        // TBD
                        section_source: false,
                        aggregation: Aggregation::None,
                    })])
                }
            }
            NodeDuty::ProcessDataPayment { msg, origin } => {
                let transfers = self.get_transfers()?;
                Ok(vec![transfers.process_payment(&msg, origin).await?])
            }
            NodeDuty::ReplicateChunk {
                current_holders,
                address,
                id,
            } => {
                let chunks = self.get_chunks()?;
                Ok(vec![
                    chunks.replicate_chunk(address, current_holders, id).await?,
                ])
            }
            NodeDuty::GetChunkForReplication {
                address,
                new_holder,
                id,
            } => {
                let chunks = self.get_chunks()?;
                Ok(vec![
                    chunks
                        .get_chunk_for_replication(address, id, new_holder)
                        .await?,
                ])
            }
            NodeDuty::StoreChunkForReplication {
                data,
                correlation_id,
            } => {
                // Recreate original MessageId from Section
                let msg_id = MessageId::combine(vec![
                    *data.address().name(),
                    self.network_api.our_name().await,
                ]);
                if msg_id == correlation_id {
                    let chunks = self.get_chunks()?;
                    Ok(vec![chunks.store_replicated_chunk(data).await?])
                } else {
                    log::warn!("Invalid message ID");
                    Ok(vec![])
                }
            }
            NodeDuty::NoOp => Ok(vec![]),
        }
    }

    fn get_chunks(&mut self) -> Result<&mut Chunks> {
        if let Some(chunks) = &mut self.chunks {
            Ok(chunks)
        } else {
            Err(Error::InvalidOperation(
                "No immutable chunks at this node".to_string(),
            ))
        }
    }

    fn get_metadata(&mut self) -> Result<&mut Metadata> {
        if let Some(meta_data) = &mut self.meta_data {
            Ok(meta_data)
        } else {
            Err(Error::InvalidOperation(
                "No meta data at this node".to_string(),
            ))
        }
    }

    fn get_transfers(&mut self) -> Result<&mut Transfers> {
        if let Some(transfers) = &mut self.transfers {
            Ok(transfers)
        } else {
            Err(Error::InvalidOperation(
                "No meta data at this node".to_string(),
            ))
        }
    }

    fn get_reward_wallets(&mut self) -> Result<&mut RewardWallets> {
        if self.section_funds.is_none() {
            Err(Error::NoSectionFunds)
        } else if let Some(SectionFunds::KeepingNodeWallets {
            section_wallet,
            wallets,
        }) = &mut self.section_funds
        {
            Ok(wallets)
        } else {
            Err(Error::InvalidOperation(
                "Section fund churn, cannot complete request.".to_string(),
            ))
        }
    }

    fn get_section_funds(&mut self) -> Result<&mut SectionFunds> {
        if let Some(section_funds) = &mut self.section_funds {
            Ok(section_funds)
        } else {
            Err(Error::NoSectionFunds)
        }
    }

    fn get_churning_funds(
        &mut self,
    ) -> Result<(
        &mut RewardWallets,
        &mut ChurnProcess,
        &mut Option<SectionElders>,
    )> {
        if let Some(SectionFunds::Churning {
            wallets,
            process,
            replicas,
        }) = &mut self.section_funds
        {
            Ok((wallets, process, replicas))
        } else {
            debug!("get_churning_funds: whaaat? NoSectionFunds");
            Err(Error::NoSectionFunds)
        }
    }
}
