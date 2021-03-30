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
    messaging::{send, send_to_nodes},
};
use crate::{
    chunks::Chunks,
    metadata::Metadata,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{
        churn_process::PayoutProcess,
        payout_stage::{CreditAccumulation, PayoutStage},
        reward_wallets::RewardWallets,
        section_wallet::SectionWallet,
        SectionFunds,
    },
    transfers::Transfers,
    Error, Node, Result,
};
use dashmap::DashMap;
use log::{debug, info};
use sn_data_types::{CreditAgreementProof, CreditId, PublicKey, SectionElders, WalletHistory};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, Query},
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
                newbie,
            } => {
                if newbie {
                    self.level_up().await?;
                }
                Ok(vec![])
            }
            NodeDuty::SplitSection {
                our_key,
                our_prefix,
                sibling_key,
                newbie,
            } => {
                if newbie {
                    self.begin_split_as_newbie(our_key, our_prefix).await?;
                    Ok(vec![])
                } else {
                    self.begin_split_as_oldie(our_prefix, our_key, sibling_key)
                        .await
                }
            }
            // a remote section asks for the replicas of their wallet
            NodeDuty::GetSectionElders { msg_id, origin } => {
                Ok(vec![self.get_section_elders(msg_id, origin).await?])
            }
            NodeDuty::ReceiveChurnProposal(proposal) => {
                if let Ok((churn_process, _, _)) = self.get_churning_funds() {
                    Ok(vec![churn_process.receive_churn_proposal(proposal).await?])
                } else {
                    // we are an adult, so ignore this msg
                    Ok(vec![])
                }
            }
            NodeDuty::ReceiveChurnAccumulation(accumulation) => {
                if let Ok((churn_process, reward_wallets, payments)) = self.get_churning_funds() {
                    let mut ops = vec![
                        churn_process
                            .receive_wallet_accumulation(accumulation)
                            .await?,
                    ];

                    if let PayoutStage::Completed(credit_proofs) = churn_process.stage().clone() {
                        ops.extend(Self::propagate_credits(credit_proofs)?);
                        // update state
                        self.section_funds = Some(SectionFunds::KeepingNodeWallets {
                            wallets: reward_wallets.clone(),
                            payments: payments.clone(),
                        });
                        let section_key = &self.network_api.section_public_key().await?;
                        info!("COMPLETED({}): Rewards have been paid out.", section_key);
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
            } => Ok(vec![]),
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
                // TODO: remove this conditional branching
                // routing should take care of this
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
                let chunks = self.get_chunks()?;
                Ok(vec![chunks.write(&write, msg_id, origin).await?])
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
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SwitchNodeJoin(_) => Ok(vec![]),
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
                    let meta_data = self.get_metadata()?;
                    Ok(vec![meta_data.read(query, id, origin).await?])
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
                let meta_data = self.get_metadata()?;
                Ok(vec![meta_data.write(cmd, id, origin).await?])
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
        } else if let Some(SectionFunds::KeepingNodeWallets { wallets, payments }) =
            &mut self.section_funds
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
            Err(Error::InvalidOperation(
                "No section funds at this node".to_string(),
            ))
        }
    }

    fn get_churning_funds(
        &mut self,
    ) -> Result<(
        &mut PayoutProcess,
        &mut RewardWallets,
        &mut DashMap<CreditId, CreditAgreementProof>,
    )> {
        if let Some(SectionFunds::Churning {
            process,
            wallets,
            payments,
        }) = &mut self.section_funds
        {
            Ok((process, wallets, payments))
        } else {
            debug!("get_churning_funds: whaaat? NoSectionFunds");
            Err(Error::NoSectionFunds)
        }
    }
}
