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
    node::{AdultRole, Role},
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{
        reward_process::RewardProcess,
        reward_stage::{CreditAccumulation, RewardStage},
        reward_wallets::RewardWallets,
        Credits, SectionFunds,
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
use std::collections::{BTreeMap, VecDeque};
use xor_name::XorName;

impl Node {
    ///
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
                    Ok(vec![self.push_state(our_prefix, msg_id)])
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
                let elder = self.role.as_elder_mut()?;

                if let SectionFunds::Churning { process, .. } = &mut elder.section_funds {
                    info!("Handling Churn proposal as an Elder");
                    Ok(vec![process.receive_churn_proposal(proposal).await?])
                } else {
                    Err(Error::NotChurningFunds)
                }
            }
            NodeDuty::ReceiveRewardAccumulation(accumulation) => {
                let elder = self.role.as_elder_mut()?;

                if let SectionFunds::Churning {
                    process,
                    wallets,
                    payments,
                } = &mut elder.section_funds
                {
                    let mut ops = vec![process.receive_wallet_accumulation(accumulation).await?];

                    if let RewardStage::Completed(credit_proofs) = process.stage().clone() {
                        let reward_sum = credit_proofs.sum();
                        ops.extend(Self::propagate_credits(credit_proofs)?);
                        // update state
                        elder.section_funds = SectionFunds::KeepingNodeWallets {
                            wallets: wallets.clone(),
                            payments: payments.clone(),
                        };
                        let section_key = &self.network_api.section_public_key().await?;
                        info!(
                            "COMPLETED SPLIT. New section: ({}). Total rewards paid: {}.",
                            section_key, reward_sum
                        );
                    }

                    Ok(ops)
                } else {
                    Err(Error::NotChurningFunds)
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
                let elder = self.role.as_elder_mut()?;
                let members = self.network_api.our_members().await;
                if let Some(age) = members.get(&node_id) {
                    elder
                        .section_funds
                        .set_node_wallet(node_id, wallet_id, *age);
                    Ok(vec![])
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

                let elder = self.role.as_elder_mut()?;
                elder.section_funds.remove_node_wallet(name);
                elder
                    .transfers
                    .decrease_full_node_count_if_present(name)
                    .await?;

                ops.extend(elder.meta_data.trigger_chunk_replication(name).await?);

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
                self.role = Role::Adult(AdultRole {
                    chunks: Chunks::new(
                        self.node_info.node_name,
                        self.node_info.root_dir.as_path(),
                        self.used_space.clone(),
                    )
                    .await?,
                });
                Ok(vec![])
            }
            //
            // ----------- Transfers -----------
            NodeDuty::GetTransferReplicaEvents { msg_id, origin } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.transfers.all_events(msg_id, origin).await?])
            }
            NodeDuty::PropagateTransfer {
                proof,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![
                    elder
                        .transfers
                        .receive_propagated(&proof, msg_id, origin)
                        .await?,
                ])
            }
            NodeDuty::ValidateClientTransfer {
                signed_transfer,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder()?;
                Ok(vec![
                    elder
                        .transfers
                        .validate(signed_transfer, msg_id, origin)
                        .await?,
                ])
            }
            NodeDuty::SimulatePayout {
                transfer,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.transfers.credit_without_proof(transfer).await?])
            }
            NodeDuty::GetTransfersHistory {
                at,
                since_version,
                msg_id,
                origin,
            } => {
                debug!(">>>> TODO: GET TRANSFER HISTORY, ADD limit with since_version....");
                let elder = self.role.as_elder()?;
                Ok(vec![elder.transfers.history(&at, msg_id, origin).await?])
            }
            NodeDuty::GetBalance { at, msg_id, origin } => {
                let elder = self.role.as_elder()?;
                Ok(vec![elder.transfers.balance(at, msg_id, origin).await?])
            }
            NodeDuty::GetStoreCost {
                requester,
                bytes,
                msg_id,
                origin,
            } => {
                let elder = self.role.as_elder()?;
                Ok(vec![
                    elder.transfers.get_store_cost(bytes, msg_id, origin).await,
                ])
            }
            NodeDuty::RegisterTransfer { proof, msg_id } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.transfers.register(&proof, msg_id).await?])
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
                    let adult = self.role.as_adult_mut()?;
                    let read = adult.chunks.read(&read, msg_id, origin).await?;
                    let mut ops = adult.chunks.check_storage().await?;
                    ops.insert(0, read);
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
                let adult = self.role.as_adult_mut()?;
                Ok(vec![adult.chunks.write(&write, msg_id, origin).await?])
            }
            NodeDuty::ReachingMaxCapacity => Ok(vec![self.notify_section_of_our_storage().await?]),
            //
            // ------- Misc ------------
            NodeDuty::IncrementFullNodeCount { node_id } => {
                let elder = self.role.as_elder_mut()?;
                elder.transfers.increase_full_node_count(node_id).await?;
                // Accept a new node in place for the full node.
                Ok(vec![NodeDuty::SetNodeJoinsAllowed(true)])
            }
            NodeDuty::Send(msg) => {
                send(msg, &self.network_api).await?;
                Ok(vec![])
            }
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, &self.network_api).await?;
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
                    let elder = self.role.as_elder()?;
                    Ok(vec![elder.meta_data.read(query, id, origin).await?])
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
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.meta_data.write(cmd, id, origin).await?])
            }
            NodeDuty::ProcessDataPayment { msg, origin } => {
                let elder = self.role.as_elder_mut()?;
                elder.transfers.process_payment(&msg, origin).await
            }
            NodeDuty::AddPayment(credit) => {
                let elder = self.role.as_elder_mut()?;
                elder.section_funds.add_payment(credit);
                Ok(vec![])
            }
            NodeDuty::ReplicateChunk {
                current_holders,
                address,
                id,
            } => {
                let adult = self.role.as_adult()?;
                Ok(vec![
                    adult
                        .chunks
                        .replicate_chunk(address, current_holders, id)
                        .await?,
                ])
            }
            NodeDuty::GetChunkForReplication {
                address,
                new_holder,
                id,
            } => {
                let adult = self.role.as_adult()?;
                Ok(vec![
                    adult
                        .chunks
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
                    let adult = self.role.as_adult_mut()?;
                    Ok(vec![adult.chunks.store_replicated_chunk(data).await?])
                } else {
                    log::warn!("Invalid message ID");
                    Ok(vec![])
                }
            }
            NodeDuty::NoOp => Ok(vec![]),
        }
    }
}
