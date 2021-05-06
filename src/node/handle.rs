// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeSet;

use super::{
    interaction::push_state,
    messaging::{send, send_to_nodes},
    role::{AdultRole, Role},
};
use crate::{
    chunks::Chunks,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{reward_stage::RewardStage, Credits, SectionFunds},
    Error, Node, Result,
};
use log::{debug, info};
use sn_messaging::{
    client::{Message, NodeQuery},
    Aggregation, DstLocation, MessageId,
};
use sn_routing::ELDER_SIZE;
use xor_name::XorName;

impl Node {
    ///
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        info!("Handling NodeDuty: {:?}", duty);
        match duty {
            NodeDuty::Genesis => {
                self.level_up().await?;
                let elder = self.role.as_elder_mut()?;
                elder.received_initial_sync = true;
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
                    if self.network_api.our_prefix().await.is_empty()
                        && self.network_api.section_chain().await.len() <= ELDER_SIZE
                    {
                        let elder = self.role.as_elder_mut()?;
                        elder.received_initial_sync = true;
                    }
                    Ok(vec![])
                } else {
                    info!("Updating our replicas on Churn");
                    self.update_replicas().await?;
                    let elder = self.role.as_elder_mut()?;
                    let msg_id =
                        MessageId::combine(vec![our_prefix.name(), XorName::from(our_key)]);
                    let ops = vec![push_state(elder, our_prefix, msg_id).await?];
                    elder
                        .meta_data
                        .retain_members_only(self.network_api.our_adults().await)
                        .await?;
                    Ok(ops)
                }
            }
            NodeDuty::AdultsChanged(adults) => {
                let our_name = self.our_name().await;
                Ok(self
                    .role
                    .as_adult_mut()?
                    .handle_adults_changed(adults, our_name)
                    .await)
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
            NodeDuty::ProposeOffline(unresponsive_adults) => {
                for adult in unresponsive_adults {
                    self.network_api.propose_offline(adult).await?;
                }
                Ok(vec![])
            }
            // a remote section asks for the replicas of their wallet
            NodeDuty::GetSectionElders { msg_id, origin } => {
                Ok(vec![self.get_section_elders(msg_id, origin).await?])
            }
            NodeDuty::ReceiveRewardProposal(proposal) => {
                let elder = self.role.as_elder_mut()?;
                info!("Handling Churn proposal as an Elder");
                let (churn_process, _) = elder.section_funds.as_churning_mut()?;
                Ok(vec![churn_process.receive_churn_proposal(proposal).await?])
            }
            NodeDuty::ReceiveRewardAccumulation(accumulation) => {
                let elder = self.role.as_elder_mut()?;

                let (churn_process, reward_wallets) = elder.section_funds.as_churning_mut()?;

                let mut ops = vec![
                    churn_process
                        .receive_wallet_accumulation(accumulation)
                        .await?,
                ];

                if let RewardStage::Completed(credit_proofs) = churn_process.stage().clone() {
                    let reward_sum = credit_proofs.sum();
                    ops.extend(Self::propagate_credits(credit_proofs)?);
                    // update state
                    elder.section_funds = SectionFunds::KeepingNodeWallets(reward_wallets.clone());
                    let section_key = &self.network_api.section_public_key().await?;
                    info!(
                        "COMPLETED SPLIT. New section: ({}). Total rewards paid: {}.",
                        section_key, reward_sum
                    );
                    ops.push(NodeDuty::SetNodeJoinsAllowed(true));
                }

                Ok(ops)
            }
            //
            // ------- reward reg -------
            NodeDuty::SetNodeWallet { wallet_id, node_id } => {
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
            NodeDuty::GetNodeWalletKey { node_name, .. } => {
                let elder = self.role.as_elder_mut()?;
                let members = self.network_api.our_members().await;
                if members.get(&node_name).is_some() {
                    let _wallet = elder.section_funds.get_node_wallet(&node_name);
                    Ok(vec![]) // not yet implemented
                } else {
                    debug!(
                        "{:?}: Couldn't find node {} when getting wallet.",
                        self.network_api.our_prefix().await,
                        node_name,
                    );
                    Err(Error::NodeNotFoundForReward)
                }
            }
            NodeDuty::ProcessLostMember { name, .. } => {
                info!("Member Lost: {:?}", name);
                let mut ops = vec![];

                info!("Setting JoinsAllowed to `True` for replacing the member left");
                ops.push(NodeDuty::SetNodeJoinsAllowed(true));

                let elder = self.role.as_elder_mut()?;
                elder.section_funds.remove_node_wallet(name);

                Ok(ops)
            }
            //
            // ---------- Levelling --------------
            NodeDuty::SynchState {
                node_rewards,
                user_wallets,
                metadata,
            } => Ok(vec![
                self.synch_state(node_rewards, user_wallets, metadata)
                    .await?,
            ]),
            NodeDuty::LevelDown => {
                info!("Getting Demoted");
                let capacity = self.used_space.max_capacity().await;
                self.role = Role::Adult(AdultRole {
                    chunks: Chunks::new(self.node_info.root_dir.as_path(), capacity).await?,
                    adult_list: BTreeSet::new(),
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
            NodeDuty::SimulatePayout { transfer, .. } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.transfers.credit_without_proof(transfer).await?])
            }
            NodeDuty::GetTransfersHistory {
                at, msg_id, origin, ..
            } => {
                // TODO: add limit with since_version
                let elder = self.role.as_elder()?;
                Ok(vec![elder.transfers.history(&at, msg_id, origin).await?])
            }
            NodeDuty::GetBalance { at, msg_id, origin } => {
                let elder = self.role.as_elder()?;
                Ok(vec![elder.transfers.balance(at, msg_id, origin).await?])
            }
            NodeDuty::GetStoreCost {
                bytes,
                msg_id,
                origin,
                ..
            } => {
                let elder = self.role.as_elder_mut()?;
                Ok(elder.transfers.get_store_cost(bytes, msg_id, origin).await)
            }
            NodeDuty::RegisterTransfer { proof, msg_id } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.transfers.register(&proof, msg_id).await?])
            }
            //
            // -------- Immutable chunks --------
            NodeDuty::ReadChunk { read, msg_id, .. } => {
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
                    let mut ops = adult.chunks.read(&read, msg_id);
                    ops.extend(adult.chunks.check_storage().await?);
                    Ok(ops)
                } else {
                    log::error!("MessageId: {:?} NodeCmd::Chunks {:?} should not have reached a wrong Adult", msg_id, read);
                    Ok(vec![])
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
            NodeDuty::ProcessRepublish { chunk, msg_id } => {
                log::info!("Processing republish with MessageId: {:?}", msg_id);
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.meta_data.republish_chunk(chunk).await?])
            }
            NodeDuty::ReachingMaxCapacity => Ok(vec![self.notify_section_of_our_storage().await?]),
            //
            // ------- Misc ------------
            NodeDuty::IncrementFullNodeCount { node_id } => {
                let elder = self.role.as_elder_mut()?;
                elder.meta_data.increase_full_node_count(node_id).await?;
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
                    let elder = self.role.as_elder_mut()?;
                    Ok(vec![elder.meta_data.read(query, id, origin).await?])
                } else {
                    Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: Message::NodeQuery {
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
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.meta_data.write(cmd, id, origin).await?])
            }
            // --- Completion of Adult operations ---
            NodeDuty::RecordAdultWriteLiveness {
                correlation_id,
                result,
                src,
            } => {
                let elder = self.role.as_elder_mut()?;
                Ok(elder
                    .meta_data
                    .record_adult_write_liveness(correlation_id, result, src)
                    .await)
            }
            NodeDuty::RecordAdultReadLiveness {
                response,
                correlation_id,
                src,
            } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![
                    elder
                        .meta_data
                        .record_adult_read_liveness(correlation_id, response, src)
                        .await?,
                ])
            }
            NodeDuty::ProcessDataPayment { msg, origin } => {
                let elder = self.role.as_elder_mut()?;
                Ok(vec![elder.transfers.process_payment(&msg, origin).await?])
            }
            NodeDuty::ReplicateChunk { data, id } => {
                let adult = self.role.as_adult_mut()?;
                Ok(vec![adult.chunks.store_for_replication(data, id).await?])
            }
            NodeDuty::NoOp => Ok(vec![]),
        }
    }
}
