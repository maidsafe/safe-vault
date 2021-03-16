// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::WalletHistory;
use sn_messaging::MessageId;

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
    node_ops::{NodeDuties, NodeDuty},
    section_funds::{
        churn_process::ChurnProcess, reward_payout::RewardPayout, reward_stages::RewardStages,
        rewards::Rewards, SectionFunds,
    },
    transfers::Transfers,
    Error, Node, Result,
};
use xor_name::XorName;

impl Node {
    ///
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        match duty {
            NodeDuty::ChurnMembers {
                elders,
                sibling_elders,
            } => self.churn(elders, sibling_elders).await,
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
                self.continue_wallet_churn(replicas).await?;
                Ok(vec![])
            }
            //
            // ------- reward payout -------
            NodeDuty::PayoutNodeRewards {
                id,
                node_id,
                msg_id,
                origin,
            } => {
                let rewards = self.get_rewards()?;
                Ok(vec![rewards.payout_node_rewards(id, node_id).await?])
            }
            NodeDuty::ReceivePayoutValidation {
                validation,
                msg_id,
                origin,
            } => {
                let rewards = self.get_rewards()?;
                Ok(rewards.receive(validation).await?)
            }
            //
            // ------- reward reg -------
            NodeDuty::SetNodeWallet {
                wallet_id,
                node_id,
                msg_id,
                origin,
            } => {
                let rewards = self.get_section_funds()?;
                Ok(vec![rewards.set_node_wallet(node_id, wallet_id)?])
            }
            NodeDuty::GetNodeWalletKey {
                old_node_id,
                new_node_id,
                msg_id,
                origin,
            } => {
                let rewards = self.get_section_funds()?;
                Ok(vec![
                    rewards
                        .get_wallet_key(old_node_id, new_node_id, msg_id, origin)
                        .await?,
                ])
            }
            NodeDuty::ProcessNewMember(node_id) => {
                let rewards = self.get_section_funds()?;
                rewards.add_new_node(node_id);
                Ok(vec![])
            }
            NodeDuty::ProcessLostMember { name, age } => {
                let rewards = self.get_section_funds()?;
                rewards.deactivate(name)?;

                let metadata = self.get_metadata()?;
                Ok(metadata.trigger_chunk_replication(name).await?)
            }
            NodeDuty::ProcessRelocatedMember {
                old_node_id,
                new_node_id,
                age,
            } => {
                let rewards = self.get_section_funds()?;
                Ok(vec![
                    rewards
                        .add_relocating_node(old_node_id, new_node_id, age)
                        .await?,
                ])
            }
            //
            // ----- Genesis ----------
            NodeDuty::BeginFormingGenesisSection => {
                self.genesis_stage =
                    begin_forming_genesis_section(self.network_api.clone()).await?;
                Ok(vec![])
            }
            NodeDuty::ReceiveGenesisProposal { credit, sig } => {
                self.genesis_stage = receive_genesis_proposal(
                    credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
                Ok(vec![])
            }
            NodeDuty::ReceiveGenesisAccumulation { signed_credit, sig } => {
                self.genesis_stage = receive_genesis_accumulation(
                    signed_credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
                let genesis_tx = match &self.genesis_stage {
                    GenesisStage::Completed(genesis_tx) => genesis_tx.clone(),
                    _ => return Ok(vec![]),
                };
                self.level_up(Some(genesis_tx)).await?;
                Ok(vec![])
            }
            //
            // ---------- Levelling --------------
            NodeDuty::LevelUp => {
                self.level_up(None).await?;
                Ok(vec![])
            }
            NodeDuty::ContinueLevelUp {
                node_rewards,
                user_wallets,
            } => {
                self.continue_level_up(node_rewards, user_wallets).await?;
                Ok(vec![])
            }
            NodeDuty::CompleteLevelUp(wallet) => {
                self.complete_level_up(wallet).await?;
                Ok(vec![])
            }
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
            // -----------     -----------
            NodeDuty::UpdateElderInfo {
                prefix,
                key,
                elders,
                sibling_key,
            } => Ok(vec![]),
            NodeDuty::CompleteElderChange {
                previous_key,
                new_key,
            } => Ok(vec![]),
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
            NodeDuty::ValidateSectionPayout {
                signed_transfer,
                msg_id,
                origin,
            } => {
                let transfers = self.get_transfers()?;
                Ok(vec![
                    transfers
                        .validate_section_payout(signed_transfer, msg_id, origin)
                        .await?,
                ])
            }
            NodeDuty::RegisterSectionPayout {
                debit_agreement,
                msg_id,
                origin,
            } => {
                let transfers = self.get_transfers()?;
                Ok(transfers
                    .register_reward_payout(&debit_agreement, msg_id, origin)
                    .await?)
            }
            //
            // -------- Immutable chunks --------
            NodeDuty::ReadChunk {
                read,
                msg_id,
                origin,
            } => {
                let chunks = self.get_chunks()?;
                Ok(vec![chunks.read(&read, msg_id, origin).await?])
            }
            NodeDuty::WriteChunk {
                write,
                msg_id,
                origin,
            } => {
                let chunks = self.get_chunks()?;
                Ok(vec![chunks.write(&write, msg_id, origin).await?])
            }
            NodeDuty::ReachingMaxCapacity => Ok(vec![]),
            //
            // ------- Misc ------------
            NodeDuty::IncrementFullNodeCount { node_id } => Ok(vec![]),
            NodeDuty::SwitchNodeJoin(_) => Ok(vec![]),
            NodeDuty::Send(msg) => {
                send(msg, self.network_api.clone()).await?;
                Ok(vec![])
            }
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, self.network_api.clone()).await?;
                Ok(vec![])
            }
            //
            // ------- Data ------------
            NodeDuty::ProcessRead { query, id, origin } => {
                let meta_data = self.get_metadata()?;
                Ok(vec![meta_data.read(query, id, origin).await?])
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

    fn get_rewards(&mut self) -> Result<&mut Rewards> {
        if self.section_funds.is_none() {
            Err(Error::InvalidOperation(
                "No section funds at this node".to_string(),
            ))
        } else if let Some(SectionFunds::Rewarding(rewards)) = &mut self.section_funds {
            Ok(rewards)
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

    fn get_churning_funds(&mut self) -> Result<(&mut Rewards, &mut ChurnProcess)> {
        if let Some(SectionFunds::Churning { rewards, process }) = &mut self.section_funds {
            Ok((rewards, process))
        } else {
            Err(Error::InvalidOperation(
                "No section funds at this node".to_string(),
            ))
        }
    }
}

// pub struct RewardsAndWallets {
//     pub section_wallet: WalletHistory,
//     pub node_rewards: BTreeMap<XorName, NodeRewardStage>,
//     pub user_wallets: BTreeMap<PublicKey, ActorHistory>,
// }

// impl RewardsAndWallets {
//     fn new(section_wallet: WalletHistory) -> Self {
//         Self {
//             section_wallet: section_wallet,
//             node_rewards: Default::default(),
//             user_wallets: Default::default(),
//         }
//     }
// }

impl Node {
    // use GenesisStage::*;

    // use super::genesis::GenesisStage;

    // #[allow(clippy::large_enum_variant)]
    // enum Stage {
    //     Infant,
    //     Adult {
    //         adult: AdultDuties,
    //         queued_ops: VecDeque<ElderDuty>,
    //     },
    //     Genesis(GenesisStage),
    //     //AssumingElderDuties(ElderDuties),
    //     Elder(ElderConstellation),
    // }

    // #[allow(clippy::large_enum_variant)]
    // pub enum GenesisStage {
    //     None,
    //     AwaitingGenesisThreshold,
    //     ProposingGenesis(GenesisProposal),
    //     AccumulatingGenesis(GenesisAccumulation),
    // }

    // impl NodeDuties {
    // pub async fn new(node_info: NodeInfo, network_api: Network) -> Result<Self> {
    //     let state = NodeState::Infant(network_api.public_key().await);
    //     let msg_analysis = ReceivedMsgAnalysis::new(state);
    //     let network_events = w::new(msg_analysis);
    //     let messaging = Messaging::new(network_api.clone());
    //     Ok(Self {
    //         node_info,
    //         stage: Stage::Infant,
    //         network_events,
    //         messaging,
    //         network_api,
    //     })
    // }

    // pub async fn process(&mut self, duty: NetworkDuty) -> Result<NetworkDuties> {
    //     if self.network_api.is_elder().await {
    //         info!("Processing op: {:?}", duty);
    //     }
    //     use NetworkDuty::*;
    //     match duty {
    //         RunAsAdult(duty) => {
    //             if let Some(duties) = self.adult_duties() {
    //                 duties.process_adult_duty(duty).await
    //             } else {
    //                 Err(Error::Logic("Currently not an Adult".to_string()))
    //             }
    //         }
    //         RunAsElder(duty) => {
    //             if let Some(duties) = self.elder_duties_mut() {
    //                 duties.process_elder_duty(duty).await
    //             } else if let Stage::Adult {
    //                 ref mut queued_ops, ..
    //             } = &mut self.stage
    //             {
    //                 queued_ops.push_back(duty);
    //                 Ok(vec![])
    //             } else {
    //                 Err(Error::Logic("Cannot process the Elder duty".to_string()))
    //             }
    //         }
    //         RunAsNode(duty) => self.process_node_duty(duty).await,
    //         NoOp => Ok(vec![]),
    //     }
    // }

    // pub fn adult_duties(&mut self) -> Option<&mut AdultDuties> {
    //     match &mut self.stage {
    //         Stage::Adult { ref mut adult, .. } => Some(adult),
    //         _ => None,
    //     }
    // }

    // pub fn elder_duties(&self) -> Option<&ElderDuties> {
    //     match &self.stage {
    //         Stage::Elder(ref elder) => Some(elder.duties()),
    //         _ => None,
    //     }
    // }

    // pub fn elder_duties_mut(&mut self) -> Option<&mut ElderDuties> {
    //     match &mut self.stage {
    //         Stage::Elder(ref mut elder) => Some(elder.duties_mut()),
    //         _ => None,
    //     }
    // }

    // fn node_state(&mut self) -> Result<NodeState> {
    //     Ok(match self.elder_duties() {
    //         Some(duties) => NodeState::Elder(duties.state().clone()),
    //         None => match self.adult_duties() {
    //             Some(duties) => NodeState::Adult(duties.state().clone()),
    //             None => {
    //                 return Err(Error::InvalidOperation(
    //                     "match self.adult_duties() is None".to_string(),
    //                 ))
    //             }
    //         },
    //     })
    // }

    // async fn process_node_duty(&mut self, duty: NodeDuty) -> Result<NetworkDuties> {
    //     use NodeDuty::*;
    //     //info!("Processing Node duty: {:?}", duty);
    //     match duty {
    //         GetSectionElders { msg_id, origin } => self.section_pk_set(msg_id, origin).await,
    //         BeginFormingGenesisSection => self.begin_forming_genesis_section().await,
    //         ReceiveGenesisProposal { credit, sig } => {
    //             self.receive_genesis_proposal(credit, sig).await
    //         }
    //         ReceiveGenesisAccumulation { signed_credit, sig } => {
    //             self.receive_genesis_accumulation(signed_credit, sig).await
    //         }
    //         AssumeAdultDuties => self.assume_adult_duties().await,
    //         CompleteLevelUp {
    //             section_wallet,
    //             node_rewards,
    //             user_wallets,
    //         } => {
    //             self.complete_elder_setup(section_wallet, node_rewards, user_wallets, None)
    //                 .await
    //         }
    //         UpdateElderInfo {
    //             prefix,
    //             key,
    //             sibling_key,
    //             ..
    //         } => self.update_elder_info(prefix, key, sibling_key).await,
    //         CompleteElderChange {
    //             previous_key,
    //             new_key,
    //         } => self.complete_elder_change(previous_key, new_key).await,
    //         ChurnMembers => self.synch_data_to_peers().await,
    //         ProcessMessaging(duty) => self.messaging.process_messaging_duty(duty).await,
    //         ProcessNetworkEvent(event) => {
    //             self.network_events
    //                 .process_network_event(event, &self.network_api)
    //                 .await
    //         }
    //         NoOp => Ok(vec![]),
    //         StorageFull => self.notify_section_of_our_storage().await,
    //     }
    // }

    // async fn notify_section_of_our_storage(&mut self) -> Result<NetworkDuties> {
    //     let node_id = PublicKey::from(self.network_api.public_key().await);
    //     Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
    //         msg: Message::NodeCmd {
    //             cmd: NodeCmd::System(NodeSystemCmd::StorageFull {
    //                 section: node_id.into(),
    //                 node_id,
    //             }),
    //             id: MessageId::new(),
    //             target_section_pk: None,
    //         },
    //         section_source: false, // sent as single node
    //         dst: DstLocation::Section(node_id.into()),
    //         aggregation: Aggregation::None,
    //     })))
    // }

    //
    // async fn update_elder_info(
    //     &mut self,
    //     prefix: sn_routing::Prefix,
    //     new_section_key: PublicKey,
    //     sibling_key: Option<PublicKey>,
    // ) -> Result<NetworkDuties> {
    //     match &mut self.stage {
    //         Stage::Infant | Stage::Genesis(_) => Ok(vec![]),
    //         Stage::Adult { queued_ops, .. } => {
    //             let state = AdultState::new(self.network_api.clone()).await?;
    //             let adult = AdultDuties::new(&self.node_info, state).await?;
    //             self.stage = Stage::Adult {
    //                 adult,
    //                 queued_ops: mem::take(queued_ops),
    //             };
    //             Ok(vec![])
    //         }
    //         Stage::Elder(elder) => {
    //             elder
    //                 .update_elder_constellation(prefix, new_section_key, sibling_key)
    //                 .await
    //         }
    //     }
    // }

    //
    // async fn complete_elder_change(
    //     &mut self,
    //     previous_key: PublicKey,
    //     new_key: PublicKey,
    // ) -> Result<NetworkDuties> {
    //     match &mut self.stage {
    //         Stage::Infant | Stage::Adult { .. } | Stage::Genesis(_) => Ok(vec![]), // Should be unreachable
    //         Stage::Elder(elder) => {
    //             elder
    //                 .complete_elder_change(&self.node_info, previous_key, new_key)
    //                 .await
    //         }
    //     }
    // }

    // // Update our replica with the latest keys
    // pub async fn elders_changed(&mut self, rate_limit: RateLimit) -> Result<()> {
    //     let id = self.network.our_public_key_share().await?;
    //     let key_index = self
    //         .network
    //         .our_index()
    //         .await
    //         .map_err(|_| Error::NoSectionPublicKeySet)?;
    //     let peer_replicas = self.network.our_public_key_set().await?;
    //     let signing = ReplicaSigningImpl::new(self.network.clone());
    //     let info = ReplicaInfo {
    //         id: id.bls_share().ok_or(Error::ProvidedPkIsNotBlsShare)?,
    //         key_index,
    //         peer_replicas,
    //         section_chain: self.network.section_chain().await,
    //         signing,
    //         initiating: false,
    //     };
    //     self.transfers.update_replica_info(info, rate_limit);

    //     Ok(())
    // }
}
