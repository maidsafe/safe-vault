// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    genesis::begin_forming_genesis_section, genesis::receive_genesis_accumulation,
    genesis::receive_genesis_proposal, genesis_stage::GenesisStage,
};
use crate::{
    messaging::{send, send_to_nodes},
    node_ops::{NodeDuties, NodeDuty},
    Node, Result,
};

impl Node {
    ///
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        match duty {
            NodeDuty::GetNodeWalletKey {
                old_node_id,
                new_node_id,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::ActivateNodeRewards {
                id,
                node_id,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::PropagateTransfer {
                proof,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::RegisterSectionPayout {
                debit_agreement,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::SetNodeWallet {
                wallet_id,
                node_id,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::ReceivePayoutValidation {
                validation,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::GetTransferReplicaEvents { msg_id, origin } => {
                return Ok(vec![]);
            }
            NodeDuty::ValidateSectionPayout {
                signed_transfer,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::ReadChunk {
                read,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::WriteChunk {
                write,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::CompleteWalletTransition {
                replicas,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }

            // ---------------------
            NodeDuty::GetSectionElders { msg_id, origin } => {}
            NodeDuty::BeginFormingGenesisSection => {
                self.genesis_stage =
                    begin_forming_genesis_section(self.network_api.clone()).await?;
            }
            NodeDuty::ReceiveGenesisProposal { credit, sig } => {
                self.genesis_stage = receive_genesis_proposal(
                    credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
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
            }
            NodeDuty::LevelUp => {
                self.level_up(None).await?;
            }
            NodeDuty::LevelDown => {
                self.meta_data = None;
                self.transfers = None;
                self.section_funds = None;
            }
            NodeDuty::AssumeAdultDuties => {}
            NodeDuty::UpdateElderInfo {
                prefix,
                key,
                elders,
                sibling_key,
            } => {}
            NodeDuty::CompleteElderChange {
                previous_key,
                new_key,
            } => {}
            NodeDuty::InformNewElders => {}
            NodeDuty::CompleteTransitionToElder {
                section_wallet,
                node_rewards,
                user_wallets,
            } => {}
            NodeDuty::ProcessNewMember(_) => {}
            NodeDuty::ProcessLostMember { name, age } => {}
            NodeDuty::ProcessRelocatedMember {
                old_node_id,
                new_node_id,
                age,
            } => {}
            NodeDuty::ReachingMaxCapacity => {}
            NodeDuty::IncrementFullNodeCount { node_id } => {}
            NodeDuty::SwitchNodeJoin(_) => {}
            NodeDuty::Send(msg) => send(msg, self.network_api.clone()).await?,
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, self.network_api.clone()).await?
            }
            NodeDuty::ProcessRead { query, id, origin } => {
                if let Some(ref meta_data) = self.meta_data {
                    return Ok(vec![meta_data.read(query, id, origin).await?]);
                }
            }
            NodeDuty::ProcessWrite { cmd, id, origin } => {
                if let Some(ref mut meta_data) = self.meta_data {
                    return Ok(vec![meta_data.write(cmd, id, origin).await?]);
                }
            }
            NodeDuty::NoOp => {}
        }
        Ok(vec![])
    }
}

// pub struct RewardsAndWallets {
//     pub section_wallet: WalletInfo,
//     pub node_rewards: BTreeMap<XorName, NodeRewardStage>,
//     pub user_wallets: BTreeMap<PublicKey, ActorHistory>,
// }

// impl RewardsAndWallets {
//     fn new(section_wallet: WalletInfo) -> Self {
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
    //         CompleteTransitionToElder {
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
    //         InformNewElders => self.inform_new_elders().await,
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

    // async fn inform_new_elders(&mut self) -> Result<NetworkDuties> {
    //     debug!("@@@@@@ INFORMING NEW ELDERS");
    //     let duties = self
    //         .elder_duties()
    //         .ok_or_else(|| Error::Logic("Only valid on Elders".to_string()))?;

    //     let peers = self.network_api.our_prefix().await.name();
    //     let section_key = self
    //         .network_api
    //         .section_public_key()
    //         .await
    //         .ok_or_else(|| Error::Logic("Section public key is missing".to_string()))?;

    //     let msg_id = MessageId::combine(vec![peers, section_key.into()]);

    //     let section_wallet = duties.section_wallet();
    //     let node_rewards = duties.node_rewards();
    //     let user_wallets = duties.user_wallets();

    //     Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
    //         msg: Message::NodeEvent {
    //             event: NodeEvent::PromotedToElder {
    //                 section_wallet,
    //                 node_rewards,
    //                 user_wallets,
    //             },
    //             correlation_id: msg_id,
    //             id: MessageId::in_response_to(&msg_id),
    //             target_section_pk: None,
    //         },
    //         section_source: false, // strictly this is not correct, but we don't expect responses to an event..
    //         dst: DstLocation::Section(peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
    //         aggregation: Aggregation::AtDestination,
    //     })))
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
