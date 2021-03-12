// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// mod elder_constellation;
// pub mod genesis;
// pub mod messaging;
// mod msg_analysis;
// mod network_events;

// use self::{
//     // elder_constellation::ElderConstellation,
//     // genesis::{GenesisAccumulation, GenesisProposal},
// };
use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    node::{
        // adult_duties::AdultDuties,
        // elder_duties::{ElderData, ElderDuties},
        // node_duties::messaging::Messaging,
        genesis::{GenesisAccumulation, GenesisProposal, GenesisStage},
        key_section::{transfers::replica_signing::ReplicaSigningImpl, WalletSection},
        node_ops::{
            ElderDuty, NetworkDuties, NetworkDuty, NodeDuty, NodeMessagingDuty, OutgoingMsg,
        },
        NodeInfo,
        RewardsAndWallets,
    },
    Error, Network, Node, Result,
};
use log::{debug, error, info, trace, warn};
// use msg_analysis::ReceivedMsgAnalysis;
// use network_events::w;
use sn_data_types::{
    ActorHistory, Credit, NodeRewardStage, PublicKey, SignatureShare, SignedCredit, Token,
    TransferPropagated, WalletInfo,
};
use sn_messaging::{
    client::{
        Message, NodeCmd, NodeEvent, NodeQueryResponse, NodeSystemCmd, NodeSystemQueryResponse,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::{XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use std::{
    collections::{BTreeMap, VecDeque},
    mem,
};

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

/// Node duties are those that all nodes
/// carry out. (TBD: adjust for Infant level, which might be doing nothing now).
/// Within the duty level, there are then additional
/// duties to be carried out, depending on the level.
// pub struct NodeDuties {
//     node_info: NodeInfo,
//     stage: Stage,
//     // network_events: w,
//     messaging: Messaging,
//     network_api: Network,
// }

/// Configuration made after connected to
/// network, or promoted to elder.
///
/// These are calls made as part of
/// a node initialising into a certain duty.
/// Being first node:
/// -> 1. Add own node id to rewards.
/// -> 2. Add own wallet to rewards.
/// Assuming Adult duties:
/// -> 1. Instantiate AdultDuties.
/// -> 2. Register wallet at Elders.
/// Assuming Elder duties:
/// -> 1. Instantiate ElderDuties.
/// -> 2. Add own node id to rewards.
/// -> 3. Add own wallet to rewards.
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
//         GetSectionPkSet { msg_id, origin } => self.section_pk_set(msg_id, origin).await,
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

impl Node {
    // async fn section_pk_set(
    //     &self,
    //     msg_id: MessageId,
    //     origin: SrcLocation,
    // ) -> Result<NetworkDuties> {
    //     let replicas = self.network_api.public_key_set().await?;
    //     Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
    //         msg: Message::NodeQueryResponse {
    //             response: NodeQueryResponse::System(NodeSystemQueryResponse::GetSectionPkSet(
    //                 replicas,
    //             )),
    //             correlation_id: msg_id,
    //             id: MessageId::in_response_to(&msg_id),
    //             target_section_pk: None,
    //         },
    //         section_source: false, // strictly this is not correct, but we don't expect responses to a response..
    //         dst: origin.to_dst(),
    //         aggregation: Aggregation::AtDestination,
    //     })))
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

    // async fn assume_adult_duties(&mut self) -> Result<NetworkDuties> {
    //     if matches!(self.stage, Stage::Adult { .. }) {
    //         return Ok(vec![]);
    //     }
    //     info!("Assuming Adult duties..");
    //     let state = AdultState::new(self.network_api.clone()).await?;
    //     let adult = AdultDuties::new(&self.node_info, state.clone()).await?;
    //     self.node_info.used_space.reset().await;
    //     self.stage = Stage::Adult {
    //         adult,
    //         queued_ops: VecDeque::new(),
    //     };
    //     self.network_events = w::new(ReceivedMsgAnalysis::new(NodeState::Adult(state)));
    //     info!("Adult duties assumed.");
    //     // NB: This is wrong, shouldn't write to disk here,
    //     // let it be upper layer resp.
    //     // Also, "Error-to-Unit" is not a good conversion..
    //     //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());

    //     let is_genesis_section = self.network_api.our_prefix().await.is_empty();
    //     let elder_count = self.network_api.our_elder_names().await.len();
    //     let section_chain_len = self.network_api.section_chain().await.len();

    //     let genesis_stage = is_genesis_section
    //         && elder_count < GENESIS_ELDER_COUNT
    //         && section_chain_len <= GENESIS_ELDER_COUNT;

    //     if !genesis_stage {
    //         self.register_wallet().await
    //     } else {
    //         Ok(vec![])
    //     }
    // }

    async fn register_wallet(&self) -> Result<()> {
        let address = self.network_api.our_prefix().await.name();
        info!("Registering wallet: {}", self.node_info.reward_key);
        self.messaging
            .send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(self.node_info.reward_key)),
                    id: MessageId::new(),
                    target_section_pk: None,
                },
                section_source: false, // sent as single node
                dst: DstLocation::Section(address),
                aggregation: Aggregation::None,
            })
            .await?;

        Ok(())
    }

    pub async fn begin_forming_genesis_section(&self) -> Result<()> {
        let is_genesis_section = self.network_api.our_prefix().await.is_empty();
        let elder_count = self.network_api.our_elder_names().await.len();
        let section_chain_len = self.network_api.section_chain().await.len();
        let our_pk_share = self.network_api.our_public_key_share().await?;
        let our_index = self.network_api.our_index().await?;

        debug!(
            "begin_transition_to_elder. is_genesis_section: {}, elder_count: {}, section_chain_len: {}",
            is_genesis_section, elder_count, section_chain_len
        );
        if is_genesis_section
            && elder_count == GENESIS_ELDER_COUNT
            && section_chain_len <= GENESIS_ELDER_COUNT
        {
            // this is the case when we are the GENESIS_ELDER_COUNT-th Elder!
            debug!("**********threshold reached; proposing genesis!");

            // let rewards_and_wallets = RewardsAndWallets::new(self.network_api.clone()).await?;
            let genesis_balance = u32::MAX as u64 * 1_000_000_000;
            let credit = Credit {
                id: Default::default(),
                amount: Token::from_nano(genesis_balance),
                recipient: self
                    .network_api
                    .section_public_key()
                    .await
                    .ok_or(Error::NoSectionPublicKey)?,
                msg: "genesis".to_string(),
            };
            let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
            let credit_sig_share = self.network_api.sign_as_elder(&credit).await?;
            let _ = signatures.insert(our_index, credit_sig_share.clone());

            let mut stage = self.genesis_stage.lock().await;

            *stage = GenesisStage::ProposingGenesis(GenesisProposal {
                proposal: credit.clone(),
                signatures,
                pending_agreement: None,
            });

            let dst = DstLocation::Section(credit.recipient.into());

            self.messaging
                .send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                            credit,
                            sig: SignatureShare {
                                share: credit_sig_share,
                                index: our_index,
                            },
                        }),
                        id: MessageId::new(),
                        target_section_pk: None,
                    },
                    dst,
                    section_source: false, // sent as single node
                    aggregation: Aggregation::None,
                })
                .await?;

            // return Ok(NetworkDuties::from());
        } else if is_genesis_section
            && elder_count < GENESIS_ELDER_COUNT
            && section_chain_len <= GENESIS_ELDER_COUNT
        {
            debug!("AwaitingGenesisThreshold!");
            let mut stage = self.genesis_stage.lock().await;

            *stage = GenesisStage::AwaitingGenesisThreshold;
            // return Ok(vec![]);
        } else {
            debug!("HITTING GENESIS ELSE FOR SOME REASON....");
            // Err(Error::InvalidOperation(
            //     "Only for genesis formation".to_string(),
            // ))
        }
        Ok(())
    }

    /// Wallet info of our constellation is supplied here
    async fn complete_elder_setup(&mut self, genesis: Option<TransferPropagated>) -> Result<()> {
        debug!(">>>>>>>>>>> Completing transition to elder!!!");
        debug!("????");
        let stage = self.genesis_stage.lock().await;

        trace!(">>> Setting up node dbs etc...");

        let rewards_and_wallets = RewardsAndWallets::new(WalletInfo {
            replicas: self.network_api.our_public_key_set().await?,
            history: ActorHistory {
                credits: vec![],
                debits: vec![],
            },
        });
        let dbs = ChunkHolderDbs::new(self.node_info.root_dir.as_path())?;
        let rate_limit = RateLimit::new(self.network_api.clone(), Capacity::new(dbs.clone()));

        let replica_signing =
            ReplicaSigningImpl::new(rewards_and_wallets.clone(), self.network_api.clone());
        let mut wallet_section = WalletSection::new(
            rate_limit,
            &self.node_info,
            rewards_and_wallets.clone(),
            Default::default(),
            replica_signing,
            self.network_api.clone(),
        )
        .await?;

        let node_rewards = rewards_and_wallets.node_rewards;
        let node_id = self.network_api.our_name().await;
        let register_wallet = match node_rewards.lock().await.get(&node_id) {
            None => true,
            Some(stage) => match stage {
                NodeRewardStage::NewNode | NodeRewardStage::AwaitingActivation(_) => true,
                NodeRewardStage::Active { .. } | NodeRewardStage::AwaitingRelocation(_) => false,
            },
        };

        if let Some(genesis) = genesis {
            // if we are genesis
            // does local init, with no roundrip via network messaging
            wallet_section.init_genesis_node(genesis).await?;
        }

        // 3. Set new stage
        self.node_info.used_space.reset().await;

        // self.stage = Stage::Elder(ElderConstellation::new(
        //     elder_duties,
        //     self.network_api.clone(),
        // ));

        // self.network_events = NetworkEvents::new(ReceivedMsgAnalysis::new(NodeState::Elder(
        //     rewards_and_wallets.clone(),
        // )));

        info!("Successfully assumed Elder duties!");

        if register_wallet {
            self.register_wallet().await?
        }

        debug!(">>>> I AM ELDER");
        Ok(())
    }

    ///
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

    ///
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

    // TODO: validate the credit...
    pub async fn receive_genesis_proposal(
        &self,
        credit: Credit,
        sig: SignatureShare,
    ) -> Result<()> {
        let our_index = self.network_api.our_index().await?;

        let mut stage = self.genesis_stage.lock().await;
        let new_stage = match *stage {
            GenesisStage::AwaitingGenesisThreshold => {
                // let rewards_and_wallets = RewardsAndWallets::new(self.network_api.clone()).await?;

                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let _ = signatures.insert(sig.index, sig.share);

                let credit_sig_share = self.network_api.sign_as_elder(&credit).await?;
                let _ = signatures.insert(our_index, credit_sig_share.clone());

                let dst = DstLocation::Section(XorName::from(
                    self.network_api
                        .section_public_key()
                        .await
                        .ok_or(Error::NoSectionPublicKey)?,
                ));
                let stage = GenesisStage::ProposingGenesis(GenesisProposal {
                    // rewards_and_wallets,
                    proposal: credit.clone(),
                    signatures,
                    pending_agreement: None,
                });

                self.messaging
                    .send(OutgoingMsg {
                        msg: Message::NodeCmd {
                            cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                                credit: credit,
                                sig: SignatureShare {
                                    share: credit_sig_share,
                                    index: our_index,
                                },
                            }),
                            id: MessageId::new(),
                            target_section_pk: None,
                        },
                        section_source: false, // sent as single node
                        dst,
                        aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                    })
                    .await?;

                stage
            }
            GenesisStage::ProposingGenesis(ref mut bootstrap) => {
                debug!("Adding incoming genesis proposal.");
                let section_pk_set = self
                    .network_api
                    .our_public_key_set()
                    .await
                    .map_err(|_| Error::NoSectionPublicKeySet)?;
                let section_pk = PublicKey::Bls(section_pk_set.public_key());
                bootstrap.add(sig, section_pk_set)?;
                if let Some(signed_credit) = &bootstrap.pending_agreement {
                    info!("******* there is an agreement");
                    // replicas signatures over > signed_credit <
                    let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                    let credit_sig_share = self.network_api.sign_as_elder(&signed_credit).await?;
                    let _ = signatures.insert(our_index, credit_sig_share.clone());

                    let stage = GenesisStage::AccumulatingGenesis(GenesisAccumulation {
                        // rewards_and_wallets: bootstrap.rewards_and_wallets.clone(),
                        agreed_proposal: signed_credit.clone(),
                        signatures,
                        pending_agreement: None,
                    });

                    self.messaging
                        .send(OutgoingMsg {
                            msg: Message::NodeCmd {
                                cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis {
                                    signed_credit: signed_credit.clone(),
                                    sig: SignatureShare {
                                        share: credit_sig_share,
                                        index: our_index,
                                    },
                                }),
                                id: MessageId::new(),
                                target_section_pk: None,
                            },
                            section_source: false, // sent as single node
                            dst: DstLocation::Section(XorName::from(section_pk)),
                            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                        })
                        .await?;

                    stage
                } else {
                    return Ok(());
                }
            }
            _ => {
                warn!("Recevied an out of order proposal for genesis.");
                warn!("We may already have seen + verified genesis, in which case this can be ignored.");

                // TODO: do we want to Lazy err here?

                return Ok(());
            }
        };

        *stage = new_stage;
        Ok(())
        // Ok(NetworkDuties::from(cmd))
    }

    /// Receive genesis accumulation
    pub async fn receive_genesis_accumulation(
        &mut self,
        signed_credit: SignedCredit,
        sig: SignatureShare,
    ) -> Result<()> {
        let mut stage = self.genesis_stage.lock().await;

        let (new_stage, finish_setup) = match *stage {
            GenesisStage::ProposingGenesis(ref mut bootstrap) => {
                // replicas signatures over > signed_credit <
                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let _ = signatures.insert(sig.index, sig.share);
                let our_sig_index = self.network_api.our_index().await?;

                let credit_sig_share = self.network_api.sign_as_elder(&signed_credit).await?;
                let _ = signatures.insert(our_sig_index, credit_sig_share);

                Ok((
                    Some(GenesisStage::AccumulatingGenesis(GenesisAccumulation {
                        // rewards_and_wallets: bootstrap.rewards_and_wallets.clone(),
                        agreed_proposal: signed_credit,
                        signatures,
                        pending_agreement: None,
                    })),
                    None,
                ))
            }
            GenesisStage::AccumulatingGenesis(ref mut bootstrap) => {
                let section_pk_set = self
                    .network_api
                    .our_public_key_set()
                    .await
                    .map_err(|_| Error::NoSectionPublicKeySet)?;
                bootstrap.add(sig, section_pk_set)?;

                let mut the_genesis = None;
                if let Some(genesis) = bootstrap.pending_agreement.take() {
                    // TODO: do not take this? (in case of fail further blow)
                    let our_sig_index = self.network_api.our_index().await?;
                    let credit_sig_share = self.network_api.sign_as_elder(&genesis).await?;
                    let _ = bootstrap
                        .signatures
                        .insert(our_sig_index, credit_sig_share.clone());

                    the_genesis = Some(TransferPropagated {
                        credit_proof: genesis.clone(),
                    });
                }

                Ok((None, the_genesis))
            }
            _ => Err(Error::InvalidGenesisStage),
        }?;

        if let Some(new) = new_stage {
            *stage = new;
        }

        // manually drop stage now we're done with it.
        drop(stage);

        if finish_setup.is_some() {
            debug!(">>>>>>>>>>>>>>>>>>>>>>>>. GENSIS AGREEMENT PROOFED!!!!");

            return self.complete_elder_setup(finish_setup).await;
        }
        Ok(())
    }
}
