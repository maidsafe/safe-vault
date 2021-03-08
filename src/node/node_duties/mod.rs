// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elder_constellation;
mod genesis;
pub mod messaging;
mod msg_analysis;
mod network_events;

use self::{
    elder_constellation::ElderConstellation,
    genesis::{GenesisAccumulation, GenesisProposal},
};
use crate::{
    node::{
        adult_duties::AdultDuties,
        elder_duties::{ElderData, ElderDuties},
        node_duties::messaging::Messaging,
        node_ops::{
            ElderDuty, NetworkDuties, NetworkDuty, NodeDuty, NodeMessagingDuty, OutgoingMsg,
            RewardCmd, RewardDuty,
        },
        NodeInfo,
    },
    AdultState, ElderState, Error, Network, NodeState, Result,
};
use log::{debug, info, trace};
use msg_analysis::ReceivedMsgAnalysis;
use network_events::NetworkEvents;
use sn_data_types::{
    ActorHistory, Credit, NodeRewardStage, PublicKey, SignatureShare, SignedCredit, Token,
    TransferPropagated, WalletInfo,
};
use sn_messaging::{
    client::{
        Message, NodeCmd, NodeEvent, NodeQuery, NodeQueryResponse, NodeRewardQuery, NodeSystemCmd,
        NodeTransferQueryResponse,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::{XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use std::{
    collections::{BTreeMap, VecDeque},
    mem,
};
use GenesisStage::*;

#[allow(clippy::large_enum_variant)]
enum Stage {
    Infant,
    Adult(AdultDuties),
    Genesis(GenesisStage),
    //AssumingElderDuties(ElderDuties),
    Elder(ElderConstellation),
}

#[allow(clippy::large_enum_variant)]
enum GenesisStage {
    AwaitingGenesisThreshold(VecDeque<ElderDuty>),
    ProposingGenesis(GenesisProposal),
    AccumulatingGenesis(GenesisAccumulation),
}

/// Node duties are those that all nodes
/// carry out. (TBD: adjust for Infant level, which might be doing nothing now).
/// Within the duty level, there are then additional
/// duties to be carried out, depending on the level.
pub struct NodeDuties {
    node_info: NodeInfo,
    stage: Stage,
    network_events: NetworkEvents,
    messaging: Messaging,
    network_api: Network,
}

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
impl NodeDuties {
    pub async fn new(node_info: NodeInfo, network_api: Network) -> Result<Self> {
        let state = NodeState::Infant(network_api.public_key().await);
        let msg_analysis = ReceivedMsgAnalysis::new(state);
        let network_events = NetworkEvents::new(msg_analysis);
        let messaging = Messaging::new(network_api.clone());
        Ok(Self {
            node_info,
            stage: Stage::Infant,
            network_events,
            messaging,
            network_api,
        })
    }

    pub async fn process(&mut self, duty: NetworkDuty) -> Result<NetworkDuties> {
        if self.network_api.is_elder().await {
            info!("Processing op: {:?}", duty);
        }
        use NetworkDuty::*;
        match duty {
            RunAsAdult(duty) => {
                if let Some(duties) = self.adult_duties() {
                    duties.process_adult_duty(duty).await
                } else {
                    Err(Error::Logic("Currently not an Adult".to_string()))
                }
            }
            RunAsElder(duty) => {
                if let Some(duties) = self.elder_duties_mut() {
                    duties.process_elder_duty(duty).await
                } else {
                    Err(Error::Logic("Currently not an Elder".to_string()))
                }
            }
            RunAsNode(duty) => self.process_node_duty(duty).await,
            NoOp => Ok(vec![]),
        }
    }

    pub fn adult_duties(&mut self) -> Option<&mut AdultDuties> {
        use Stage::*;
        match &mut self.stage {
            Adult(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn elder_duties(&self) -> Option<&ElderDuties> {
        match &self.stage {
            Stage::Elder(ref elder) => Some(elder.duties()),
            _ => None,
        }
    }

    pub fn elder_duties_mut(&mut self) -> Option<&mut ElderDuties> {
        match &mut self.stage {
            Stage::Elder(ref mut elder) => Some(elder.duties_mut()),
            _ => None,
        }
    }

    fn node_state(&mut self) -> Result<NodeState> {
        Ok(match self.elder_duties() {
            Some(duties) => NodeState::Elder(duties.state().clone()),
            None => match self.adult_duties() {
                Some(duties) => NodeState::Adult(duties.state().clone()),
                None => {
                    return Err(Error::InvalidOperation(
                        "match self.adult_duties() is None".to_string(),
                    ))
                }
            },
        })
    }

    async fn process_node_duty(&mut self, duty: NodeDuty) -> Result<NetworkDuties> {
        use NodeDuty::*;
        //info!("Processing Node duty: {:?}", duty);
        match duty {
            GetWalletReplicas {
                wallet,
                msg_id,
                origin,
            } => self.get_wallet_replicas(wallet, msg_id, origin).await,
            InformNewElders => self.inform_new_elders().await,
            AssumeAdultDuties => self.assume_adult_duties().await,
            BeginFormingGenesisSection => self.begin_forming_genesis_section().await,
            CompleteTransitionToElder {
                section_wallet,
                node_rewards,
                user_wallets,
            } => {
                self.complete_transition_to_elder(section_wallet, node_rewards, user_wallets, None)
                    .await
            }
            ReceiveGenesisProposal { credit, sig } => {
                self.receive_genesis_proposal(credit, sig).await
            }
            ReceiveGenesisAccumulation { signed_credit, sig } => {
                self.receive_genesis_accumulation(signed_credit, sig).await
            }
            InitiateElderChange {
                prefix,
                key,
                sibling_key,
                ..
            } => self.initiate_elder_change(prefix, key, sibling_key).await,
            CompleteElderChange {
                previous_key,
                new_key,
            } => self.complete_elder_change(previous_key, new_key).await,
            ProcessMessaging(duty) => self.messaging.process_messaging_duty(duty).await,
            ProcessNetworkEvent(event) => {
                self.network_events
                    .process_network_event(event, &self.network_api)
                    .await
            }
            NoOp => Ok(vec![]),
            StorageFull => self.notify_section_of_our_storage().await,
        }
    }

    async fn get_wallet_replicas(
        &self,
        wallet: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NetworkDuties> {
        let replicas = self.network_api.public_key_set().await?;
        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeQueryResponse {
                response: NodeQueryResponse::Transfers(
                    NodeTransferQueryResponse::GetWalletReplicas(replicas),
                ),
                correlation_id: msg_id,
                id: MessageId::in_response_to(&msg_id),
                query_origin: origin,
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: origin.to_dst(),
            aggregation: Aggregation::AtDestination,
        })))
    }

    async fn inform_new_elders(&mut self) -> Result<NetworkDuties> {
        let duties = self
            .elder_duties()
            .ok_or_else(|| Error::Logic("Only valid on Elders".to_string()))?;

        let peers = self.network_api.our_prefix().await.name();
        let section_key = self
            .network_api
            .section_public_key()
            .await
            .ok_or_else(|| Error::Logic("Section public key is missing".to_string()))?;

        let msg_id = MessageId::combine(vec![peers, section_key.into()]);

        let section_wallet = duties.section_wallet();
        let node_rewards = duties.node_rewards();
        let user_wallets = duties.user_wallets();

        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeEvent {
                event: NodeEvent::PromotedToElder {
                    section_wallet,
                    node_rewards,
                    user_wallets,
                },
                correlation_id: msg_id,
                id: MessageId::in_response_to(&msg_id),
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an event..
            dst: DstLocation::Section(peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
            aggregation: Aggregation::AtDestination,
        })))
    }

    async fn notify_section_of_our_storage(&mut self) -> Result<NetworkDuties> {
        let node_id = PublicKey::from(self.network_api.public_key().await);
        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::StorageFull {
                    section: node_id.into(),
                    node_id,
                }),
                id: MessageId::new(),
                target_section_pk: None,
            },
            section_source: false, // sent as single node
            dst: DstLocation::Section(node_id.into()),
            aggregation: Aggregation::None,
        })))
    }

    async fn assume_adult_duties(&mut self) -> Result<NetworkDuties> {
        if matches!(self.stage, Stage::Adult(_)) {
            return Ok(vec![]);
        }
        info!("Assuming Adult duties..");
        let state = AdultState::new(self.network_api.clone()).await?;
        let duties = AdultDuties::new(&self.node_info, state.clone()).await?;
        self.node_info.used_space.reset().await;
        self.stage = Stage::Adult(duties);
        self.network_events = NetworkEvents::new(ReceivedMsgAnalysis::new(NodeState::Adult(state)));
        info!("Adult duties assumed.");
        // NB: This is wrong, shouldn't write to disk here,
        // let it be upper layer resp.
        // Also, "Error-to-Unit" is not a good conversion..
        //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());

        let is_genesis_section = self.network_api.our_prefix().await.is_empty();
        let elder_count = self.network_api.our_elder_names().await.len();
        let section_chain_len = self.network_api.section_chain().await.len();

        let genesis_stage = is_genesis_section
            && elder_count < GENESIS_ELDER_COUNT
            && section_chain_len <= GENESIS_ELDER_COUNT;

        if !genesis_stage {
            self.register_wallet().await
        } else {
            Ok(vec![])
        }
    }

    async fn register_wallet(&self) -> Result<NetworkDuties> {
        let address = self.network_api.our_prefix().await.name();
        info!("Registering wallet: {}", self.node_info.reward_key);
        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(self.node_info.reward_key)),
                id: MessageId::new(),
                target_section_pk: None,
            },
            section_source: false, // sent as single node
            dst: DstLocation::Section(address),
            aggregation: Aggregation::None,
        })))
    }

    async fn begin_forming_genesis_section(&mut self) -> Result<NetworkDuties> {
        if matches!(self.stage, Stage::Elder(_))
            //|| matches!(self.stage, Stage::AssumingElderDuties { .. })
            || matches!(self.stage, Stage::Genesis(AwaitingGenesisThreshold(_)))
        {
            return Ok(vec![]);
        } else if !self.node_info.genesis && matches!(self.stage, Stage::Infant) {
            return Err(Error::InvalidOperation(
                "only genesis node can transition to Elder as Infant".to_string(),
            ));
        }

        let is_genesis_section = self.network_api.our_prefix().await.is_empty();
        let elder_count = self.network_api.our_elder_names().await.len();
        let section_chain_len = self.network_api.section_chain().await.len();
        // debug!(
        //     "begin_transition_to_elder. is_genesis_section: {}, elder_count: {}, section_chain_len: {}",
        //     is_genesis_section, elder_count, section_chain_len
        // );
        if is_genesis_section
            && elder_count == GENESIS_ELDER_COUNT
            && matches!(self.stage, Stage::Adult(_))
            && section_chain_len <= GENESIS_ELDER_COUNT
        {
            // this is the case when we are the GENESIS_ELDER_COUNT-th Elder!
            debug!("threshold reached; proposing genesis!");

            let elder_state = ElderState::new(self.network_api.clone()).await?;
            let genesis_balance = u32::MAX as u64 * 1_000_000_000;
            let credit = Credit {
                id: Default::default(),
                amount: Token::from_nano(genesis_balance),
                recipient: elder_state.section_public_key(),
                msg: "genesis".to_string(),
            };
            let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
            let credit_sig_share = elder_state.sign_as_elder(&credit).await?;
            let _ = signatures.insert(credit_sig_share.index, credit_sig_share.share.clone());

            self.stage = Stage::Genesis(ProposingGenesis(GenesisProposal {
                elder_state: elder_state.clone(),
                proposal: credit.clone(),
                signatures,
                pending_agreement: None,
                queued_ops: VecDeque::new(),
            }));

            let dst = DstLocation::Section(credit.recipient.into());
            return Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                        credit,
                        sig: credit_sig_share,
                    }),
                    id: MessageId::new(),
                    target_section_pk: None,
                },
                dst,
                section_source: false, // sent as single node
                aggregation: Aggregation::None,
            })));
        } else if is_genesis_section
            && elder_count < GENESIS_ELDER_COUNT
            && section_chain_len <= GENESIS_ELDER_COUNT
        {
            debug!("AwaitingGenesisThreshold!");
            self.stage = Stage::Genesis(AwaitingGenesisThreshold(VecDeque::new()));
            return Ok(vec![]);
        } else {
            Err(Error::InvalidOperation(
                "Only for genesis formation".to_string(),
            ))
        }

        // trace!("Beginning transition to Elder duties.");
        // let state = ElderState::new(self.network_api.clone()).await?;
        // let our_section = DstLocation::Section(state.prefix().name());
        // // must get the above wrapping instance before overwriting stage
        // self.stage =
        //     Stage::AssumingElderDuties(ElderDuties::pre_elder(&self.node_info, state).await?);
        // // queries the other Elders for the section wallet history
        // // NB: we most likely will get the wallet of the constellation as it was before we joined
        // return Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
        //     msg: Message::NodeQuery {
        //         query: NodeQuery::Rewards(NodeRewardQuery::GetSectionWalletHistory),
        //         id: MessageId::new(),
        //         target_section_pk: None,
        //     },
        //     section_source: false, // sent as single node
        //     dst: our_section,
        //     aggregation: Aggregation::None,
        // })));
    }

    /// Wallet info of our constellation is supplied here
    async fn complete_transition_to_elder(
        &mut self,
        section_wallet: WalletInfo,
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
        genesis: Option<TransferPropagated>,
    ) -> Result<NetworkDuties> {
        debug!(">>>>>>>>>>> Completing transition to elder!!!");
        debug!("????");

        match &mut self.stage {
            Stage::Elder(_) => {
                debug!("was already elder");
                return Ok(vec![])
            },
            Stage::Infant => {
                if !self.node_info.genesis {
                    return Err(Error::InvalidOperation("cannot complete transition to elder as Infant".to_string()));
                }
            }
            // consider accepting the completion for these as well..
            Stage::Genesis(AwaitingGenesisThreshold(_)) | Stage::Genesis(ProposingGenesis(_)) => {
                return Err(Error::InvalidOperation("cannot complete transition to elder as AwaitingGenesisThreshold | ProposingGenesis".to_string()))
            }
            Stage::Genesis(AccumulatingGenesis(_)) | Stage::Adult(_) => (),
        };

        trace!(">>> Setting stage to Elder..");

        //let mut ops: NetworkDuties = vec![];
        let elder_state = ElderState::new(self.network_api.clone()).await?;

        let node_id = elder_state.node_name();
        let register_wallet = match node_rewards.get(&node_id) {
            None => true,
            Some(stage) => match stage {
                NodeRewardStage::NewNode | NodeRewardStage::AwaitingActivation(_) => true,
                NodeRewardStage::Active { .. } | NodeRewardStage::AwaitingRelocation(_) => false,
            },
        };

        let mut elder_duties = ElderDuties::new(
            &self.node_info,
            elder_state.clone(),
            ElderData {
                section_wallet,
                node_rewards,
                user_wallets,
            },
        )
        .await?;

        // 1. Initiate genesis if any.
        elder_duties.initiate(genesis).await?;

        // 3. Set new stage
        self.node_info.used_space.reset().await;
        self.stage = Stage::Elder(ElderConstellation::new(
            elder_duties,
            self.network_api.clone(),
        ));

        self.network_events = NetworkEvents::new(ReceivedMsgAnalysis::new(NodeState::Elder(
            elder_state.clone(),
        )));
        // NB: This is wrong, shouldn't write to disk here,
        // let it be upper layer resp.
        // Also, "Error-to-Unit" is not a good conversion..
        //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())

        info!("Successfully assumed Elder duties!");

        if register_wallet {
            self.register_wallet().await
        } else {
            Ok(vec![])
        }

        // // 4. Add own node id to rewards.
        // ops.push(NetworkDuty::from(RewardDuty::ProcessCmd {
        //     cmd: RewardCmd::AddNewNode(node_id),
        //     msg_id: MessageId::new(),
        //     origin: SrcLocation::Node(node_id),
        // }));

        // debug!(">>>>>>>> ALLLLLLLMOST THERE");

        // // 5. Add own wallet to rewards.
        // ops.push(NetworkDuty::from(RewardDuty::ProcessCmd {
        //     cmd: RewardCmd::SetNodeWallet {
        //         node_id,
        //         wallet_id: self.node_info.reward_key,
        //     },
        //     msg_id: MessageId::new(),
        //     origin: SrcLocation::Node(node_id),
        // }));

        //Ok(ops)
    }

    ///
    async fn initiate_elder_change(
        &mut self,
        prefix: sn_routing::Prefix,
        new_section_key: PublicKey,
        sibling_key: Option<PublicKey>,
    ) -> Result<NetworkDuties> {
        match &mut self.stage {
            Stage::Infant | Stage::Genesis(_) => Ok(vec![]),
            Stage::Adult(_old_state) => {
                let state = AdultState::new(self.network_api.clone()).await?;
                let duties = AdultDuties::new(&self.node_info, state).await?;
                self.stage = Stage::Adult(duties);
                Ok(vec![])
            }
            Stage::Elder(elder) => {
                elder
                    .initiate_elder_change(prefix, new_section_key, sibling_key)
                    .await
            }
        }
    }

    ///
    async fn complete_elder_change(
        &mut self,
        previous_key: PublicKey,
        new_key: PublicKey,
    ) -> Result<NetworkDuties> {
        match &mut self.stage {
            Stage::Infant | Stage::Adult(_) | Stage::Genesis(_) => Ok(vec![]), // Should be unreachable
            Stage::Elder(elder) => {
                elder
                    .complete_elder_change(&self.node_info, previous_key, new_key)
                    .await
            }
        }
    }

    // TODO: validate the credit...
    async fn receive_genesis_proposal(
        &mut self,
        credit: Credit,
        sig: SignatureShare,
    ) -> Result<NetworkDuties> {
        if matches!(self.stage, Stage::Genesis(AccumulatingGenesis(_)))
            || matches!(self.stage, Stage::Elder(_))
        {
            return Ok(vec![]);
        }

        let (stage, cmd) = match self.stage {
            Stage::Genesis(AwaitingGenesisThreshold(ref mut queued_ops)) => {
                let elder_state = ElderState::new(self.network_api.clone()).await?;

                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let _ = signatures.insert(sig.index, sig.share);

                let credit_sig_share = elder_state.sign_as_elder(&credit).await?;
                let _ = signatures.insert(credit_sig_share.index, credit_sig_share.share.clone());

                let dst = DstLocation::Section(elder_state.section_public_key().into());
                let stage = Stage::Genesis(ProposingGenesis(GenesisProposal {
                    elder_state,
                    proposal: credit.clone(),
                    signatures,
                    pending_agreement: None,
                    queued_ops: queued_ops.drain(..).collect(),
                }));
                let cmd = NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                            credit,
                            sig: credit_sig_share,
                        }),
                        id: MessageId::new(),
                        target_section_pk: None,
                    },
                    section_source: false, // sent as single node
                    dst,
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                });

                (stage, cmd)
            }
            Stage::Genesis(ProposingGenesis(ref mut bootstrap)) => {
                debug!("Adding incoming genesis proposal.");
                bootstrap.add(sig)?;
                if let Some(signed_credit) = &bootstrap.pending_agreement {
                    // replicas signatures over > signed_credit <
                    let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                    let credit_sig_share =
                        bootstrap.elder_state.sign_as_elder(&signed_credit).await?;
                    let _ =
                        signatures.insert(credit_sig_share.index, credit_sig_share.share.clone());

                    let stage = Stage::Genesis(AccumulatingGenesis(GenesisAccumulation {
                        elder_state: bootstrap.elder_state.clone(),
                        agreed_proposal: signed_credit.clone(),
                        signatures,
                        pending_agreement: None,
                        queued_ops: bootstrap.queued_ops.drain(..).collect(),
                    }));

                    let cmd = NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::NodeCmd {
                            cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis {
                                signed_credit: signed_credit.clone(),
                                sig: credit_sig_share,
                            }),
                            id: MessageId::new(),
                            target_section_pk: None,
                        },
                        section_source: false, // sent as single node
                        dst: DstLocation::Section(
                            bootstrap.elder_state.section_public_key().into(),
                        ),
                        aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                    });

                    (stage, cmd)
                } else {
                    return Ok(vec![]);
                }
            }
            _ => {
                return Err(Error::InvalidOperation(
                    "invalid self.stage at fn receive_genesis_proposal".to_string(),
                ))
            }
        };

        self.stage = stage;

        Ok(NetworkDuties::from(cmd))
    }

    async fn receive_genesis_accumulation(
        &mut self,
        signed_credit: SignedCredit,
        sig: SignatureShare,
    ) -> Result<NetworkDuties> {
        if matches!(self.stage, Stage::Elder(_)) {
            return Ok(vec![]);
        }

        match self.stage {
            Stage::Genesis(ProposingGenesis(ref mut bootstrap)) => {
                // replicas signatures over > signed_credit <
                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let _ = signatures.insert(sig.index, sig.share);

                let credit_sig_share = bootstrap.elder_state.sign_as_elder(&signed_credit).await?;
                let _ = signatures.insert(credit_sig_share.index, credit_sig_share.share);

                self.stage = Stage::Genesis(AccumulatingGenesis(GenesisAccumulation {
                    elder_state: bootstrap.elder_state.clone(),
                    agreed_proposal: signed_credit,
                    signatures,
                    pending_agreement: None,
                    queued_ops: bootstrap.queued_ops.drain(..).collect(),
                }));
                Ok(vec![])
            }
            Stage::Genesis(AccumulatingGenesis(ref mut bootstrap)) => {
                bootstrap.add(sig)?;
                if let Some(genesis) = bootstrap.pending_agreement.take() {
                    // TODO: do not take this? (in case of fail further blow)
                    let credit_sig_share = bootstrap.elder_state.sign_as_elder(&genesis).await?;
                    let _ = bootstrap
                        .signatures
                        .insert(credit_sig_share.index, credit_sig_share.share.clone());

                    let genesis = TransferPropagated {
                        credit_proof: genesis.clone(),
                    };

                    debug!(">>>>>>>>>>>>>>>>>>>>>>>>. GENSIS AGREEMENT PROOFED");
                    return self
                        .complete_transition_to_elder(
                            WalletInfo {
                                replicas: genesis.credit_proof.debiting_replicas_keys.clone(),
                                history: ActorHistory {
                                    credits: vec![genesis.credit_proof.clone()],
                                    debits: vec![],
                                },
                            },
                            Default::default(),
                            Default::default(),
                            Some(genesis),
                        )
                        .await;
                }
                Ok(vec![])
            }
            _ => Err(Error::InvalidOperation(
                "invalid self.stage at fn receive_genesis_accumulation".to_string(),
            )),
        }
    }
}
