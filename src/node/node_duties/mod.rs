// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod elder_constellation;
pub mod messaging;
mod msg_analysis;
mod network_events;

use self::elder_constellation::ElderConstellation;
use crate::{
    node::{
        adult_duties::AdultDuties,
        elder_duties::ElderDuties,
        node_duties::messaging::Messaging,
        node_ops::{
            ElderDuty, NetworkDuties, NetworkDuty, NodeDuty, OutgoingMsg, RewardCmd, RewardDuty,
        },
        NodeInfo,
    },
    AdultState, ElderState, Error, Network, NodeState, Result,
};
use log::{debug, info, trace};
use msg_analysis::ReceivedMsgAnalysis;
use network_events::NetworkEvents;
use sn_data_types::{
    ActorHistory, Credit, CreditAgreementProof, PublicKey, SignatureShare, SignedCredit, Token,
    TransferPropagated, WalletInfo,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, NodeRewardQuery, NodeSystemCmd},
    DstLocation, MessageId, SrcLocation,
};
use std::collections::{BTreeMap, VecDeque};

use super::node_ops::NodeMessagingDuty;

const GENESIS_ELDER_COUNT: usize = 5;

#[allow(clippy::large_enum_variant)]
pub enum Stage {
    Infant,
    Adult(AdultDuties),
    AssumingElderDuties(VecDeque<ElderDuty>),
    AwaitingGenesisThreshold(VecDeque<ElderDuty>),
    ProposingGenesis(GenesisProposal),
    AccumulatingGenesis(GenesisAccumulation),
    Elder(ElderConstellation),
}

pub struct GenesisProposal {
    elder_state: ElderState,
    proposal: Credit,
    signatures: BTreeMap<usize, bls::SignatureShare>,
    pending_agreement: Option<SignedCredit>,
    queued_ops: VecDeque<ElderDuty>,
}

pub struct GenesisAccumulation {
    elder_state: ElderState,
    agreed_proposal: SignedCredit,
    signatures: BTreeMap<usize, bls::SignatureShare>,
    pending_agreement: Option<CreditAgreementProof>,
    queued_ops: VecDeque<ElderDuty>,
}

impl GenesisProposal {
    fn add(&mut self, sig: SignatureShare) -> Result<()> {
        let _ = self.signatures.insert(sig.index, sig.share);
        let min_count = 1 + self.elder_state.public_key_set().threshold();
        if self.signatures.len() >= min_count {
            info!("Aggregating actor signature..");

            // Combine shares to produce the main signature.
            let actor_signature = sn_data_types::Signature::Bls(
                self.elder_state
                    .public_key_set()
                    .combine_signatures(&self.signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            let signed_credit = SignedCredit {
                credit: self.proposal.clone(),
                actor_signature,
            };

            self.pending_agreement = Some(signed_credit);
        }

        Ok(())
    }
}

impl GenesisAccumulation {
    fn add(&mut self, sig: SignatureShare) -> Result<()> {
        let _ = self.signatures.insert(sig.index, sig.share);
        let min_count = 1 + self.elder_state.public_key_set().threshold();
        if self.signatures.len() >= min_count {
            info!("Aggregating replica signature..");
            // Combine shares to produce the main signature.
            let debiting_replicas_sig = sn_data_types::Signature::Bls(
                self.elder_state
                    .public_key_set()
                    .combine_signatures(&self.signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            self.pending_agreement = Some(CreditAgreementProof {
                signed_credit: self.agreed_proposal.clone(),
                debiting_replicas_sig,
                debiting_replicas_keys: self.elder_state.public_key_set().clone(),
            });
        }

        Ok(())
    }
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

    pub fn adult_duties(&mut self) -> Option<&mut AdultDuties> {
        use Stage::*;
        match &mut self.stage {
            Adult(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn elder_duties(&mut self) -> Option<&mut ElderDuties> {
        match &mut self.stage {
            Stage::Elder(ref mut elder) => Some(elder.duties()),
            _ => None,
        }
    }

    pub fn try_enqueue_elder_duty(&mut self, duty: ElderDuty) -> bool {
        match self.stage {
            Stage::AssumingElderDuties(ref mut queue)
            | Stage::AwaitingGenesisThreshold(ref mut queue) => {
                queue.push_back(duty);
                true
            }
            Stage::ProposingGenesis(ref mut bootstrap) => {
                bootstrap.queued_ops.push_back(duty);
                true
            }
            Stage::AccumulatingGenesis(ref mut bootstrap) => {
                bootstrap.queued_ops.push_back(duty);
                true
            }
            _ => false,
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

    pub async fn process_node_duty(&mut self, duty: NodeDuty) -> Result<NetworkDuties> {
        use NodeDuty::*;
        info!("Processing Node duty: {:?}", duty);
        match duty {
            RegisterWallet(wallet) => self.register_wallet(wallet).await,
            AssumeAdultDuties => self.assume_adult_duties().await,
            AssumeElderDuties => self.begin_transition_to_elder().await,
            ReceiveGenesisProposal { credit, sig } => {
                self.receive_genesis_proposal(credit, sig).await
            }
            ReceiveGenesisAccumulation { signed_credit, sig } => {
                self.receive_genesis_accumulation(signed_credit, sig).await
            }
            InitiateElderChange { prefix, key, .. } => {
                self.initiate_elder_change(prefix, key).await
            }
            FinishElderChange {
                previous_key,
                new_key,
            } => self.finish_elder_change(previous_key, new_key).await,
            InitSectionWallet(wallet_info) => {
                self.finish_transition_to_elder(wallet_info, None).await
            }
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

    async fn notify_section_of_our_storage(&mut self) -> Result<NetworkDuties> {
        let node_id = PublicKey::from(self.network_api.public_key().await);
        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::StorageFull {
                    section: node_id.into(),
                    node_id,
                }),
                id: MessageId::new(),
            },
            dst: DstLocation::Section(node_id.into()),
            to_be_aggregated: false,
        })))
    }

    async fn register_wallet(&mut self, wallet: PublicKey) -> Result<NetworkDuties> {
        let node_state = self.node_state()?;
        info!("Registering wallet: {}", wallet);
        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet {
                    wallet,
                    section: PublicKey::Ed25519(node_state.node_id()).into(),
                }),
                id: MessageId::new(),
            },
            dst: DstLocation::Section(wallet.into()),
            to_be_aggregated: false,
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
        Ok(NodeDuty::RegisterWallet(self.node_info.reward_key).into())
    }

    async fn begin_transition_to_elder(&mut self) -> Result<NetworkDuties> {
        if matches!(self.stage, Stage::Elder(_))
            || matches!(self.stage, Stage::AssumingElderDuties(_))
            || matches!(self.stage, Stage::AwaitingGenesisThreshold(_))
        {
            return Ok(vec![]);
        } else if !self.node_info.genesis && matches!(self.stage, Stage::Infant) {
            return Err(Error::InvalidOperation(
                "only genesis node can transition to Elder as Infant".to_string(),
            ));
        }

        let is_genesis_section = self.network_api.our_prefix().await.is_empty();
        let elder_count = self.network_api.our_elder_names().await.len();
        debug!(
            "begin_transition_to_elder. is_genesis_section: {}, elder_count: {}",
            is_genesis_section, elder_count
        );
        if is_genesis_section
            && elder_count == GENESIS_ELDER_COUNT
            && matches!(self.stage, Stage::Adult(_))
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

            self.stage = Stage::ProposingGenesis(GenesisProposal {
                elder_state: elder_state.clone(),
                proposal: credit.clone(),
                signatures,
                pending_agreement: None,
                queued_ops: VecDeque::new(),
            });

            let dst = DstLocation::Section(credit.recipient.into());
            return Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                        credit,
                        sig: credit_sig_share,
                    }),
                    id: MessageId::new(),
                },
                dst,
                to_be_aggregated: false,
            })));
        } else if is_genesis_section && elder_count < GENESIS_ELDER_COUNT {
            debug!("AwaitingGenesisThreshold!");
            self.stage = Stage::AwaitingGenesisThreshold(VecDeque::new());
            return Ok(vec![]);
        }

        debug!("Beginning normal transition to Elder.");

        if let Some(wallet_id) = self.network_api.section_public_key().await {
            trace!("Beginning transition to Elder duties.");
            // must get the above wrapping instance before overwriting stage
            self.stage = Stage::AssumingElderDuties(VecDeque::new());
            // queries the other Elders for the section wallet history
            return Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::NodeQuery {
                    query: NodeQuery::Rewards(NodeRewardQuery::GetSectionWalletHistory),
                    id: MessageId::new(),
                },
                dst: DstLocation::Section(wallet_id.into()),
                to_be_aggregated: false,
            })));
        }

        Ok(vec![])
    }

    // TODO: validate the credit...
    async fn receive_genesis_proposal(
        &mut self,
        credit: Credit,
        sig: SignatureShare,
    ) -> Result<NetworkDuties> {
        if matches!(self.stage, Stage::AccumulatingGenesis(_))
            || matches!(self.stage, Stage::Elder(_))
        {
            return Ok(vec![]);
        }

        let (stage, cmd) = match self.stage {
            Stage::AwaitingGenesisThreshold(ref mut queued_ops) => {
                let elder_state = ElderState::new(self.network_api.clone()).await?;

                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let _ = signatures.insert(sig.index, sig.share);

                let credit_sig_share = elder_state.sign_as_elder(&credit).await?;
                let _ = signatures.insert(credit_sig_share.index, credit_sig_share.share.clone());

                let dst = DstLocation::Section(elder_state.section_public_key().into());
                let stage = Stage::ProposingGenesis(GenesisProposal {
                    elder_state,
                    proposal: credit.clone(),
                    signatures,
                    pending_agreement: None,
                    queued_ops: queued_ops.drain(..).collect(),
                });
                let cmd = NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                            credit,
                            sig: credit_sig_share,
                        }),
                        id: MessageId::new(),
                    },
                    dst,
                    to_be_aggregated: false,
                });

                (stage, cmd)
            }
            Stage::ProposingGenesis(ref mut bootstrap) => {
                debug!("Adding incoming genesis proposal.");
                let _ = bootstrap.add(sig)?;
                if let Some(signed_credit) = &bootstrap.pending_agreement {
                    // replicas signatures over > signed_credit <
                    let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                    let credit_sig_share =
                        bootstrap.elder_state.sign_as_elder(&signed_credit).await?;
                    let _ =
                        signatures.insert(credit_sig_share.index, credit_sig_share.share.clone());

                    let stage = Stage::AccumulatingGenesis(GenesisAccumulation {
                        elder_state: bootstrap.elder_state.clone(),
                        agreed_proposal: signed_credit.clone(),
                        signatures,
                        pending_agreement: None,
                        queued_ops: bootstrap.queued_ops.drain(..).collect(),
                    });

                    let cmd = NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::NodeCmd {
                            cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis {
                                signed_credit: signed_credit.clone(),
                                sig: credit_sig_share,
                            }),
                            id: MessageId::new(),
                        },
                        dst: DstLocation::Section(
                            bootstrap.elder_state.section_public_key().into(),
                        ),
                        to_be_aggregated: false,
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
            Stage::ProposingGenesis(ref mut bootstrap) => {
                // replicas signatures over > signed_credit <
                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let _ = signatures.insert(sig.index, sig.share);

                let credit_sig_share = bootstrap.elder_state.sign_as_elder(&signed_credit).await?;
                let _ = signatures.insert(credit_sig_share.index, credit_sig_share.share);

                self.stage = Stage::AccumulatingGenesis(GenesisAccumulation {
                    elder_state: bootstrap.elder_state.clone(),
                    agreed_proposal: signed_credit,
                    signatures,
                    pending_agreement: None,
                    queued_ops: bootstrap.queued_ops.drain(..).collect(),
                });
                Ok(vec![])
            }
            Stage::AccumulatingGenesis(ref mut bootstrap) => {
                let _ = bootstrap.add(sig)?;
                if let Some(genesis) = bootstrap.pending_agreement.take() {
                    // TODO: do not take this? (in case of fail further blow)
                    let credit_sig_share = bootstrap.elder_state.sign_as_elder(&genesis).await?;
                    let _ = bootstrap
                        .signatures
                        .insert(credit_sig_share.index, credit_sig_share.share.clone());

                    let genesis = TransferPropagated {
                        credit_proof: genesis.clone(),
                        //crediting_replica_sig: credit_sig_share,
                        //crediting_replica_keys: bootstrap.elder_state.section_public_key(),
                    };
                    return self
                        .finish_transition_to_elder(
                            WalletInfo {
                                replicas: genesis.credit_proof.debiting_replicas_keys.clone(),
                                history: ActorHistory {
                                    credits: vec![genesis.credit_proof.clone()],
                                    debits: vec![],
                                },
                            },
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

    async fn finish_transition_to_elder(
        &mut self,
        wallet_info: WalletInfo,
        genesis: Option<TransferPropagated>,
    ) -> Result<NetworkDuties> {
        let queued_duties = &mut VecDeque::new();
        let queued_duties = match self.stage {
            Stage::Elder(_) => return Ok(vec![]),
            Stage::Infant => {
                if self.node_info.genesis {
                    queued_duties
                } else {
                    return Err(Error::InvalidOperation("cannot finish_transition_to_elder as Infant".to_string()));
                }
            }
            Stage::Adult(_) | Stage::AwaitingGenesisThreshold(_) | Stage::ProposingGenesis(_) => {
                return Err(Error::InvalidOperation("cannot finish_transition_to_elder as Adult | AwaitingGenesisThreshold | ProposingGenesis".to_string()))
            }
            Stage::AccumulatingGenesis(ref mut bootstrap) => &mut bootstrap.queued_ops,
            Stage::AssumingElderDuties(ref mut queue) => queue,
        };

        trace!("Finishing transition to Elder..");

        let mut ops: NetworkDuties = vec![];
        let state = ElderState::new(self.network_api.clone()).await?;
        let mut duties = ElderDuties::new(wallet_info, &self.node_info, state.clone()).await?;

        // 1. Initiate duties.
        ops.extend(duties.initiate(genesis).await?);

        // 2. Process all enqueued duties.
        for duty in queued_duties.drain(..) {
            debug!("queued duty: {:?}", duty);
            ops.extend(duties.process_elder_duty(duty).await?);
        }

        // 3. Set new stage
        self.node_info.used_space.reset().await;
        self.stage = Stage::Elder(ElderConstellation::new(duties, self.network_api.clone()));
        self.network_events =
            NetworkEvents::new(ReceivedMsgAnalysis::new(NodeState::Elder(state.clone())));
        // NB: This is wrong, shouldn't write to disk here,
        // let it be upper layer resp.
        // Also, "Error-to-Unit" is not a good conversion..
        //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())

        info!("Successfully assumed Elder duties!");

        let node_id = state.node_name();

        // 4. Add own node id to rewards.
        ops.push(NetworkDuty::from(RewardDuty::ProcessCmd {
            cmd: RewardCmd::AddNewNode(node_id),
            msg_id: MessageId::new(),
            origin: SrcLocation::Node(node_id),
        }));

        // 5. Add own wallet to rewards.
        ops.push(NetworkDuty::from(RewardDuty::ProcessCmd {
            cmd: RewardCmd::SetNodeWallet {
                node_id,
                wallet_id: self.node_info.reward_key,
            },
            msg_id: MessageId::new(),
            origin: SrcLocation::Node(node_id),
        }));

        Ok(ops)
    }

    ///
    async fn initiate_elder_change(
        &mut self,
        prefix: sn_routing::Prefix,
        new_section_key: PublicKey,
    ) -> Result<NetworkDuties> {
        match &mut self.stage {
            Stage::Infant => Ok(vec![]),
            Stage::AssumingElderDuties(_) => Ok(vec![]), // TODO: Queue up (or something?)!!
            Stage::AwaitingGenesisThreshold(_) => Ok(vec![]),
            Stage::ProposingGenesis(_) => Ok(vec![]), // TODO: Queue up (or something?)!!
            Stage::AccumulatingGenesis(_) => Ok(vec![]), // TODO: Queue up (or something?)!!
            Stage::Adult(_old_state) => {
                let state = AdultState::new(self.network_api.clone()).await?;
                let duties = AdultDuties::new(&self.node_info, state).await?;
                self.stage = Stage::Adult(duties);
                Ok(vec![])
            }
            Stage::Elder(elder) => elder.initiate_elder_change(prefix, new_section_key).await,
        }
    }

    ///
    pub async fn finish_elder_change(
        &mut self,
        previous_key: PublicKey,
        new_key: PublicKey,
    ) -> Result<NetworkDuties> {
        match &mut self.stage {
            Stage::AwaitingGenesisThreshold(_) => Ok(vec![]),
            Stage::ProposingGenesis(_) => Ok(vec![]),
            Stage::AccumulatingGenesis(_) => Ok(vec![]),
            Stage::AssumingElderDuties(_) => Ok(vec![]), // Should be unreachable?
            Stage::Infant | Stage::Adult(_) => Ok(vec![]),
            Stage::Elder(elder) => {
                elder
                    .finish_elder_change(&self.node_info, previous_key, new_key)
                    .await
            }
        }
    }
}
