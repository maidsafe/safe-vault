// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::validator::Validator;
use crate::{
    node::{
        elder_duties::data_section::ElderSigning,
        node_ops::{NetworkDuties, NetworkDuty, NodeDuty, NodeMessagingDuty, OutgoingMsg},
    },
    ElderState, Error, Result,
};
use bls::PublicKeySet;
use log::{debug, info};
use sn_data_types::{
    ActorHistory, CreditAgreementProof, PublicKey, SignedTransferShare, Token, TransferValidated,
    WalletInfo,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, NodeSystemQuery, NodeTransferCmd, NodeTransferQuery},
    Aggregation, DstLocation, MessageId,
};
use sn_transfers::{ActorEvent, TransferActor};
use std::collections::{BTreeSet, VecDeque};
use xor_name::XorName;
use ActorEvent::*;

type SectionActor = TransferActor<Validator, ElderSigning>;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
pub(super) struct SectionFunds {
    actor: SectionActor,
    state: State,
}

#[derive(Clone)]
pub struct Payout {
    pub to: PublicKey,
    pub amount: Token,
    pub node_id: XorName,
}

#[derive(Clone)]
struct State {
    /// Incoming payout requests are queued here.
    /// It is queued when we already have a payout in flight,
    /// or when we are transitioning to a new Actor.
    queued_payouts: VecDeque<Payout>,
    payout_in_flight: Option<Payout>,
    completed: BTreeSet<XorName>, // this set grows within acceptable bounds, since transitions do not happen that often, and at every section split, the set is cleared..
    transition: Transition,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum Transition {
    Regular(TransitionStage),
    Split(SplitStage),
    None,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum TransitionStage {
    Pending(ElderState),
    InTransition(SectionActor),
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum SplitStage {
    Pending {
        next_actor_state: ElderState,
        sibling_key: PublicKey,
    },
    CompletingT1 {
        next_actor: SectionActor,
        t2: T2,
    },
    CompletingT2 {
        next_actor: SectionActor,
        if_t1_was_ours: Option<CreditAgreementProof>,
    },
}

#[derive(Clone)]
struct T2 {
    amount: Token,
    recipient: PublicKey,
}

impl SectionFunds {
    pub fn new(actor: SectionActor) -> Self {
        Self {
            actor,
            state: State {
                queued_payouts: Default::default(),
                payout_in_flight: None,
                completed: Default::default(),
                transition: Transition::None,
            },
        }
    }
    /// Current Replicas
    pub fn replicas(&self) -> PublicKey {
        self.actor.replicas_public_key()
    }

    /// Wallet info
    pub fn wallet_info(&self) -> WalletInfo {
        WalletInfo {
            replicas: self.actor.replicas_key_set(),
            history: self.actor.history(),
        }
    }

    /// Replica history are synched to section actor instances.
    pub async fn synch(&mut self, history: ActorHistory) -> Result<NodeMessagingDuty> {
        info!("Synching replica events to section transfer actor...");
        let event = match self.actor.from_history(history) {
            Ok(event) => Ok(event),
            Err(error) => match error {
                sn_transfers::Error::InvalidActorHistory => Ok(None),
                _ => Err(Error::Transfer(error)),
            },
        }?;

        if let Some(event) = event {
            self.actor.apply(TransfersSynched(event.clone()))?;
            info!("Synched: {:?}", event);
        }
        info!("Section Actor balance: {}", self.actor.balance());
        Ok(NodeMessagingDuty::NoOp)
    }

    /// Wallet transition, step 1.
    /// At Elder churn, we must transition to a new wallet.
    /// We start by querying network for the Replicas of this new wallet.
    pub async fn init_wallet_transition(
        &mut self,
        next_actor_state: ElderState,
        sibling_key: Option<PublicKey>,
    ) -> Result<NodeMessagingDuty> {
        info!(">>> ??? Initiating transition to new section wallet...");
        if !matches!(self.state.transition, Transition::None) {
            info!(">>> ??? has_initiated_transition");
            return Err(Error::Logic("Already initiated transition".to_string()));
        }

        // When we have a payout in flight, we defer the transition.
        if self.has_payout_in_flight() {
            info!(">>> ???? has_payout_in_flight");
            return Err(Error::Logic("Has payout in flight".to_string()));
        }

        let new_wallet = next_actor_state.section_public_key();

        if let Some(sibling_key) = sibling_key {
            self.state.transition = Transition::Split(SplitStage::Pending {
                next_actor_state,
                sibling_key,
            });
        } else {
            self.state.transition = Transition::Regular(TransitionStage::Pending(next_actor_state));
        }

        info!(">>>> ??? sending GetSectionPkSet query!");
        // deterministic msg id for aggregation
        let msg_id = MessageId::combine(vec![self.replicas().into(), new_wallet.into()]);
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeQuery {
                query: NodeQuery::System(NodeSystemQuery::GetSectionPkSet),
                id: msg_id,
                target_section_pk: None,
            },
            section_source: true, // i.e. responses go to our section
            dst: DstLocation::Section(new_wallet.into()),
            aggregation: Aggregation::AtDestination,
        }))
    }

    fn get_actor(replicas: PublicKeySet, elder_state: ElderState) -> Result<SectionActor> {
        let signing = ElderSigning::new(elder_state);
        let actor = TransferActor::from_info(
            signing,
            WalletInfo {
                replicas,
                history: ActorHistory::empty(),
            },
            Validator {},
        )?;
        Ok(actor)
    }

    /// Wallet transition, step 2.
    /// When receiving the wallet info, containing the Replicas of
    /// the new wallet, we can complete the transition by starting
    /// transfers to the new wallets.
    pub async fn complete_wallet_transition(
        &mut self,
        replicas: PublicKeySet,
    ) -> Result<NetworkDuties> {
        info!(">>>>--------------------------");
        info!(">>>>--------------------------");
        info!(">>>>--------------------------");
        info!(">>>>Completing transition of section transfer actor...");
        if self.has_payout_in_flight() {
            info!(">>>> has_payout_in_flight");
            return Err(Error::Logic("Has payout in flight".to_string()));
        }
        info!(">>>> no payout in flight");

        match self.state.transition.clone() {
            Transition::Regular(TransitionStage::Pending(next_actor_state)) => {
                debug!(">>>>> in pending stage");
                let next_actor = Self::get_actor(replicas, next_actor_state)?;
                let our_new_key = next_actor.id();
                // Get all the tokens of current actor.
                let current_balance = self.actor.balance();
                let duty = self.generate_validation(current_balance, our_new_key)?;
                // set next stage of the transition process
                self.state.transition =
                    Transition::Regular(TransitionStage::InTransition(next_actor));
                Ok(NetworkDuties::from(duty))
            }
            Transition::Split(SplitStage::Pending {
                next_actor_state,
                sibling_key,
            }) => {
                debug!(
                    ">>>> Split happening, we need to transfer to TWO wallets; one for each sibling"
                );
                let next_actor = Self::get_actor(replicas, next_actor_state)?;
                let our_new_key = next_actor.id();

                // Get all the tokens of current actor.
                let current_balance = self.actor.balance();
                let half_balance = current_balance.as_nano() / 2;
                let remainder = current_balance.as_nano() % 2;

                debug!(">>>>Creating two transfers; one to each child section");

                // create two transfers; one to each sibling wallet
                let t1_amount = Token::from_nano(half_balance + remainder);
                let t2_amount = Token::from_nano(half_balance);

                // Determine which transfer is first
                // (deterministic order is important for reaching consensus)
                let (t1, t2_recipient) = if our_new_key > sibling_key {
                    let t1 = self.generate_validation(t1_amount, our_new_key)?;
                    (t1, sibling_key.to_owned())
                } else {
                    let t1 = self.generate_validation(t1_amount, sibling_key.to_owned())?;
                    (t1, our_new_key)
                };
                // set next stage of the transition process
                self.state.transition = Transition::Split(SplitStage::CompletingT1 {
                    next_actor,
                    t2: T2 {
                        amount: t2_amount,
                        recipient: t2_recipient,
                    },
                });
                Ok(NetworkDuties::from(t1))
            }
            Transition::Regular(TransitionStage::InTransition(_))
            | Transition::Split(SplitStage::CompletingT1 { .. })
            | Transition::Split(SplitStage::CompletingT2 { .. }) => {
                debug!(">>>>> SOME OTHER STAGE");
                Err(Error::Logic("Undergoing transition already".to_string()))
            }
            Transition::None => {
                debug!(">>>>>>>>> no transition");
                Err(Error::Logic("No transition initiated!".to_string()))
            }
        }
    }

    /// Generates validation
    /// to transfer the tokens from
    /// previous actor to new actor.
    fn generate_validation(
        &mut self,
        amount: Token,
        wallet_id: PublicKey,
    ) -> Result<NodeMessagingDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;

        match self.actor.transfer(
            amount,
            wallet_id,
            format!("Section Actor transition to new wallet: {}", wallet_id),
        )? {
            None => Ok(NodeMessagingDuty::NoOp), // Would indicate that this apparently has already been done, so no change.
            Some(event) => {
                info!(
                    ">>>> Section actor transition transfer is being requested of the replicas.."
                );
                self.apply(TransferInitiated(event.clone()))?;

                info!(">>>> !!!!!! TRANSFER APPLIED TO SELF, event {:?}", event);
                // We ask of our Replicas to validate this transfer.
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(SignedTransferShare::new(
                            event.signed_debit.as_share()?,
                            event.signed_credit.as_share()?,
                            self.actor.owner().public_key_set()?,
                        )?)),
                        id: MessageId::new(),
                        target_section_pk: None,
                    },
                    section_source: false,
                    dst: DstLocation::Section(self.actor.id().into()),
                    aggregation: Aggregation::None,
                }))
            }
        }
    }

    /// Will validate and sign the payout, and ask of the replicas to
    /// do the same, and await their responses as to accumulate the result.
    pub async fn initiate_reward_payout(&mut self, payout: Payout) -> Result<NodeMessagingDuty> {
        if self.state.completed.contains(&payout.node_id) {
            return Ok(NodeMessagingDuty::NoOp);
        }
        // if we are transitioning, or having payout in flight, the payout is deferred.
        if self.has_payout_in_flight() || !matches!(self.state.transition, Transition::None) {
            self.state.queued_payouts.push_back(payout);
            return Ok(NodeMessagingDuty::NoOp);
        }

        use NodeCmd::*;
        use NodeTransferCmd::*;
        // We try initiate the transfer..
        match self.actor.transfer(
            payout.amount,
            payout.to,
            format!("Reward for node id: {}", payout.node_id),
        )? {
            None => Ok(NodeMessagingDuty::NoOp), // Would indicate that this apparently has already been done, so no change.
            Some(event) => {
                self.apply(TransferInitiated(event.clone()))?;
                // We now have a payout in flight.
                self.state.payout_in_flight = Some(payout);
                // We ask of our Replicas to validate this transfer.
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(SignedTransferShare::new(
                            event.signed_debit.as_share()?,
                            event.signed_credit.as_share()?,
                            self.actor.owner().public_key_set()?,
                        )?)),
                        id: MessageId::new(),
                        target_section_pk: None,
                    },
                    section_source: false,
                    dst: DstLocation::Section(self.actor.id().into()),
                    aggregation: Aggregation::None,
                }))
            }
        }
    }

    fn move_to_next(
        &mut self,
        next_actor: SectionActor,
        proof: CreditAgreementProof,
    ) -> Result<NetworkDuties> {
        if proof.recipient() != next_actor.id() {
            return Err(Error::Logic("Invalid recipient for transition".to_string()));
        }

        // Set the next actor to be our current.
        self.actor = next_actor;

        // Credit the transfer to the new actor.
        let history = ActorHistory {
            credits: vec![proof],
            debits: vec![],
        };

        // if this errors with nothing to synch, that certainly
        // _is_ an error (a bug), since the history is populated above
        if let Some(event) = self
            .actor
            .from_history(history.clone())
            .map_err(Error::Transfer)?
        {
            self.apply(TransfersSynched(event))?
        }

        // cleanup of previous state: clear completed reward payouts
        self.state.completed.clear();
        self.state.transition = Transition::None;

        // Wallet transition is completed!
        info!("Wallet transition is completed!");

        // inform the new Elders
        Ok(NetworkDuties::from(NodeDuty::InformNewElders))
    }

    /// (potentially leading to Wallet transition, step 3.)
    /// As all Replicas have accumulated the distributed
    /// actor cmds and applied them, they'll send out the
    /// result, which each actor instance accumulates locally.
    /// This validated transfer can be either a reward payout, or
    /// a transition of section funds to a new section actor.
    pub async fn receive(&mut self, validation: TransferValidated) -> Result<NetworkDuties> {
        use NodeCmd::*;
        use NodeTransferCmd::*;

        debug!(">>>>>>>>>>>>>> Receiving transfer validation");
        if let Some(event) = self.actor.receive(validation)? {
            self.apply(TransferValidationReceived(event.clone()))?;
            let proof = if let Some(proof) = event.proof {
                proof
            } else {
                return Ok(vec![]);
            };
            // If we have an accumulated proof, we'll continue with registering the proof.
            if let Some(event) = self.actor.register(proof.clone())? {
                self.apply(TransferRegistrationSent(event))?;
            };

            debug!(">>>>>>>> further in receive");
            let mut queued_ops = vec![];

            match self.state.transition.clone() {
                Transition::None => {
                    debug!(">>>> NO TRANSITION");
                }
                Transition::Regular(TransitionStage::InTransition(next_actor)) => {
                    debug!(">>>> REGULAR TRANSITION");

                    queued_ops.extend(self.move_to_next(next_actor, proof.credit_proof())?);
                    queued_ops.extend(self.try_pop_queue().await?);
                }
                Transition::Split(SplitStage::CompletingT1 { next_actor, ref t2 }) => {
                    debug!(">>>> ************************* Completing t1!");

                    let if_t1_was_ours = if t2.recipient != next_actor.id() {
                        Some(proof.credit_proof())
                    } else {
                        None
                    };
                    let t2 = self.generate_validation(t2.amount, t2.recipient)?;
                    queued_ops.push(NetworkDuty::from(t2));
                    self.state.transition = Transition::Split(SplitStage::CompletingT2 {
                        next_actor,
                        if_t1_was_ours,
                    });
                }
                Transition::Split(SplitStage::CompletingT2 {
                    next_actor,
                    ref if_t1_was_ours,
                }) => {
                    debug!(">>>> ********************** Completing t2!");
                    if let Some(credit) = if_t1_was_ours {
                        // t1 was the credit to our next actor
                        queued_ops.extend(self.move_to_next(next_actor, credit.clone())?)
                    } else {
                        // t2 is the credit to our next actor
                        queued_ops.extend(self.move_to_next(next_actor, proof.credit_proof())?)
                    }
                }
                Transition::Split(SplitStage::Pending { .. })
                | Transition::Regular(TransitionStage::Pending(_)) => {
                    debug!(">>>> PENDING ERROR FOR TRANSITION");

                    return Err(Error::Logic(
                        "Invalid transition stage: Pending".to_string(),
                    ));
                }
            }

            let msg_id = XorName::from_content(&[&bincode::serialize(&proof.credit_sig)?]);

            // We ask of our Replicas to register this transfer.
            let mut register_op = NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: Transfers(RegisterSectionPayout(proof)),
                    id: MessageId(msg_id),
                    target_section_pk: None,
                },
                section_source: true, // i.e. responses go to our section
                dst: DstLocation::Section(self.actor.id().into()), // a remote section transfers module will handle this (i.e. our replicas)
                aggregation: Aggregation::AtDestination, // (not needed, but makes sn_node logs less chatty..)
            }));

            // First register the transfer, then
            // carry out the first queued payout.
            register_op.extend(queued_ops);

            debug!(">>> registering");
            Ok(register_op)
        } else {
            Ok(vec![])
        }
    }

    // Can safely be called without overwriting any
    // payout in flight, since validations for that are made.
    async fn try_pop_queue(&mut self) -> Result<NetworkDuties> {
        if let Some(payout) = self.state.queued_payouts.pop_front() {
            // Validation logic when inititating rewards prevents enqueueing a payout that is already
            // in the completed set. Therefore, calling initiate here cannot return None because of
            // the payout already being completed.
            // For that reason it is safe to enqueue it again, if this call returns None.
            // (we will not loop on that payout)
            match self.initiate_reward_payout(payout.clone()).await? {
                NodeMessagingDuty::NoOp => {
                    if !self.state.completed.contains(&payout.node_id) {
                        // buut.. just to prevent any future changes to
                        // enable such a loop, we do the check above anyway :)
                        // (NB: We put it at the front of the queue again,
                        //  since that's where the other instances will expect it to be. (Unclear atm if this is necessary or not.))
                        self.state.queued_payouts.insert(0, payout);
                    }
                }
                op => return Ok(NetworkDuties::from(op)),
            }
        }

        Ok(vec![])
    }

    fn apply(&mut self, event: ActorEvent) -> Result<()> {
        self.actor.apply(event).map_err(Error::Transfer)
    }

    fn has_payout_in_flight(&self) -> bool {
        self.state.payout_in_flight.is_some()
    }
}
