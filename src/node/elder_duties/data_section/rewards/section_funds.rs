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
        node_ops::{ElderDuty, NetworkDuties, NetworkDuty, NodeMessagingDuty, OutgoingMsg},
    },
    ElderState, Error, Result,
};
use log::{debug, error, info};
use sn_data_types::{
    ActorHistory, CreditAgreementProof, PublicKey, SignedTransferShare, Token, TransferValidated,
    WalletInfo,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, NodeTransferCmd, NodeTransferQuery},
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

struct State {
    /// Incoming payout requests are queued here.
    /// It is queued when we already have a payout in flight,
    /// or when we are transitioning to a new Actor.
    queued_payouts: VecDeque<Payout>,
    payout_in_flight: Option<Payout>,
    finished: BTreeSet<XorName>, // this set grows within acceptable bounds, since transitions do not happen that often, and at every section split, the set is cleared..
    pending_actor: Option<ElderState>,
    /// While awaiting payout completion
    next_actor: Option<SectionActor>, // we could do a queue here, and when starting transition skip all but the last one, but that is also prone to edge case problems..
}

impl SectionFunds {
    pub fn new(actor: SectionActor) -> Self {
        Self {
            actor,
            state: State {
                queued_payouts: Default::default(),
                payout_in_flight: None,
                finished: Default::default(),
                pending_actor: None,
                next_actor: None,
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
        if let Some(event) = self.actor.from_history(history).map_err(Error::Transfer)? {
            self.actor.apply(TransfersSynched(event.clone()))?;
            info!("Synched: {:?}", event);
        }
        info!("Section Actor balance: {}", self.actor.balance());
        Ok(NodeMessagingDuty::NoOp)
    }

    /// Wallet transition, step 1.
    /// At Elder churn, we must transition to a new wallet.
    /// We start by querying network for the Replicas of this new wallet.
    pub async fn init_transition(
        &mut self,
        elder_state: ElderState,
        sibling_key: Option<PublicKey>,
    ) -> Result<NodeMessagingDuty> {
        info!(">>> Initiating transition to new section wallet...");
        if self.has_initiated_transition() {
            info!(">>>has_initiated_transition");
            return Err(Error::Logic("Already initiated transition".to_string()));
        } else if self.is_transitioning() {
            info!(">>>is_transitioning");
            return Err(Error::Logic("Undergoing transition already".to_string()));
        }

        // When we have a payout in flight, we defer the transition.
        if self.has_payout_in_flight() {
            info!(">>>has_payout_in_flight");
            return Err(Error::Logic("Has payout in flight".to_string()));
        }

        let new_wallet = elder_state.section_public_key();

        self.state.pending_actor = Some(elder_state);

        info!(">>>sending transfer setup query");
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeQuery {
                query: NodeQuery::Transfers(NodeTransferQuery::SetupNewSectionWallets((
                    new_wallet,
                    sibling_key,
                ))),
                id: MessageId::new(),
                target_section_pk: None,
            },
            dst: DstLocation::Section(new_wallet.into()),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Wallet transition, step 2.
    /// When receiving the wallet info, containing the Replicas of
    /// the new wallet, we can complete the transition by starting
    /// transfers to the new wallets.
    pub async fn complete_transition(
        &mut self,
        new_wallet: WalletInfo,
        sibling_key: Option<PublicKey>,
    ) -> Result<NetworkDuties> {
        info!(">>>Transitioning section transfer actor...");
        if self.is_transitioning() {
            info!("is_transitioning");
            return Err(Error::Logic("Undergoing transition already".to_string()));
        }

        // TODO: Create a transfer to the other wallet toooooo.

        if let Some(elder_state) = self.state.pending_actor.take() {
            let signing = ElderSigning::new(elder_state);
            let actor = TransferActor::from_info(signing, new_wallet, Validator {})?;
            let wallet_id = actor.id();
            self.state.next_actor = Some(actor);
            // When we have a payout in flight, we defer the transition.
            if self.has_payout_in_flight() {
                info!("has_payout_in_flight");
                return Err(Error::Logic("Has payout in flight".to_string()));
            }

            // Get all the tokens of current actor.
            let amount = self.actor.balance();
            if amount == Token::zero() {
                info!("No tokens to transfer in this section.");
                // if zero, then there is nothing to transfer..
                // so just go ahead and become the new actor.
                return match self.state.next_actor.take() {
                    Some(actor) => {
                        self.actor = actor;
                        Ok(vec![])
                    }
                    None => {
                        error!("Tried to take next actor while non existed!");
                        Err(Error::Logic(
                            "Tried to take next actor while non existed".to_string(),
                        ))
                    }
                };
            }

            let mut transfers: NetworkDuties = vec![];
            if let Some(sibling_key) = sibling_key {
                debug!(">>> Split happening, we need to transfer to TWO wallets, for each sibling");

                let amount = Token::from_nano(amount.as_nano() / 2);
                debug!("Creating two transfers to each child section");
                // create two transfers to each sibling wallet

                // TODO:is order important here?
                // Determine which transfer is first
                if wallet_id > sibling_key {
                    let t1 = self.generate_transfer_duties(amount, wallet_id).await?;
                    let t2 = self.generate_transfer_duties(amount, sibling_key).await?;
                    transfers.push(NetworkDuty::from(t1));
                    transfers.push(NetworkDuty::from(t2));
                } else {
                    let t1 = self.generate_transfer_duties(amount, sibling_key).await?;
                    let t2 = self.generate_transfer_duties(amount, wallet_id).await?;
                    transfers.push(NetworkDuty::from(t1));
                    transfers.push(NetworkDuty::from(t2));
                }
            } else {
                let duty = self.generate_transfer_duties(amount, wallet_id).await?;
                transfers.push(NetworkDuty::from(duty));
            }

            Ok(transfers)
        } else {
            Err(Error::Logic(
                "eeeeh.. had not initiated transition !?!?!".to_string(),
            ))
        }
    }

    /// generate transfer duties from our current actor
    pub async fn generate_transfer_duties(
        &mut self,
        amount: Token,
        wallet_id: PublicKey,
    ) -> Result<NodeMessagingDuty> {
        // Transfer the tokens from
        // previous actor to new actor.
        use NodeCmd::*;
        use NodeTransferCmd::*;

        match self.actor.transfer(
            amount,
            wallet_id,
            format!("Section Actor transition to new wallet: {}", wallet_id),
        )? {
            None => Ok(NodeMessagingDuty::NoOp), // Would indicate that this apparently has already been done, so no change.
            Some(event) => {
                self.apply(TransferInitiated(event.clone()))?;
                info!("Section actor transition transfer is being requested of the replicas..");
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
                    dst: DstLocation::Section(self.actor.id().into()),
                    to_be_aggregated: false,
                }))
            }
        }
    }

    /// Will validate and sign the payout, and ask of the replicas to
    /// do the same, and await their responses as to accumulate the result.
    pub async fn initiate_reward_payout(&mut self, payout: Payout) -> Result<NodeMessagingDuty> {
        if self.state.finished.contains(&payout.node_id) {
            return Ok(NodeMessagingDuty::NoOp);
        }
        // if we are transitioning, or having payout in flight, the payout is deferred.
        if self.is_transitioning() || self.has_payout_in_flight() {
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
                    dst: DstLocation::Section(self.actor.id().into()),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// (potentially leading to Wallet transition, step 3.)
    /// As all Replicas have accumulated the distributed
    /// actor cmds and applied them, they'll send out the
    /// result, which each actor instance accumulates locally.
    pub async fn receive(&mut self, validation: TransferValidated) -> Result<NetworkDuties> {
        use NodeCmd::*;
        use NodeTransferCmd::*;

        debug!(">>> Receiving section funds");
        if let Some(event) = self.actor.receive(validation)? {
            self.apply(TransferValidationReceived(event.clone()))?;
            // If we have an accumulated proof, we'll continue with registering the proof.
            let proof = if let Some(proof) = event.proof {
                proof
            } else {
                return Ok(vec![]);
            };

            if let Some(event) = self.actor.register(proof.clone())? {
                self.apply(TransferRegistrationSent(event))?;
            };

            // The payout flow is completed,
            // thus we have no payout in flight;
            if let Some(payout) = self.state.payout_in_flight.take() {
                let _ = self.state.finished.insert(payout.node_id);
            }

            // If we are transitioning to a new actor,
            // we replace the old with the new.
            let transitioned = self.try_transition(proof.credit_proof())?;

            // If there are queued payouts,
            // the first in queue will be executed.
            // (NB: If we were transitioning, we cannot do this until Transfers has transitioned as well!)
            let mut queued_ops = vec![];
            if !transitioned {
                queued_ops = self.try_pop_queue().await?;
            }

            // We ask of our Replicas to register this transfer.
            let mut register_op = NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: Transfers(RegisterSectionPayout(proof)),
                    id: MessageId::new(),
                    target_section_pk: None,
                },
                dst: DstLocation::Section(self.actor.id().into()),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination, // TODO: aggregate here (not needed, but makes sn_node logs less chatty..)
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
            // in the finished set. Therefore, calling initiate here cannot return None because of
            // the payout already being finished.
            // For that reason it is safe to enqueue it again, if this call returns None.
            // (we will not loop on that payout)
            match self.initiate_reward_payout(payout.clone()).await? {
                NodeMessagingDuty::NoOp => {
                    if !self.state.finished.contains(&payout.node_id) {
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

    /// Wallet transition, step 3.
    /// If we are transitioning to a new actor, we replace the old with the new.
    fn try_transition(&mut self, credit_proof: CreditAgreementProof) -> Result<bool> {
        if !self.is_transition_credit(&credit_proof) {
            return Ok(false);
        }
        // hmm.. it would actually be a bug
        // if we have a payout in flight...
        if self.has_payout_in_flight() {
            return Err(Error::Logic(
                "You failed to implement the logic correctly. Go back to the drawing desk."
                    .to_string(),
            ));
        }

        // Set the next actor to be our current.
        self.actor = self
            .state
            .next_actor
            .take()
            .ok_or_else(|| Error::Logic("Could not set the next actor".to_string()))?;
        // // // clear finished
        // // cannot do this here: self.state.finished.clear();

        // Credit the transfer to the new actor.
        match self.actor.from_history(ActorHistory {
            credits: vec![credit_proof],
            debits: vec![],
        }) {
            Ok(Some(event)) => self.apply(TransfersSynched(event))?,
            Ok(None) => (),
            Err(error) => return Err(Error::Transfer(error)),
        };

        // Wallet transition is completed!
        info!("Wallet transition is completed!");

        Ok(true)
    }

    fn apply(&mut self, event: ActorEvent) -> Result<()> {
        self.actor.apply(event).map_err(Error::Transfer)
    }

    fn is_transition_credit(&self, credit: &CreditAgreementProof) -> bool {
        if let Some(next_actor) = &self.state.next_actor {
            return credit.recipient() == next_actor.id();
        }
        false
    }

    pub fn has_initiated_transition(&self) -> bool {
        self.state.pending_actor.is_some()
    }

    fn is_transitioning(&self) -> bool {
        self.state.next_actor.is_some()
    }

    fn has_payout_in_flight(&self) -> bool {
        self.state.payout_in_flight.is_some()
    }
}
