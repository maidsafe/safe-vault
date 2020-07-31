// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::validator::Validator;
use crate::{
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{MessagingDuty, NodeOperation},
};
use safe_nd::{
    AccountId, DebitAgreementProof, Message, MessageId, Money, NodeCmd, NodeTransferCmd, Result,
    TransferValidated, XorName,
};
use safe_transfers::{ActorEvent, TransferActor};
use std::collections::{BTreeSet, VecDeque};
use ActorEvent::*;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
pub(super) struct SectionFunds {
    actor: TransferActor<Validator>,
    wrapping: ElderMsgWrapping,
    state: State,
}

#[derive(Clone)]
pub struct Payout {
    pub to: AccountId,
    pub amount: Money,
    pub node_id: XorName,
}

struct State {
    /// Incoming payout requests are queued here.
    /// It is queued when we already have a payout in flight,
    /// or when we are transitioning to a new Actor.
    queued_payouts: VecDeque<Payout>,
    payout_in_flight: Option<Payout>,
    finished: BTreeSet<XorName>, // this set grows within acceptable bounds, since transitions do not happen that often, and at every section split, the set is cleared..
    /// While awaiting payout completion
    next_actor: Option<TransferActor<Validator>>, // we could do a queue here, and when starting transition skip all but the last one, but that is also prone to edge case problems..
}

impl SectionFunds {
    pub fn new(actor: TransferActor<Validator>, wrapping: ElderMsgWrapping) -> Self {
        Self {
            actor,
            wrapping,
            state: State {
                queued_payouts: Default::default(),
                payout_in_flight: None,
                finished: Default::default(),
                next_actor: None,
            },
        }
    }

    /// At Elder churn, we must transition to a new account.
    pub fn transition(&mut self, to: TransferActor<Validator>) -> Option<MessagingDuty> {
        if self.is_transitioning() {
            // hm, could be tricky edge cases here, but
            // we'll start by assuming there will only be
            // one transition at a time.
            // (We could enqueue actors, and when starting transition skip
            // all but the last one, but that is also prone to edge case problems..)
            return None;
        }

        let new_id = to.id();
        self.state.next_actor = Some(to);
        // When we have a payout in flight, we defer the transition.
        if self.has_payout_in_flight() {
            return None;
        }

        // Get all the money of current actor.
        let amount = self.actor.balance();
        if amount == Money::zero() {
            // if zero, then there is nothing to transfer..
            // so just go ahead and become the new actor.
            self.actor = self.state.next_actor.take()?;
            return None;
        }

        // Transfer the money from
        // previous actor to new actor.
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.actor.transfer(amount, new_id) {
            Ok(Some(event)) => {
                let applied = self.apply(TransferInitiated(event.clone()));
                if applied.is_err() {
                    // This would be a bug!
                    // send some error, log, crash .. or something
                    panic!(applied)
                } else {
                    // We ask of our Replicas to validate this transfer.
                    self.wrapping.send(Message::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(event.signed_transfer)),
                        id: MessageId::new(),
                    })
                }
            }
            Ok(None) => None, // Would indicate that this apparently has already been done, so no change.
            Err(error) => panic!(error), // This would be a bug! Cannot move on from here, only option is to crash!
        }
    }

    pub fn initiate_reward_payout(&mut self, payout: Payout) -> Option<MessagingDuty> {
        if self.state.finished.contains(&payout.node_id) {
            return None;
        }
        // if we are transitioning, or having payout in flight, the payout is deferred.
        if self.is_transitioning() || self.has_payout_in_flight() {
            self.state.queued_payouts.push_back(payout);
            return None;
        }

        use NodeCmd::*;
        use NodeTransferCmd::*;
        // We try initiate the transfer..
        match self.actor.transfer(payout.amount, payout.to) {
            Ok(Some(event)) => {
                let applied = self.apply(TransferInitiated(event.clone()));
                if applied.is_err() {
                    // This would be a bug!
                    // send some error, log, crash .. or something
                    None
                } else {
                    // We now have a payout in flight.
                    self.state.payout_in_flight = Some(payout);
                    // We ask of our Replicas to validate this transfer.
                    self.wrapping.send(Message::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(event.signed_transfer)),
                        id: MessageId::new(),
                    })
                }
            }
            Ok(None) => None, // Would indicate that this apparently has already been done, so no change.
            Err(_error) => None, // for now, but should give NodeCmdError
        }
    }

    pub fn receive(&mut self, validation: TransferValidated) -> Option<NodeOperation> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.actor.receive(validation) {
            Ok(Some(event)) => {
                let applied = self.apply(TransferValidationReceived(event.clone()));
                if applied.is_err() {
                    // This would be a bug!
                    // send some error, log, crash .. or something
                    None
                } else {
                    let proof = event.proof?;
                    // If we have an accumulated proof, we'll update local state.
                    match self.actor.register(proof.clone()) {
                        Ok(Some(event)) => self.apply(TransferRegistrationSent(event)).ok()?,
                        Ok(None) => (),
                        Err(_error) => return None, // for now, but should give NodeCmdError
                    };

                    // The payout flow is completed,
                    // thus we have no payout in flight;
                    if let Some(payout) = self.state.payout_in_flight.take() {
                        let _ = self.state.finished.insert(payout.node_id);
                    }

                    // If we are transitioning to a new actor,
                    // we replace the old with the new.
                    self.try_transition(proof.clone()).ok()?;

                    // If there are queued payouts,
                    // the first in queue will be executed.
                    let queued_op = self.try_pop_queue();

                    // We ask of our Replicas to register this transfer.
                    let reg_op = self
                        .wrapping
                        .send(Message::NodeCmd {
                            cmd: Transfers(RegisterSectionPayout(proof)),
                            id: MessageId::new(),
                        })?
                        .into();

                    if let Some(queued) = queued_op {
                        // First register the transfer, then
                        // carry out the first queued payout.
                        return Some(vec![reg_op, queued].into());
                    }

                    Some(reg_op)
                }
            }
            Ok(None) => None,
            Err(_error) => None, // for now, but should give NodeCmdError
        }
    }

    // Can safely be called without opverwriting any
    // payout in flight, since validations for that are made.
    fn try_pop_queue(&mut self) -> Option<NodeOperation> {
        if let Some(payout) = self.state.queued_payouts.pop_front() {
            // Validation logic when inititating rewards prevents enqueueing a payout that is already
            // in the finished set. Therefore, calling initiate here cannot return None because of
            // the payout already being finished.
            // For that reason it is safe to enqueue it again, if this call returns None.
            // (we will not loop on that payout)
            if let Some(msg) = self.initiate_reward_payout(payout.clone()) {
                return Some(msg.into());
            } else if !self.state.finished.contains(&payout.node_id) {
                // buut.. just to prevent any future changes to
                // enable such a loop, we do the check above anyway :)
                // (NB: We put it at the front of the queue again,
                //  since that's where the other instances will expect it to be. (Unclear atm if this is necessary or not.))
                self.state.queued_payouts.insert(0, payout);
            }
        }
        None
    }

    // If we are transitioning to a new actor, we replace the old with the new.
    fn try_transition(&mut self, credit: DebitAgreementProof) -> Result<()> {
        if !self.is_transition_credit(&credit) {
            return Ok(());
        }
        // hmm.. it would actually be a bug
        // if we have a payout in flight...
        if self.has_payout_in_flight() {
            panic!("You failed to implement the logic correctly. Go back to the drawing desk.")
        }

        use safe_nd::ReplicaEvent::*;
        // Set the next actor to be our current.
        self.actor = self.state.next_actor.take().unwrap();
        // (we're probably not in a very good state though if we happen to not have anything here.. so probably best to panic.. at least until we know we can recover from this)

        // Credit the transfer to the new actor.
        match self
            .actor
            .synch(vec![TransferPropagated(safe_nd::TransferPropagated {
                debit_proof: credit,
                debiting_replicas: self.actor.id(),
                crediting_replica_sig: dummy_sig(),
            })]) {
            Ok(Some(event)) => self.apply(TransfersSynched(event))?,
            Ok(None) => (),
            Err(error) => return Err(error),
        };

        Ok(())
    }

    fn apply(&mut self, event: ActorEvent) -> Result<()> {
        self.actor.apply(event)
    }

    fn is_transition_credit(&self, credit: &DebitAgreementProof) -> bool {
        if let Some(next_actor) = &self.state.next_actor {
            return credit.to() == next_actor.id();
        }
        false
    }

    fn is_transitioning(&self) -> bool {
        self.state.next_actor.is_some()
    }

    fn has_payout_in_flight(&self) -> bool {
        self.state.payout_in_flight.is_some()
    }
}

use safe_nd::SignatureShare;
use threshold_crypto::SecretKeyShare;
fn dummy_sig() -> SignatureShare {
    let dummy_shares = SecretKeyShare::default();
    let dummy_sig = dummy_shares.sign("DUMMY MSG");
    SignatureShare {
        index: 0,
        share: dummy_sig,
    }
}
