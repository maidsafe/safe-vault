// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::validator::Validator;
use crate::{node::msg_wrapping::ElderMsgWrapping, node::node_ops::MessagingDuty};
use safe_nd::{
    AccountId, DebitAgreementProof, Message, MessageId, Money, NodeCmd, NodeTransferCmd, Result,
    TransferValidated,
};
use safe_transfers::{ActorEvent, TransferActor};
use ActorEvent::*;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
pub(super) struct SectionFunds {
    actor: TransferActor<Validator>,
    next_actor: Option<TransferActor<Validator>>,
    wrapping: ElderMsgWrapping,
}

impl SectionFunds {
    pub fn new(actor: TransferActor<Validator>, wrapping: ElderMsgWrapping) -> Self {
        Self {
            actor,
            wrapping,
            next_actor: None,
        }
    }

    #[allow(dead_code)]
    /// At Elder churn, we must transition to a new account.
    pub fn transition(&mut self, to: TransferActor<Validator>) -> Option<MessagingDuty> {
        // TODO:
        // check if any payout is currently processing
        // queue this transition if it is
        use NodeCmd::*;
        use NodeTransferCmd::*;
        let amount = self.actor.balance();
        match self.actor.transfer(amount, to.id()) {
            Ok(Some(event)) => {
                let applied = self.apply(TransferInitiated(event.clone()));
                if applied.is_err() {
                    // This would be a bug!
                    // send some error, log, crash .. or something
                    panic!(applied)
                } else {
                    self.next_actor = Some(to);
                    self.wrapping.send(Message::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(event.signed_transfer)),
                        id: MessageId::new(),
                    })
                }
            }
            Ok(None) => None,
            Err(error) => panic!(error), // This would be a bug! Cannot move on from here, only option is to crash!
        }
    }

    pub fn initiate_reward_payout(
        &mut self,
        amount: Money,
        to: AccountId,
    ) -> Option<MessagingDuty> {
        // TODO:
        // check if any transition is currently processing
        // queue this payout if it is
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.actor.transfer(amount, to) {
            Ok(Some(event)) => {
                let applied = self.apply(TransferInitiated(event.clone()));
                if applied.is_err() {
                    // This would be a bug!
                    // send some error, log, crash .. or something
                    None
                } else {
                    self.wrapping.send(Message::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(event.signed_transfer)),
                        id: MessageId::new(),
                    })
                }
            }
            Ok(None) => None,
            Err(_error) => None, // for now, but should give NodeCmdError
        }
    }

    pub fn receive(&mut self, validation: TransferValidated) -> Option<MessagingDuty> {
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
                    // If we are transitioning to a new actor, we replace the old with the new.
                    self.try_transition(proof.clone())?;
                    self.wrapping.send(Message::NodeCmd {
                        cmd: Transfers(RegisterSectionPayout(proof)),
                        id: MessageId::new(),
                    })
                }
            }
            Ok(None) => None,
            Err(_error) => None, // for now, but should give NodeCmdError
        }
    }

    // If we are transitioning to a new actor, we replace the old with the new.
    fn try_transition(&mut self, credit: DebitAgreementProof) -> Option<()> {
        if let Some(next) = &self.next_actor {
            if next.id() == credit.to() {
                use safe_nd::ReplicaEvent::*;
                self.actor = self.next_actor.take()?;
                match self
                    .actor
                    .synch(vec![TransferPropagated(safe_nd::TransferPropagated {
                        debit_proof: credit,
                        debiting_replicas: self.actor.id(),
                        crediting_replica_sig: dummy_sig(),
                    })]) {
                    Ok(Some(event)) => self.apply(TransfersSynched(event)).ok()?,
                    Ok(None) => (),
                    Err(_error) => return None,
                };
                // TODO: apply any pending payouts
            }
        } else if false {
            // TODO: Check if any pending transitions
        }
        Some(())
    }

    fn apply(&mut self, event: ActorEvent) -> Result<()> {
        self.actor.apply(event)
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
