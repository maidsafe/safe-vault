// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::elder_signing::ElderSigning;
use crate::{
    node::node_ops::{NetworkDuties, NetworkDuty, NodeMessagingDuty, OutgoingMsg},
    ElderState, Error, Result,
};
use log::{debug, info};
use sn_data_types::{
    ActorHistory, PublicKey, SectionElders, SignedTransferShare, Token, TransferValidated,
    WalletInfo,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeTransferCmd},
    Aggregation, DstLocation, MessageId,
};
use sn_transfers::ReplicaValidator;
use sn_transfers::{ActorEvent, TransferActor};
use std::collections::{BTreeSet, VecDeque};
use xor_name::XorName;
use ActorEvent::*;

type SectionActor = TransferActor<Validator, ElderSigning>;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
pub struct RewardingWallet {
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
}

impl RewardingWallet {
    pub fn new(actor: SectionActor) -> Self {
        Self {
            actor,
            state: State {
                queued_payouts: Default::default(),
                payout_in_flight: None,
                completed: Default::default(),
            },
        }
    }
   
    /// Balance
    pub fn balance(&self) -> Token {
        self.actor.balance()
    }
        
    /// Current Replicas
    pub fn replicas(&self) -> PublicKey {
        self.actor.replicas_public_key()
    }

    /// Wallet info
    pub fn wallet_info(&self) -> WalletInfo {
        WalletInfo {
            replicas: self.actor.replicas(),
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

    fn get_actor(replicas: SectionElders, elder_state: ElderState) -> Result<SectionActor> {
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

    /// Will validate and sign the payout, and ask of the replicas to
    /// do the same, and await their responses as to accumulate the result.
    pub async fn initiate_reward_payout(&mut self, payout: Payout) -> Result<NodeMessagingDuty> {
        if self.state.completed.contains(&payout.node_id) {
            return Ok(NodeMessagingDuty::NoOp);
        }
        // if we have a payout in flight, the payout is deferred.
        if self.has_payout_in_flight() {
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

            let msg_id = XorName::from_content(&[&bincode::serialize(&proof.credit_sig)?]);

            let register_op: Vec<_> = self
                .actor
                .replicas()
                .names
                .into_iter()
                .map(|elder| {
                    // We ask of our Replicas to validate this transfer.
                    Some(NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::NodeCmd {
                            cmd: Transfers(RegisterSectionPayout(proof.clone())),
                            id: MessageId(msg_id),
                            target_section_pk: None,
                        },
                        section_source: false, // i.e. responses go to our section
                        dst: DstLocation::Node(elder), // a remote section transfers module will handle this (i.e. our replicas)
                        aggregation: Aggregation::AtDestination, // (not needed, but makes sn_node logs less chatty..)
                    }))
                })
                .flatten()
                .map(|m| NetworkDuty::from(m))
                .collect();

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

/// Should be validating
/// other replica groups, i.e.
/// make sure they are run at Elders
/// of sections we know of.
/// TBD.
#[derive(Clone)]
pub struct Validator {}

impl ReplicaValidator for Validator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}
