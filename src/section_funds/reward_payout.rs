// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    elder_signing::ElderSigning, reward_stages::RewardStages, section_wallet::SectionWallet,
};
use crate::node_ops::{NodeDuties, NodeDuty, OutgoingMsg};
use crate::{Error, Result};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use sn_data_types::{
    ActorHistory, Error as DtError, NodeRewardStage, PublicKey, SectionElders, SignedTransferShare,
    Token, TransferValidated, WalletHistory,
};
use sn_messaging::{
    client::{
        Error as ErrorMessage, NodeCmd, NodeQuery, NodeQueryResponse, NodeRewardQuery,
        NodeRewardQueryResponse, NodeTransferCmd, ProcessMsg,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_transfers::{ActorEvent, ReplicaValidator, TransferActor};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use xor_name::XorName;
use ActorEvent::*;

type SectionActor = TransferActor<Validator, ElderSigning>;

/// The accumulation and paying
/// out of rewards to nodes for
/// their work in the network.
#[derive(Clone)]
pub struct RewardPayout {
    actor: SectionActor,
    members: SectionElders,
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
    /// It is queued when we already have a payout in flight.
    queued_payouts: VecDeque<Payout>,
    payout_in_flight: Option<Payout>,
    completed: BTreeSet<XorName>, // this set grows within acceptable bounds, since transitions do not happen that often, and at every section split, the set is cleared..
}

// Node age
type Age = u8;

impl RewardPayout {
    pub fn new(actor: SectionActor, members: SectionElders) -> Self {
        Self {
            actor,
            members,
            state: State {
                queued_payouts: Default::default(),
                payout_in_flight: None,
                completed: Default::default(),
            },
        }
    }

    pub fn set(&mut self, actor: SectionActor, members: SectionElders) {
        self.actor = actor;
        self.members = members;
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
    pub fn section_wallet_history(&self) -> WalletHistory {
        WalletHistory {
            replicas: self.actor.replicas(),
            history: self.actor.history(),
        }
    }

    /// Section wallet
    pub fn section_wallet_members(&self) -> SectionWallet {
        SectionWallet {
            replicas: self.actor.replicas(),
            members: self.members.clone(),
        }
    }

    pub fn has_payout_in_flight(&self) -> bool {
        self.state.payout_in_flight.is_some()
    }

    // When churning, we cannot continue handling an initiated payout
    // since the sigs won't match. Therefore we pop it from pending and push it
    // to our queue front. This queue is worked down right after the churn is completed.
    // As the old actor is overwritten, it doesn't bother us that there might be TransferInitiated or
    // TransferValidated events applied in it, as a result of this in-flight payout.
    pub fn stash_payout_in_flight(&mut self) {
        if let Some(payout) = self.state.payout_in_flight.take() {
            self.state.queued_payouts.push_front(payout)
        }
    }

    pub async fn synch(&mut self, info: WalletHistory) -> Result<NodeDuty> {
        if self.replicas() != PublicKey::Bls(info.replicas.key_set.public_key()) {
            error!("Section funds keys dont match");
            return Err(Error::Logic("crap..".to_string()));
        }
        debug!(">>>> syncing....");
        info!("Synching replica events to section transfer actor...");
        let event = match self.actor.from_history(info.history) {
            Ok(event) => Ok(event),
            Err(error) => match error {
                sn_transfers::Error::NoActorHistory => Ok(None),
                _ => Err(Error::Transfer(error)),
            },
        }?;

        if let Some(event) = event {
            self.actor.apply(TransfersSynched(event.clone()))?;
            info!("Synched: {:?}", event);
        }
        info!("Section Actor balance: {}", self.actor.balance());
        Ok(NodeDuty::NoOp)
    }

    /// Will validate and sign the payout, and ask of the replicas to
    /// do the same, and await their responses as to accumulate the result.
    pub async fn initiate_reward_payout(&mut self, payout: Payout) -> Result<NodeDuty> {
        if self.state.completed.contains(&payout.node_id) {
            return Ok(NodeDuty::NoOp);
        }
        // if we have a payout in flight, the payout is deferred.
        if self.has_payout_in_flight() {
            self.state.queued_payouts.push_back(payout);
            return Ok(NodeDuty::NoOp);
        }

        use NodeCmd::*;
        use NodeTransferCmd::*;
        // We try initiate the transfer..
        match self.actor.transfer(
            payout.amount,
            payout.to,
            format!("Reward for node id: {}", payout.node_id),
        )? {
            None => Ok(NodeDuty::NoOp), // Would indicate that this apparently has already been done, so no change.
            Some(event) => {
                self.apply(TransferInitiated(event.clone()))?;
                // We now have a payout in flight.
                self.state.payout_in_flight = Some(payout);
                // We ask of our Replicas to validate this transfer.
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeCmd {
                        cmd: Transfers(ValidateSectionPayout(SignedTransferShare::new(
                            event.signed_debit.as_share()?,
                            event.signed_credit.as_share()?,
                            self.actor.owner().public_key_set()?,
                        )?)),
                        id: MessageId::new(),
                    },
                    section_source: false,
                    dst: DstLocation::Section(self.actor.id().into()),
                    aggregation: Aggregation::None,
                }))
            }
        }
    }

    /// As all Replicas have accumulated the distributed
    /// actor cmds and applied them, they'll send out the
    /// result, which each actor instance accumulates locally.
    /// This validated transfer is a reward payout.
    pub async fn receive(&mut self, validation: TransferValidated) -> Result<NodeDuties> {
        use NodeCmd::*;
        use NodeTransferCmd::*;

        debug!(">>>>>>>>>>>>>> Receiving validation of reward payout");
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

            // The payout flow is completed,
            // thus we have no payout in flight;
            if let Some(payout) = self.state.payout_in_flight.take() {
                let _ = self.state.completed.insert(payout.node_id);
            }

            debug!(">>>>>>>> Payout has been registered locally.");

            /// send out the registration
            let msg_id = XorName::from_content(&[&bincode::serialize(&proof.credit_sig)?]);
            let mut reward_ops: Vec<_> = self
                .actor
                .replicas()
                .names
                .into_iter()
                .map(|elder| {
                    // We ask of our Replicas to validate this transfer.
                    Some(NodeDuty::Send(OutgoingMsg {
                        msg: ProcessMsg::NodeCmd {
                            cmd: Transfers(RegisterSectionPayout(proof.clone())),
                            id: MessageId(msg_id),
                        },
                        section_source: false, // i.e. responses go to our section
                        dst: DstLocation::Node(elder), // a remote section transfers module will handle this (i.e. our replicas)
                        aggregation: Aggregation::AtDestination, // (not needed, but makes sn_node logs less chatty..)
                    }))
                })
                .flatten()
                .collect();

            // pop from queue if any
            reward_ops.push(self.try_pop_queue().await?);

            Ok(reward_ops)
        } else {
            Ok(vec![])
        }
    }

    // Can safely be called without overwriting any
    // payout in flight, since validations for that are made.
    async fn try_pop_queue(&mut self) -> Result<NodeDuty> {
        if let Some(payout) = self.state.queued_payouts.pop_front() {
            // Validation logic when inititating rewards prevents enqueueing a payout that is already
            // in the completed set. Therefore, calling initiate here cannot return None because of
            // the payout already being completed.
            // For that reason it is safe to enqueue it again, if this call returns None.
            // (we will not loop on that payout)
            match self.initiate_reward_payout(payout.clone()).await? {
                NodeDuty::NoOp => {
                    if !self.state.completed.contains(&payout.node_id) {
                        // buut.. just to prevent any future changes to
                        // enable such a loop, we do the check above anyway :)
                        // (NB: We put it at the front of the queue again,
                        //  since that's where the other instances will expect it to be. (Unclear atm if this is necessary or not.))
                        self.state.queued_payouts.insert(0, payout);
                    }
                }
                op => return Ok(op),
            }
        }

        Ok(NodeDuty::NoOp)
    }

    fn apply(&mut self, event: ActorEvent) -> Result<()> {
        self.actor.apply(event).map_err(Error::Transfer)
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
