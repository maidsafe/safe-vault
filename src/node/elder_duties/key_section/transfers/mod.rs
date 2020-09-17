// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod replica_manager;
pub mod store;

pub use self::replica_manager::ReplicaManager;
use crate::{
    node::keys::NodeSigningKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{MessagingDuty, NodeOperation, TransferCmd, TransferDuty, TransferQuery},
};
use log::{debug, trace};
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_data_types::{
    Address, CmdError, DebitAgreementProof, ElderDuties, Error, Event, Message, MessageId, NodeCmd,
    NodeCmdError, NodeEvent, NodeQuery, NodeQueryResponse, NodeTransferCmd, NodeTransferError,
    NodeTransferQuery, NodeTransferQueryResponse, PublicKey, QueryResponse, ReplicaEvent,
    SignedTransfer, TransferError,
};
use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};
/*
Transfers is the layer that manages
interaction with an AT2 Replica.

Flow overview:

Client transfers
1. Client-to-Elders: Cmd::ValidateTransfer
2. Elders-to-Client: Event::TransferValidated
3. Client-to-Elders: Cmd::RegisterTransfer
4. Elders-to-Elders: NodeCmd::PropagateTransfer

Section transfers (such as reward payout)
1. Elders-to-Elders: NodeCmd::ValidateSectionPayout
2. Elders-to-Elders: NodeEvent::SectionPayoutValidated
3. Elders-to-Elders: NodeCmd::RegisterSectionPayout
4. Elders-to-Elders: NodeCmd::PropagateTransfer

The Replica is the part of an AT2 system
that forms validating groups, and signs individual
Actors' transfers.
They validate incoming requests for transfer, and
apply operations that has a valid proof of agreement from the group.
Replicas don't initiate transfers or drive the algo - only Actors do.
*/

/// Transfers is the layer that manages
/// interaction with an AT2 Replica.
pub struct Transfers {
    replica: Rc<RefCell<ReplicaManager>>,
    wrapping: ElderMsgWrapping,
}

impl Transfers {
    pub fn new(keys: NodeSigningKeys, replica: Rc<RefCell<ReplicaManager>>) -> Self {
        let wrapping = ElderMsgWrapping::new(keys, ElderDuties::Transfer);
        Self { replica, wrapping }
    }

    /// Issues a query to existing Replicas
    /// asking for their events, as to catch up and
    /// start working properly in the group.
    pub fn catchup_with_replicas(&mut self) -> Option<NodeOperation> {
        // prepare replica init
        self.wrapping
            .send(Message::NodeQuery {
                query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents(PublicKey::Bls(
                    self.replica.borrow_mut().replicas_pk_set()?.public_key(),
                ))),
                id: MessageId::new(),
            })
            .map(|c| c.into())
    }

    /// When handled by Elders in the dst
    /// section, the actual business logic is executed.
    pub fn process_transfer_duty(&mut self, duty: &TransferDuty) -> Option<NodeOperation> {
        use TransferDuty::*;
        let result = match duty {
            ProcessQuery {
                query,
                msg_id,
                origin,
            } => self.process_query(query, *msg_id, origin.clone()),
            ProcessCmd {
                cmd,
                msg_id,
                origin,
            } => self.process_cmd(cmd, *msg_id, origin.clone()),
        };

        result.map(|c| c.into())
    }

    fn process_query(
        &mut self,
        query: &TransferQuery,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        use TransferQuery::*;
        match query {
            GetReplicaEvents => self.all_events(msg_id, origin),
            GetReplicaKeys(wallet_id) => self.get_replica_pks(wallet_id, msg_id, origin),
            GetBalance(wallet_id) => self.balance(wallet_id, msg_id, origin),
            GetHistory { at, since_version } => self.history(at, *since_version, msg_id, origin),
        }
    }

    fn process_cmd(
        &mut self,
        cmd: &TransferCmd,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        use TransferCmd::*;
        debug!("Processing Transfer CMD in keysection");
        match cmd {
            InitiateReplica(events) => self.initiate_replica(events),
            #[cfg(feature = "simulated-payouts")]
            // Cmd to simulate a farming payout
            SimulatePayout(transfer) => self
                .replica
                .borrow_mut()
                .credit_without_proof(transfer.clone()),
            ValidateTransfer(signed_transfer) => {
                self.validate(signed_transfer.clone(), msg_id, origin)
            }
            ValidateSectionPayout(signed_transfer) => {
                self.validate_section_payout(signed_transfer.clone(), msg_id, origin)
            }
            RegisterTransfer(debit_agreement) | RegisterSectionPayout(debit_agreement) => {
                self.register(&debit_agreement, msg_id, origin)
            }
            PropagateTransfer(debit_agreement) => {
                self.receive_propagated(&debit_agreement, msg_id, origin)
            }
        }
    }

    /// Initiates a new Replica with the
    /// state of existing Replicas in the group.
    fn initiate_replica(&mut self, events: &[ReplicaEvent]) -> Option<MessagingDuty> {
        // We must be able to initiate the replica, otherwise this node cannot function.
        match self.replica.borrow_mut().initiate(events) {
            Ok(()) => None,
            Err(e) => panic!(e), // Temporary brittle solution before lazy messaging impl.
        }
    }

    /// Get all the events of the Replica.
    fn all_events(&self, msg_id: MessageId, origin: Address) -> Option<MessagingDuty> {
        let result = match self.replica.borrow().all_events() {
            None => Err(Error::NoSuchData),
            Some(events) => Ok(events),
        };
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        self.wrapping.send(Message::NodeQueryResponse {
            response: Transfers(GetReplicaEvents(result)),
            id: MessageId::new(),
            correlation_id: msg_id,
            query_origin: origin,
        })
    }

    /// Get the PublicKeySet of our replicas
    fn get_replica_pks(
        &self,
        _wallet_id: &PublicKey,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        // validate signature
        let result = match self.replica.borrow().replicas_pk_set() {
            None => Err(Error::NoSuchKey),
            Some(keys) => Ok(keys),
        };
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetReplicaKeys(result),
            id: MessageId::new(),
            correlation_id: msg_id,
            query_origin: origin,
        })
    }

    fn balance(
        &self,
        wallet_id: &PublicKey,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        // validate signature
        let result = self
            .replica
            .borrow()
            .balance(wallet_id)
            .ok_or(Error::NoSuchBalance);
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetBalance(result),
            id: MessageId::new(),
            correlation_id: msg_id,
            query_origin: origin,
        })
    }

    fn history(
        &self,
        wallet_id: &PublicKey,
        _since_version: usize,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        trace!("Handling GetHistory");
        // validate signature
        let result = match self
            .replica
            .borrow()
            .history(wallet_id) // since_version
        {
            None => Ok(vec![]),
            Some(history) => Ok(history),
        };
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetHistory(result),
            id: MessageId::new(),
            correlation_id: msg_id,
            query_origin: origin,
        })
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    fn validate(
        &mut self,
        transfer: SignedTransfer,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        debug!("Validating a transfer from msg_id: {:?}", msg_id);
        let message = match self.replica.borrow_mut().validate(transfer) {
            Ok(None) => return None,
            Ok(Some(event)) => Message::Event {
                event: Event::TransferValidated {
                    client: origin.xorname(),
                    event,
                },
                id: MessageId::new(),
                correlation_id: msg_id,
            },
            Err(error) => Message::CmdError {
                id: MessageId::new(),
                error: CmdError::Transfer(TransferError::TransferValidation(error)),
                correlation_id: msg_id,
                cmd_origin: origin,
            },
        };
        self.wrapping.send(message)
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    fn validate_section_payout(
        &mut self,
        transfer: SignedTransfer,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        let message = match self.replica.borrow_mut().validate(transfer) {
            Ok(None) => return None,
            Ok(Some(event)) => Message::NodeEvent {
                event: NodeEvent::SectionPayoutValidated(event),
                id: MessageId::new(),
                correlation_id: msg_id,
            },
            Err(error) => Message::CmdError {
                id: MessageId::new(),
                error: CmdError::Transfer(TransferError::TransferValidation(error)),
                correlation_id: msg_id,
                cmd_origin: origin,
            },
        };
        self.wrapping.send(message)
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    fn register(
        &mut self,
        proof: &DebitAgreementProof,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;

        match self.replica.borrow_mut().register(proof) {
            Ok(None) => None,
            Ok(Some(event)) => self.wrapping.send(Message::NodeCmd {
                cmd: Transfers(PropagateTransfer(event.debit_proof)),
                id: MessageId::new(),
            }),
            Err(error) => self.wrapping.error(
                CmdError::Transfer(TransferError::TransferRegistration(error)),
                msg_id,
                &origin,
            ),
        }
    }

    /// The only step that is triggered by a Replica.
    /// (See fn register_transfer).
    /// After a successful registration of a transfer at
    /// the source, the transfer is propagated to the destination.
    fn receive_propagated(
        &mut self,
        proof: &DebitAgreementProof,
        msg_id: MessageId,
        origin: Address,
    ) -> Option<MessagingDuty> {
        use NodeTransferError::*;
        // We will just validate the proofs and then apply the event.
        let message = match self.replica.borrow_mut().receive_propagated(proof) {
            Ok(_) => return None,
            Err(err) => Message::NodeCmdError {
                error: NodeCmdError::Transfers(TransferPropagation(err)),
                id: MessageId::new(),
                correlation_id: msg_id,
                cmd_origin: origin,
            },
        };
        self.wrapping.send(message)
    }

    #[allow(unused)]
    #[cfg(feature = "simulated-payouts")]
    pub fn pay(&mut self, transfer: Transfer) {
        self.replica.borrow_mut().debit_without_proof(transfer)
    }
}

impl Display for Transfers {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transfers")
    }
}
