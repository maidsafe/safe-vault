// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod replicas;
pub mod store;
use self::replicas::Replicas;
use crate::{
    capacity::RateLimit,
    node::keys::NodeSigningKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{
        Blah, NodeMessagingDuty, NodeOperation, TransferCmd, TransferDuty, TransferQuery,
    },
    utils, Error, ReplicaInfo, Result,
};
use futures::lock::Mutex;
use log::{debug, error, info, trace, warn};
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_data_types::{
    Address, Cmd, CmdError, CreditAgreementProof, ElderDuties, Error as NdError, Event, Message,
    MessageId, MsgEnvelope, NodeCmd, NodeCmdError, NodeEvent, NodeQuery, NodeQueryResponse,
    NodeTransferCmd, NodeTransferError, NodeTransferQuery, NodeTransferQueryResponse, PublicKey,
    QueryResponse, ReplicaEvent, SignedTransfer, TransferAgreementProof, TransferError,
};
use std::fmt::{self, Display, Formatter};
use xor_name::Prefix;

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
    replicas: Replicas,
    rate_limit: RateLimit,
    wrapping: ElderMsgWrapping,
}

impl Transfers {
    pub fn new(keys: NodeSigningKeys, replicas: Replicas, rate_limit: RateLimit) -> Self {
        let wrapping = ElderMsgWrapping::new(keys, ElderDuties::Transfer);
        Self {
            replicas,
            rate_limit,
            wrapping,
        }
    }

    pub async fn init_first(&mut self) -> Result<NodeOperation> {
        let result = self.initiate_replica(&[]).await;
        result.convert()
    }

    /// Issues a query to existing Replicas
    /// asking for their events, as to catch up and
    /// start working properly in the group.
    pub async fn catchup_with_replicas(&mut self) -> Result<NodeOperation> {
        // prepare replica init
        let pub_key = PublicKey::Bls(self.replicas.replicas_pk_set().public_key());
        self.wrapping
            .send_to_section(
                Message::NodeQuery {
                    query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents(pub_key)),
                    id: MessageId::new(),
                },
                true,
            )
            .await
            .convert()
    }

    /// When section splits, the Replicas in either resulting section
    /// also split the responsibility of the accounts.
    /// Thus, both Replica groups need to drop the accounts that
    /// the other group is now responsible for.
    pub async fn section_split(&mut self, prefix: Prefix) -> Result<NodeOperation> {
        // Removes keys that are no longer our section responsibility.
        let _ = self.replicas.keep_keys_of(prefix).await?;
        Ok(NodeOperation::NoOp)
    }

    /// When handled by Elders in the dst
    /// section, the actual business logic is executed.
    pub async fn process_transfer_duty(&mut self, duty: &TransferDuty) -> Result<NodeOperation> {
        trace!("Processing transfer duty");
        use TransferDuty::*;
        let result = match duty {
            ProcessQuery {
                query,
                msg_id,
                origin,
            } => self.process_query(query, *msg_id, origin.clone()).await,
            ProcessCmd {
                cmd,
                msg_id,
                origin,
            } => self.process_cmd(cmd, *msg_id, origin.clone()).await,
            NoOp => return Ok(NodeOperation::NoOp),
        };

        result.convert()
    }

    async fn process_query(
        &self,
        query: &TransferQuery,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        use TransferQuery::*;
        match query {
            GetReplicaEvents => self.all_events(msg_id, origin).await,
            GetReplicaKeys(_wallet_id) => self.get_replica_pks(msg_id, origin).await,
            GetBalance(wallet_id) => self.balance(*wallet_id, msg_id, origin).await,
            GetHistory { at, since_version } => {
                self.history(at, *since_version, msg_id, origin).await
            }
            GetStoreCost { bytes, .. } => self.get_store_cost(*bytes, msg_id, origin).await,
        }
    }

    async fn process_cmd(
        &mut self,
        cmd: &TransferCmd,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        use TransferCmd::*;
        debug!("Processing Transfer CMD in keysection");
        match cmd {
            InitiateReplica(events) => self.initiate_replica(events).await,
            ProcessPayment(msg) => self.process_payment(msg).await,
            #[cfg(feature = "simulated-payouts")]
            // Cmd to simulate a farming payout
            SimulatePayout(transfer) => {
                let res = self.replicas.credit_without_proof(transfer.clone()).await;
                debug!("Simu payoput res: {:?}", res);
                res
            }
            ValidateTransfer(signed_transfer) => {
                self.validate(signed_transfer.clone(), msg_id, origin).await
            }
            ValidateSectionPayout(signed_transfer) => {
                self.validate_section_payout(signed_transfer.clone(), msg_id, origin)
                    .await
            }
            RegisterTransfer(debit_agreement) => {
                self.register(&debit_agreement, msg_id, origin).await
            }
            RegisterSectionPayout(debit_agreement) => {
                self.register_section_payout(&debit_agreement, msg_id, origin)
                    .await
            }
            PropagateTransfer(debit_agreement) => {
                self.receive_propagated(&debit_agreement, msg_id, origin)
                    .await
            }
        }
    }

    pub fn update_replica_keys(&mut self, info: ReplicaInfo) -> Result<NodeMessagingDuty> {
        self.replicas.update_replica_keys(info);
        Ok(NodeMessagingDuty::NoOp)
    }

    /// Initiates a new Replica with the
    /// state of existing Replicas in the group.
    async fn initiate_replica(&self, events: &[ReplicaEvent]) -> Result<NodeMessagingDuty> {
        // We must be able to initiate the replica, otherwise this node cannot function.
        let _ = self.replicas.initiate(events).await?;
        Ok(NodeMessagingDuty::NoOp)
    }

    /// Makes sure the payment contained
    /// within a data write, is credited
    /// to the section funds.
    async fn process_payment(&self, msg: &MsgEnvelope) -> Result<NodeMessagingDuty> {
        let (payment, num_bytes) = match &msg.message {
            Message::Cmd {
                cmd: Cmd::Data { payment, cmd },
                ..
            } => (payment, utils::serialise(cmd)?.len() as u64),
            _ => return Ok(NodeMessagingDuty::NoOp),
        };

        // Make sure we are actually at the correct replicas,
        // before executing the debit.
        // (We could also add a method that executes both
        // debit + credit atomically, but this is much simpler).
        let recipient_is_not_section = payment.recipient() != self.section_wallet_id();

        use TransferError::*;
        if recipient_is_not_section {
            warn!("Payment: recipient is not section");
            return self
                .wrapping
                .error(
                    CmdError::Transfer(TransferRegistration(NdError::NoSuchRecipient)),
                    msg.id(),
                    &msg.origin.address(),
                )
                .await;
        }
        let registration = self.replicas.register(&payment).await;
        let result = match registration {
            Ok(_) => match self
                .replicas
                .receive_propagated(&payment.credit_proof())
                .await
            {
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            },
            Err(error) => Err(error), // not using TransferPropagation error, since that is for NodeCmds, so wouldn't be returned to client.
        };
        let result = match result {
            Ok(_) => {
                info!("Payment: registration and propagation succeeded.");
                // Paying too little will see the amount be forfeited.
                // This prevents spam of the network.
                let total_cost = if let Some(res) = self.rate_limit.from(num_bytes).await {
                    res
                } else {
                    return Err(Error::NetworkData(NdError::Unexpected(
                        "Could not calculate store cost.".to_string(),
                    )));
                };
                if total_cost > payment.amount() {
                    warn!(
                        "Payment: Too low payment: {}, expected: {}",
                        payment.amount(),
                        total_cost
                    );
                    // todo, better error, like `TooLowPayment`
                    return self
                        .wrapping
                        .error(
                            CmdError::Transfer(TransferRegistration(NdError::InsufficientBalance)),
                            msg.id(),
                            &msg.origin.address(),
                        )
                        .await;
                }
                info!("Payment: forwarding data..");
                // consider having the section actor be
                // informed of this transfer as well..
                self.wrapping.forward(msg).await
            }
            Err(Error::NetworkData(error)) => {
                warn!("Payment: registration or propagation failed: {}", error);
                self.wrapping
                    .error(
                        CmdError::Transfer(TransferRegistration(error)),
                        msg.id(),
                        &msg.origin.address(),
                    )
                    .await
            }
            Err(_e) => unimplemented!("process_payment"),
        };
        result
    }

    fn section_wallet_id(&self) -> PublicKey {
        let set = self.replicas.replicas_pk_set();
        PublicKey::Bls(set.public_key())
    }

    /// Get all the events of the Replica.
    async fn all_events(&self, msg_id: MessageId, origin: Address) -> Result<NodeMessagingDuty> {
        let result = self
            .replicas
            .all_events()
            .await
            .map_err(|e| NdError::Unexpected(e.to_string()));
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        self.wrapping
            .send_to_node(Message::NodeQueryResponse {
                response: Transfers(GetReplicaEvents(result)),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    /// Get latest StoreCost for the given number of bytes
    async fn get_store_cost(
        &self,
        bytes: u64,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        info!("Computing StoreCost for {:?} bytes", bytes);
        let result =
            self.rate_limit.from(bytes).await.ok_or_else(|| {
                NdError::Unexpected("Could not compute current StoreCost".to_string())
            });

        if result.is_ok() {
            info!("Got StoreCost {:?}", result.clone()?);
        }

        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetStoreCost(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    /// Get the PublicKeySet of our replicas
    async fn get_replica_pks(
        &self,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        // validate signature
        let pk_set = self.replicas.replicas_pk_set();
        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetReplicaKeys(Ok(pk_set)),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    async fn balance(
        &self,
        wallet_id: PublicKey,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        debug!("Getting balance for {:?}", wallet_id);

        // validate signature
        let result = self
            .replicas
            .balance(wallet_id)
            .await
            .map_err(|e| NdError::Unexpected(e.to_string()));

        debug!("------->>>The result: {:?}", result);
        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetBalance(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    async fn history(
        &self,
        wallet_id: &PublicKey,
        _since_version: usize,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        trace!("Handling GetHistory");
        // validate signature
        let result = self
            .replicas
            .history(*wallet_id)
            .await
            .map_err(|e| NdError::Unexpected(e.to_string()));
        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetHistory(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    async fn validate(
        &self,
        transfer: SignedTransfer,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        debug!("Validating a transfer from msg_id: {:?}", msg_id);
        let message = match self.replicas.validate(transfer).await {
            Ok(event) => Message::Event {
                event: Event::TransferValidated {
                    client: origin.xorname(),
                    event,
                },
                id: MessageId::new(),
                correlation_id: msg_id,
            },
            Err(e) => Message::CmdError {
                id: MessageId::new(),
                error: CmdError::Transfer(TransferError::TransferValidation(NdError::Unexpected(
                    e.to_string(),
                ))),
                correlation_id: msg_id,
                cmd_origin: origin,
            },
        };
        self.wrapping.send_to_client(message).await
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    async fn validate_section_payout(
        &self,
        transfer: SignedTransfer,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        let message = match self.replicas.validate(transfer).await {
            Ok(event) => Message::NodeEvent {
                event: NodeEvent::SectionPayoutValidated(event),
                id: MessageId::new(),
                correlation_id: msg_id,
            },
            Err(e) => Message::NodeCmdError {
                id: MessageId::new(),
                error: NodeCmdError::Transfers(NodeTransferError::TransferPropagation(
                    NdError::Unexpected(e.to_string()),
                )), // TODO: SHOULD BE TRANSFERVALIDATION
                correlation_id: msg_id,
                cmd_origin: origin,
            },
            Err(_e) => unimplemented!("validate_section_payout"),
        };
        self.wrapping.send_to_node(message).await
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    async fn register(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                self.wrapping
                    .send_to_section(
                        Message::NodeCmd {
                            cmd: Transfers(PropagateTransfer(event.transfer_proof)),
                            id: MessageId::new(),
                        },
                        true,
                    )
                    .await
            }
            Err(e) => {
                self.wrapping
                    .error(
                        CmdError::Transfer(TransferError::TransferRegistration(
                            NdError::Unexpected(e.to_string()),
                        )),
                        msg_id,
                        &origin,
                    )
                    .await
            }
        }
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    async fn register_section_payout(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                self.wrapping
                    .send_to_section(
                        Message::NodeCmd {
                            cmd: Transfers(PropagateTransfer(event.transfer_proof)),
                            id: MessageId::new(),
                        },
                        true,
                    )
                    .await
            }
            Err(e) => {
                self.wrapping
                    .error(
                        CmdError::Transfer(TransferError::TransferRegistration(
                            NdError::Unexpected(e.to_string()),
                        )),
                        msg_id,
                        &origin,
                    )
                    .await
            }
        }
    }

    /// The only step that is triggered by a Replica.
    /// (See fn register_transfer).
    /// After a successful registration of a transfer at
    /// the source, the transfer is propagated to the destination.
    async fn receive_propagated(
        &self,
        credit_proof: &CreditAgreementProof,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        use NodeTransferError::*;
        // We will just validate the proofs and then apply the event.
        let message = match self.replicas.receive_propagated(credit_proof).await {
            Ok(_) => return Ok(NodeMessagingDuty::NoOp),
            Err(Error::NetworkData(error)) => Message::NodeCmdError {
                error: NodeCmdError::Transfers(TransferPropagation(error)),
                id: MessageId::new(),
                correlation_id: msg_id,
                cmd_origin: origin,
            },
            Err(_e) => unimplemented!("receive_propagated"),
        };
        self.wrapping.send_to_node(message).await
    }

    #[allow(unused)]
    #[cfg(feature = "simulated-payouts")]
    pub async fn pay(&mut self, transfer: Transfer) -> Result<()> {
        self.replicas.debit_without_proof(transfer).await
    }
}

impl Display for Transfers {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transfers")
    }
}
