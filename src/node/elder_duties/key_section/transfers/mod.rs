// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod genesis;
pub mod replica_signing;
pub mod replicas;
pub mod store;
mod test_utils;

use self::replicas::Replicas;
use super::ReplicaInfo;
use crate::{
    capacity::RateLimit,
    error::{convert_dt_error_to_error_message, convert_to_error_message},
    node::node_ops::{
        NetworkDuties, NetworkDuty, NodeMessagingDuty, OutgoingMsg, TransferCmd, TransferDuty,
        TransferQuery,
    },
    utils, Error, Result,
};
use log::{debug, error, info, trace, warn};
use replica_signing::ReplicaSigningImpl;
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use std::collections::HashSet;

use futures::lock::Mutex;
use sn_data_types::{
    CreditAgreementProof, DebitId, PublicKey, ReplicaEvent, SignedTransfer, SignedTransferShare,
    TransferAgreementProof, TransferPropagated,
};
use sn_messaging::{
    client::{
        Cmd, CmdError, Error as ErrorMessage, Event, Message, NodeCmd, NodeCmdError, NodeEvent,
        NodeQuery, NodeQueryResponse, NodeTransferCmd, NodeTransferError, NodeTransferQuery,
        NodeTransferQueryResponse, QueryResponse, TransferError,
    },
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
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
    replicas: Replicas<ReplicaSigningImpl>,
    rate_limit: RateLimit,
    // TODO: limit this? where do we store it
    recently_validated_transfers: Arc<Mutex<HashSet<DebitId>>>,
}

impl Transfers {
    pub fn new(replicas: Replicas<ReplicaSigningImpl>, rate_limit: RateLimit) -> Self {
        Self {
            replicas,
            rate_limit,
            recently_validated_transfers: Default::default(),
        }
    }

    ///
    pub async fn genesis(&self, genesis: TransferPropagated) -> Result<()> {
        self.replicas
            .initiate(&[ReplicaEvent::TransferPropagated(genesis)])
            .await
    }

    /// Issues a query to existing Replicas
    /// asking for their events, as to catch up and
    /// start working properly in the group.
    pub async fn catchup_with_replicas(&self) -> Result<NetworkDuties> {
        info!("Transfers: Catching up with transfer Replicas!");
        // prepare replica init
        let pub_key = PublicKey::Bls(self.replicas.replicas_pk_set().public_key());
        Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeQuery {
                query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents),
                id: MessageId::new(),
                target_section_pk: None,
            },
            dst: DstLocation::Section(pub_key.into()),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        })))
    }

    /// When section splits, the Replicas in either resulting section
    /// also split the responsibility of the accounts.
    /// Thus, both Replica groups need to drop the accounts that
    /// the other group is now responsible for.
    pub async fn split_section(&self, prefix: Prefix) -> Result<()> {
        // Removes keys that are no longer our section responsibility.
        self.replicas.keep_keys_of(prefix).await
    }

    ///
    pub fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<()> {
        self.rate_limit.increase_full_node_count(node_id)
    }

    /// When handled by Elders in the dst
    /// section, the actual business logic is executed.
    pub async fn process_transfer_duty(&self, duty: &TransferDuty) -> Result<NetworkDuties> {
        trace!("Processing transfer duty");
        use TransferDuty::*;
        match duty {
            ProcessQuery {
                query,
                msg_id,
                origin,
            } => self.process_query(query, *msg_id, *origin).await,
            ProcessCmd {
                cmd,
                msg_id,
                origin,
            } => self.process_cmd(cmd, *msg_id, *origin).await,
            NoOp => Ok(vec![]),
        }
    }

    async fn process_query(
        &self,
        query: &TransferQuery,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NetworkDuties> {
        use TransferQuery::*;
        let duty = match query {
            GetWalletReplicas(wallet_key) => {
                self.get_wallet_replicas(*wallet_key, msg_id, origin)
                    .await?
            }
            GetReplicaEvents => self.all_events(msg_id, origin).await?,
            GetReplicaKeys(_wallet_id) => self.get_replica_pks(msg_id, origin).await?,
            GetBalance(wallet_id) => self.balance(*wallet_id, msg_id, origin).await?,
            GetHistory { at, since_version } => {
                self.history(at, *since_version, msg_id, origin).await?
            }
            GetStoreCost { bytes, .. } => {
                let mut ops = vec![];
                ops.push(NetworkDuty::from(
                    self.get_store_cost(*bytes, msg_id, origin).await?,
                ));
                //ops.push(Ok(ElderDuty::SwitchNodeJoin(self.rate_limit.check_network_storage().await).into()));
                return Ok(ops);
            }
        };
        Ok(NetworkDuties::from(duty))
    }

    async fn process_cmd(
        &self,
        cmd: &TransferCmd,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NetworkDuties> {
        use TransferCmd::*;
        debug!(">>>Processing cmd in Transfers mod");
        let duty = match cmd {
            InitiateReplica(events) => self.initiate_replica(events).await?,
            ProcessPayment(msg) => self.process_payment(msg, origin).await?,
            #[cfg(feature = "simulated-payouts")]
            // Cmd to simulate a farming payout
            SimulatePayout(transfer) => {
                self.replicas.credit_without_proof(transfer.clone()).await?
            }
            ValidateTransfer(signed_transfer) => {
                self.validate(signed_transfer.clone(), msg_id, origin)
                    .await?
            }
            ValidateSectionPayout(signed_transfer) => {
                debug!(">>>> ?? Validating sectin payout");
                self.validate_section_payout(signed_transfer.clone(), msg_id, origin)
                    .await?
            }
            RegisterTransfer(debit_agreement) => self.register(&debit_agreement, msg_id).await?,
            RegisterSectionPayout(debit_agreement) => {
                return self
                    .register_section_payout(&debit_agreement, msg_id, origin)
                    .await;
            }
            PropagateTransfer(debit_agreement) => {
                self.receive_propagated(&debit_agreement, msg_id, origin)
                    .await?
            }
        };
        Ok(NetworkDuties::from(duty))
    }

    ///
    pub fn update_replica_info(
        &mut self,
        info: ReplicaInfo<ReplicaSigningImpl>,
        rate_limit: RateLimit,
    ) {
        self.rate_limit = rate_limit;
        self.replicas.update_replica_info(info);
    }

    /// Initiates a new Replica with the
    /// state of existing Replicas in the group.
    async fn initiate_replica(&self, events: &[ReplicaEvent]) -> Result<NodeMessagingDuty> {
        // We must be able to initiate the replica, otherwise this node cannot function.
        self.replicas.initiate(events).await?;
        Ok(NodeMessagingDuty::NoOp)
    }

    /// Makes sure the payment contained
    /// within a data write, is credited
    /// to the section funds.
    async fn process_payment(
        &self,
        msg: &Message,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        debug!(">>>> processing payment");
        let origin = match origin {
            SrcLocation::EndUser(enduser) => enduser,
            _ => {
                return Err(Error::InvalidMessage(
                    msg.id(),
                    format!("This source can only be an enduser.. : {:?}", msg),
                ))
            }
        };
        let (payment, data_cmd, num_bytes, dst_address) = match &msg {
            Message::Cmd {
                cmd: Cmd::Data { payment, cmd },
                ..
            } => (
                payment,
                cmd,
                utils::serialise(cmd)?.len() as u64,
                cmd.dst_address(),
            ),
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
            let origin = SrcLocation::EndUser(EndUser::AllClients(payment.sender()));
            return Ok(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::CmdError {
                    error: CmdError::Transfer(TransferRegistration(ErrorMessage::NoSuchRecipient)),
                    id: MessageId::in_response_to(&msg.id()),
                    correlation_id: msg.id(),
                    cmd_origin: origin,
                    target_section_pk: None,
                },
                dst: origin.to_dst(),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            }));
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
        match result {
            Ok(_) => {
                let total_cost = self.rate_limit.from(num_bytes).await;
                info!("Payment: registration and propagation succeeded. (Store cost: {}, paid amount: {}.)", total_cost, payment.amount());
                info!(
                    "Section balance: {}",
                    self.replicas.balance(payment.recipient()).await?
                );
                if total_cost > payment.amount() {
                    // Paying too little will see the amount be forfeited.
                    // This prevents spam of the network.
                    warn!(
                        "Payment: Too low payment: {}, expected: {}",
                        payment.amount(),
                        total_cost
                    );
                    // todo, better error, like `TooLowPayment`
                    let origin = SrcLocation::EndUser(EndUser::AllClients(payment.sender()));
                    return Ok(NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::CmdError {
                            error: CmdError::Transfer(TransferRegistration(
                                ErrorMessage::InsufficientBalance,
                            )),
                            id: MessageId::in_response_to(&msg.id()),
                            correlation_id: msg.id(),
                            cmd_origin: origin,
                            target_section_pk: None,
                        },
                        dst: origin.to_dst(),
                        aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                    }));
                }
                info!("Payment: forwarding data..");
                // consider having the section actor be
                // informed of this transfer as well..
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::Metadata {
                            cmd: data_cmd.clone(),
                            origin,
                        },
                        id: MessageId::in_response_to(&msg.id()),
                        target_section_pk: None,
                    },
                    dst: DstLocation::Section(dst_address),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
            Err(e) => {
                warn!("Payment: registration or propagation failed: {}", e);
                let origin = SrcLocation::EndUser(EndUser::AllClients(payment.sender()));
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::CmdError {
                        error: CmdError::Transfer(TransferRegistration(
                            ErrorMessage::PaymentFailed,
                        )),
                        id: MessageId::in_response_to(&msg.id()),
                        correlation_id: msg.id(),
                        cmd_origin: origin,
                        target_section_pk: None,
                    },
                    dst: origin.to_dst(),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
        }
    }

    fn section_wallet_id(&self) -> PublicKey {
        let set = self.replicas.replicas_pk_set();
        PublicKey::Bls(set.public_key())
    }

    /// Get all the events of the Replica.
    async fn all_events(
        &self,
        msg_id: MessageId,
        query_origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        let result = match self.replicas.all_events().await {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeQueryResponse {
                response: Transfers(GetReplicaEvents(result)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin,
                target_section_pk: None,
            },
            dst: query_origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get latest StoreCost for the given number of bytes.
    /// Also check for Section storage capacity and report accordingly.
    async fn get_store_cost(
        &self,
        bytes: u64,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        info!("Computing StoreCost for {:?} bytes", bytes);
        let result = self.rate_limit.from(bytes).await;

        info!("Got StoreCost {:?}", result);

        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetStoreCost(Ok(result)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
                target_section_pk: None,
            },
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get the PublicKeySet of our replicas
    async fn get_replica_pks(
        &self,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        // validate signature
        let pk_set = self.replicas.replicas_pk_set();

        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetReplicaKeys(Ok(pk_set)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
                target_section_pk: None,
            },
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn balance(
        &self,
        wallet_id: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        debug!("Getting balance for {:?}", wallet_id);

        // validate signature
        let result = match self.replicas.balance(wallet_id).await {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetBalance(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
                target_section_pk: None,
            },
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_wallet_replicas(
        &self,
        _wallet_key: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        info!(">>> Handling GetSectionWalletReplicas query");
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        // todo: validate signature
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeQueryResponse {
                response: Transfers(GetWalletReplicas(self.replicas.replicas_pk_set())),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
                target_section_pk: None,
            },
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination, // this has to be sorted out by recipient..
        }))
    }

    async fn history(
        &self,
        wallet_id: &PublicKey,
        _since_version: usize,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        trace!("Handling GetHistory");
        // validate signature
        let result = self
            .replicas
            .history(*wallet_id)
            .await
            .map_err(|_e| ErrorMessage::NoHistoryForPublicKey(*wallet_id));

        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetHistory(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
                target_section_pk: None,
            },
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination, // this has to be sorted out by recipient..
        }))
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    async fn validate(
        &self,
        transfer: SignedTransfer,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        debug!("Validating a transfer from msg_id: {:?}", msg_id);
        match self.replicas.validate(transfer).await {
            Ok(event) => Ok(NodeMessagingDuty::Send(OutgoingMsg {
                msg: Message::Event {
                    event: Event::TransferValidated { event },
                    id: MessageId::new(),
                    correlation_id: msg_id,
                    target_section_pk: None,
                },
                dst: origin.to_dst(),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            })),
            Err(e) => {
                let message_error = convert_to_error_message(e)?;
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::CmdError {
                        id: MessageId::in_response_to(&msg_id),
                        error: CmdError::Transfer(TransferError::TransferValidation(message_error)),
                        correlation_id: msg_id,
                        cmd_origin: origin,
                        target_section_pk: None,
                    },
                    dst: origin.to_dst(),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    async fn validate_section_payout(
        &self,
        transfer: SignedTransferShare,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        debug!(">>>>> validatin....");

        if let Some(id) = self
            .recently_validated_transfers
            .lock()
            .await
            .get(&transfer.id())
        {
            debug!(
                ">>>>>>>>> seen this transfer as valid already {:?} ",
                transfer.id()
            );
            // we've done this before so we can safely just return No op
            return Ok(NodeMessagingDuty::NoOp);
        }

        match self.replicas.propose_validation(&transfer).await {
            Ok(None) => return Ok(NodeMessagingDuty::NoOp),
            Ok(Some(event)) => {
                debug!(">>>>> is valid!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                let _ = self
                    .recently_validated_transfers
                    .lock()
                    .await
                    .insert(transfer.id());
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeEvent {
                        event: NodeEvent::SectionPayoutValidated(event),
                        id: MessageId::new(),
                        correlation_id: msg_id,
                        target_section_pk: None,
                    },
                    dst: DstLocation::Section(origin.name()),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
            Err(e) => {
                error!(">>>> transfer is not valid! {:?}", e);
                let message_error = convert_to_error_message(e)?;
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmdError {
                        id: MessageId::in_response_to(&msg_id),
                        error: NodeCmdError::Transfers(NodeTransferError::TransferPropagation(
                            message_error,
                        )), // TODO: SHOULD BE TRANSFERVALIDATION
                        correlation_id: msg_id,
                        cmd_origin: origin,
                        target_section_pk: None,
                    },
                    dst: origin.to_dst(),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    async fn register(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        //origin: Address,
    ) -> Result<NodeMessagingDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                let location = event.transfer_proof.recipient().into();
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: Transfers(PropagateTransfer(event.transfer_proof)),
                        id: MessageId::in_response_to(&msg_id),
                        target_section_pk: None,
                    },
                    dst: DstLocation::Section(location),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,  // not necessary, but will be slimmer
                }))
            }
            Err(e) => {
                let message_error = convert_to_error_message(e)?;
                Ok(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::CmdError {
                        error: CmdError::Transfer(TransferError::TransferRegistration(
                            message_error,
                        )),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                        cmd_origin: SrcLocation::EndUser(EndUser::AllClients(proof.sender())),
                        target_section_pk: None,
                    },
                    dst: DstLocation::EndUser(EndUser::AllClients(proof.sender())),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    async fn register_section_payout(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NetworkDuties> {
        debug!(">>> registering section payout");
        use NodeCmd::*;
        use NodeEvent::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                debug!(">>> in match ok");
                let mut ops: NetworkDuties = vec![];
                // notify sending section
                let location = event.transfer_proof.sender().into();
                ops.push(
                    NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::NodeEvent {
                            event: SectionPayoutRegistered {
                                from: event.transfer_proof.sender(),
                                to: event.transfer_proof.recipient(),
                            },
                            id: MessageId::in_response_to(&msg_id),
                            correlation_id: msg_id,
                            target_section_pk: None,
                        },
                        dst: DstLocation::Section(location),
                        aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                    })
                    .into(),
                );
                // notify receiving section
                let location = event.transfer_proof.recipient().into();
                ops.push(
                    NodeMessagingDuty::Send(OutgoingMsg {
                        msg: Message::NodeCmd {
                            cmd: Transfers(PropagateTransfer(event.transfer_proof)),
                            id: MessageId::new(),
                            target_section_pk: None,
                        },
                        dst: DstLocation::Section(location),
                        aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,  // not necessary, but will be slimmer
                    })
                    .into(),
                );
                Ok(ops)
            }
            Err(e) => {
                debug!(">>> Error in match payout, {:?}", e);
                let message_error = convert_to_error_message(e)?;
                Ok(NetworkDuties::from(NodeMessagingDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmdError {
                        error: NodeCmdError::Transfers(
                            NodeTransferError::SectionPayoutRegistration(message_error),
                        ),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                        cmd_origin: origin,
                        target_section_pk: None,
                    },
                    dst: origin.to_dst(),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                })))
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
        origin: SrcLocation,
    ) -> Result<NodeMessagingDuty> {
        use NodeTransferError::*;
        // We will just validate the proofs and then apply the event.
        let msg = match self.replicas.receive_propagated(credit_proof).await {
            Ok(_) => return Ok(NodeMessagingDuty::NoOp),
            Err(Error::NetworkData(error)) => {
                let message_error = convert_dt_error_to_error_message(error)?;
                Message::NodeCmdError {
                    error: NodeCmdError::Transfers(TransferPropagation(message_error)),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                    cmd_origin: origin,
                    target_section_pk: None,
                }
            }
            Err(Error::InvalidPropagatedTransfer(error)) => {
                error!(
                    ">> Error now being handled w/ fake Nosuchkeymsg at receive_propagated, {:?}",
                    error
                );

                // Nonsense error just not to crash node for now. Should be converted properly to be handled at client.
                Message::NodeCmdError {
                    error: NodeCmdError::Transfers(TransferPropagation(ErrorMessage::NoSuchKey)),
                    id: MessageId::new(),
                    correlation_id: msg_id,
                    cmd_origin: origin,
                    target_section_pk: None,
                }
            }
            Err(_e) => unimplemented!("receive_propagated"),
        };
        Ok(NodeMessagingDuty::Send(OutgoingMsg {
            msg,
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
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
