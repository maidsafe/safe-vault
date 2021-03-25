// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod genesis;
pub mod get_replicas;
pub mod replica_signing;
pub mod replicas;
pub mod store;
mod test_utils;

use self::{
    replica_signing::ReplicaSigning,
    replicas::{ReplicaInfo, Replicas},
};
use crate::{
    capacity::RateLimit,
    error::{convert_dt_error_to_error_message, convert_to_error_message},
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    utils, Error, Result,
};
use log::{debug, error, info, trace, warn};
use replica_signing::ReplicaSigningImpl;
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_routing::XorName;
use std::collections::{BTreeMap, HashSet};

use futures::lock::Mutex;
use sn_data_types::{
    ActorHistory, CreditAgreementProof, DebitId, PublicKey, ReplicaEvent, SignedTransfer,
    SignedTransferShare, TransferAgreementProof, TransferPropagated,
};
use sn_messaging::{
    client::{
        Cmd, CmdError, Error as ErrorMessage, Event, NodeCmd, NodeCmdError, NodeEvent,
        NodeQueryResponse, NodeTransferCmd, NodeTransferError, NodeTransferQueryResponse,
        ProcessMsg, QueryResponse, TransferError,
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
2. Elders-to-Elders: NodeEvent::RewardPayoutValidated
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
#[derive(Clone)]
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

    ///
    pub fn user_wallets(&self) -> BTreeMap<PublicKey, ActorHistory> {
        self.replicas.user_wallets()
    }

    pub fn merge(&mut self, user_wallets: BTreeMap<PublicKey, ActorHistory>) {
        self.replicas.merge(user_wallets);
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
    pub async fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<()> {
        self.rate_limit.increase_full_node_count(node_id).await
    }

    /// Get latest StoreCost for the given number of bytes.
    /// Also check for Section storage capacity and report accordingly.
    pub async fn get_store_cost(
        &self,
        bytes: u64,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> NodeDuty {
        let result = self.rate_limit.from(bytes).await;
        info!("StoreCost for {:?} bytes: {}", bytes, result);
        NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetStoreCost(Ok(result)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        })
        //let mut ops = vec![];
        //ops.push();
        //ops.push(Ok(ElderDuty::SwitchNodeJoin(self.rate_limit.check_network_storage().await).into()));
        //ops
    }

    ///
    pub fn update_replica_info(&mut self, info: ReplicaInfo<ReplicaSigningImpl>) {
        self.replicas.update_replica_info(info);
    }

    /// Initiates a new Replica with the
    /// state of existing Replicas in the group.
    pub async fn initiate_replica(&self, events: &[ReplicaEvent]) -> Result<NodeDuty> {
        // We must be able to initiate the replica, otherwise this node cannot function.
        self.replicas.initiate(events).await?;
        Ok(NodeDuty::NoOp)
    }

    /// Makes sure the payment contained
    /// within a data write, is credited
    /// to the section funds.
    pub async fn process_payment(&self, msg: &ProcessMsg, origin: EndUser) -> Result<NodeDuty> {
        debug!(">>>> processing payment");
        let (payment, data_cmd, num_bytes, dst_address) = match &msg {
            ProcessMsg::Cmd {
                cmd: Cmd::Data { payment, cmd },
                ..
            } => (
                payment,
                cmd,
                utils::serialise(cmd)?.len() as u64,
                cmd.dst_address(),
            ),
            _ => return Ok(NodeDuty::NoOp),
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
            return Ok(NodeDuty::Send(OutgoingMsg {
                msg: ProcessMsg::CmdError {
                    error: CmdError::Transfer(TransferRegistration(ErrorMessage::NoSuchRecipient)),
                    id: MessageId::in_response_to(&msg.id()),
                    correlation_id: msg.id(),
                },
                section_source: false, // strictly this is not correct, but we don't expect responses to a response..
                dst: origin.to_dst(),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            }));
        }
        let registration = self.replicas.register(&payment).await;
        let result = match registration {
            Ok(_) => match self
                .replicas
                .receive_propagated(payment.sender().into(), &payment.credit_proof())
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
                    return Ok(NodeDuty::Send(OutgoingMsg {
                        msg: ProcessMsg::CmdError {
                            error: CmdError::Transfer(TransferRegistration(
                                ErrorMessage::InsufficientBalance,
                            )),
                            id: MessageId::in_response_to(&msg.id()),
                            correlation_id: msg.id(),
                        },
                        section_source: false, // strictly this is not correct, but we don't expect responses to a response..
                        dst: origin.to_dst(),
                        aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                    }));
                }
                info!("Payment: forwarding data..");
                // consider having the section actor be
                // informed of this transfer as well..
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeCmd {
                        cmd: NodeCmd::Metadata {
                            cmd: data_cmd.clone(),
                            origin,
                        },
                        id: MessageId::in_response_to(&msg.id()),
                    },
                    section_source: true, // i.e. errors go to our section
                    dst: DstLocation::Section(dst_address),
                    aggregation: Aggregation::AtDestination,
                }))
            }
            Err(e) => {
                warn!("Payment: registration or propagation failed: {}", e);
                let origin = SrcLocation::EndUser(EndUser::AllClients(payment.sender()));
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::CmdError {
                        error: CmdError::Transfer(TransferRegistration(
                            ErrorMessage::PaymentFailed,
                        )),
                        id: MessageId::in_response_to(&msg.id()),
                        correlation_id: msg.id(),
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
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
    pub async fn all_events(
        &self,
        msg_id: MessageId,
        query_origin: SrcLocation,
    ) -> Result<NodeDuty> {
        let result = match self.replicas.all_events().await {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::NodeQueryResponse {
                response: Transfers(GetReplicaEvents(result)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: query_origin.to_dst(),
            aggregation: Aggregation::AtDestination,
        }))
    }

    pub async fn balance(
        &self,
        wallet_id: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        debug!("Getting balance for {:?}", wallet_id);

        // validate signature
        let result = match self.replicas.balance(wallet_id).await {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetBalance(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    pub async fn history(
        &self,
        wallet_id: &PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        trace!("Handling GetHistory");
        // validate signature
        let result = self
            .replicas
            .history(*wallet_id)
            .map_err(|_e| ErrorMessage::NoHistoryForPublicKey(*wallet_id));

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetHistory(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination, // this has to be sorted out by recipient..
        }))
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    pub async fn validate(
        &self,
        transfer: SignedTransfer,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        debug!("Validating a transfer from msg_id: {:?}", msg_id);
        match self.replicas.validate(transfer).await {
            Ok(event) => Ok(NodeDuty::Send(OutgoingMsg {
                msg: ProcessMsg::Event {
                    event: Event::TransferValidated { event },
                    id: MessageId::new(),
                    correlation_id: msg_id,
                },
                section_source: false, // strictly this is not correct, but we don't expect responses to an event..
                dst: origin.to_dst(),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            })),
            Err(e) => {
                let message_error = convert_to_error_message(e)?;
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::CmdError {
                        id: MessageId::in_response_to(&msg_id),
                        error: CmdError::Transfer(TransferError::TransferValidation(message_error)),
                        correlation_id: msg_id,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: origin.to_dst(),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// This validation will render a signature over the
    /// original request (ValidateTransfer), giving a partial
    /// proof by this individual Elder, that the transfer is valid.
    pub async fn validate_section_payout(
        &self,
        transfer: SignedTransferShare,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        debug!(">>>>> validating....");

        if let Some(_id) = self
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
            return Ok(NodeDuty::NoOp);
        }

        match self.replicas.propose_validation(&transfer).await {
            Ok(None) => return Ok(NodeDuty::NoOp),
            Ok(Some(event)) => {
                debug!(">>>>> reward payout validated!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                let _ = self
                    .recently_validated_transfers
                    .lock()
                    .await
                    .insert(transfer.id());
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeEvent {
                        event: NodeEvent::RewardPayoutValidated(event),
                        id: MessageId::new(),
                        correlation_id: msg_id,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an event..
                    dst: DstLocation::Section(origin.name()),
                    aggregation: Aggregation::None, // outer msg cannot be aggregated due to containing sig share
                }))
            }
            Err(e) => {
                error!(">>>> transfer is not valid! {:?}", e);
                let message_error = convert_to_error_message(e)?;
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeCmdError {
                        id: MessageId::in_response_to(&msg_id),
                        error: NodeCmdError::Transfers(NodeTransferError::TransferPropagation(
                            message_error,
                        )), // TODO: SHOULD BE TRANSFERVALIDATION
                        correlation_id: msg_id,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: origin.to_dst(),
                    aggregation: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    pub async fn register(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        //origin: Address,
    ) -> Result<NodeDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                let location = event.transfer_proof.recipient().into();
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeCmd {
                        cmd: Transfers(PropagateTransfer(event.transfer_proof.credit_proof())),
                        id: MessageId::in_response_to(&msg_id),
                    },
                    section_source: true, // i.e. errors go to our section
                    dst: DstLocation::Section(location),
                    aggregation: Aggregation::AtDestination,
                }))
            }
            Err(e) => {
                let message_error = convert_to_error_message(e)?;
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::CmdError {
                        error: CmdError::Transfer(TransferError::TransferRegistration(
                            message_error,
                        )),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: DstLocation::EndUser(EndUser::AllClients(proof.sender())),
                    aggregation: Aggregation::AtDestination,
                }))
            }
        }
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    pub async fn register_reward_payout(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuties> {
        debug!(">>> registering section payout");
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                debug!(">>> in match ok");
                let mut ops: NodeDuties = vec![];
                // notify receiving section
                let location = event.transfer_proof.recipient().into();
                ops.push(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeCmd {
                        cmd: Transfers(PropagateTransfer(event.transfer_proof.credit_proof())),
                        id: MessageId::in_response_to(&msg_id),
                    },
                    section_source: true, // i.e. errors go to our section
                    dst: DstLocation::Section(location),
                    aggregation: Aggregation::AtDestination, // not necessary, but will be slimmer
                }));
                Ok(ops)
            }
            Err(e) => {
                debug!(">>> Error in match payout, {:?}", e);
                let message_error = convert_to_error_message(e)?;
                Ok(NodeDuties::from(NodeDuty::Send(OutgoingMsg {
                    msg: ProcessMsg::NodeCmdError {
                        error: NodeCmdError::Transfers(
                            NodeTransferError::SectionPayoutRegistration(message_error),
                        ),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                    },
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: origin.to_dst(),
                    aggregation: Aggregation::AtDestination,
                })))
            }
        }
    }

    /// The only step that is triggered by a Replica.
    /// (See fn register_transfer).
    /// After a successful registration of a transfer at
    /// the source, the transfer is propagated to the destination.
    pub async fn receive_propagated(
        &self,
        credit_proof: &CreditAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        use NodeTransferError::*;
        // We will just validate the proofs and then apply the event.
        let msg = match self
            .replicas
            .receive_propagated(origin.name(), credit_proof)
            .await
        {
            Ok(_) => return Ok(NodeDuty::NoOp),
            Err(Error::NetworkData(error)) => {
                let message_error = convert_dt_error_to_error_message(error)?;
                ProcessMsg::NodeCmdError {
                    error: NodeCmdError::Transfers(TransferPropagation(message_error)),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                }
            }
            Err(Error::Transfer(sn_transfers::Error::SectionKeyNeverExisted)) => {
                error!(">> SectionKeyNeverExisted at receive_propagated");
                ProcessMsg::NodeCmdError {
                    error: NodeCmdError::Transfers(TransferPropagation(ErrorMessage::NoSuchKey)),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                }
            }
            Err(e) => unimplemented!("receive_propagated: {}", e),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg,
            section_source: false, // strictly this is not correct, but we don't expect responses to an error..
            dst: origin.to_dst(),
            aggregation: Aggregation::AtDestination,
        }))
    }

    #[cfg(feature = "simulated-payouts")]
    pub async fn pay(&mut self, transfer: Transfer) -> Result<NodeDuty> {
        // self.replicas.credit_without_proof(transfer).await
        self.replicas.debit_without_proof(transfer).await
    }

    #[cfg(feature = "simulated-payouts")]
    pub async fn credit_without_proof(&mut self, transfer: Transfer) -> Result<NodeDuty> {
        // self.replicas.credit_without_proof(transfer).await
        self.replicas.credit_without_proof(transfer).await
    }
}

impl Display for Transfers {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transfers")
    }
}
