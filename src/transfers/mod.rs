// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod get_replicas;
pub mod replica_signing;
pub mod replicas;
pub mod store;
mod test_utils;

use self::replicas::{ReplicaInfo, Replicas};
use crate::{
    capacity::StoreCost,
    error::{convert_dt_error_to_error_message, convert_to_error_message},
    node_ops::{MsgType, NodeDuties, NodeDuty, OutgoingMsg},
    utils, Error, Result,
};
use futures::lock::Mutex;
use log::{debug, error, info, trace, warn};
use replica_signing::ReplicaSigningImpl;
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_data_types::{
    ActorHistory, CreditAgreementProof, DebitId, PublicKey, SignedTransfer, Token,
    TransferAgreementProof,
};
use sn_messaging::{
    client::{
        ClientMsg, ClientSigned, CmdError, DataCmd, Error as ErrorMessage, Event, ProcessMsg,
        QueryResponse, TransferError,
    },
    node::{
        NodeCmd, NodeCmdError, NodeMsg, NodeQueryResponse, NodeTransferCmd, NodeTransferError,
        NodeTransferQueryResponse,
    },
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};
use std::collections::{BTreeMap, HashSet};
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
    store_cost: StoreCost,
    // TODO: limit this? where do we store it
    recently_validated_transfers: Arc<Mutex<HashSet<DebitId>>>,
}

impl Transfers {
    pub fn new(replicas: Replicas<ReplicaSigningImpl>, store_cost: StoreCost) -> Self {
        Self {
            replicas,
            store_cost,
            recently_validated_transfers: Arc::default(),
        }
    }

    /// The total amount in wallets managed
    /// by the replicas in this section.
    pub async fn managed_amount(&self) -> Result<Token> {
        self.replicas.managed_amount().await
    }

    ///
    pub fn user_wallets(&self) -> BTreeMap<PublicKey, ActorHistory> {
        self.replicas.user_wallets()
    }

    pub async fn merge(&mut self, user_wallets: BTreeMap<PublicKey, ActorHistory>) -> Result<()> {
        self.replicas.merge(user_wallets).await
    }

    /// When section splits, the Replicas in either resulting section
    /// also split the responsibility of the accounts.
    /// Thus, both Replica groups need to drop the accounts that
    /// the other group is now responsible for.
    pub async fn keep_keys_of(&self, prefix: Prefix) -> Result<()> {
        // Removes keys that are no longer our section responsibility.
        self.replicas.keep_keys_of(prefix).await
    }

    pub async fn payments(&self) -> Result<Token> {
        self.replicas.balance(self.section_wallet_id()).await
    }

    /// Get latest StoreCost for the given number of bytes.
    /// Also check for Section storage capacity and report accordingly.
    pub async fn get_store_cost(
        &mut self,
        bytes: u64,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> NodeDuties {
        let result = if bytes == 0 {
            Err(ErrorMessage::InvalidOperation(
                "Cannot store 0 bytes".to_string(),
            ))
        } else {
            match self.store_cost.from(bytes).await {
                Ok(store_cost) => {
                    info!("StoreCost for {:?} bytes: {}", bytes, store_cost);
                    Ok((bytes, store_cost, self.section_wallet_id()))
                }
                Err(e) => Err(ErrorMessage::InvalidOperation(e.to_string())), // TODO: Add `NetworkFull` error to sn_messaging
            }
        };

        let response = NodeDuty::Send(OutgoingMsg {
            msg: MsgType::Client(ClientMsg::Process(ProcessMsg::QueryResponse {
                id: MessageId::in_response_to(&msg_id),
                response: QueryResponse::GetStoreCost(result),
                correlation_id: msg_id,
            })),
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: origin.to_dst(),
            aggregation: Aggregation::AtDestination,
        });
        vec![response]
    }

    ///
    pub fn update_replica_info(&mut self, info: ReplicaInfo<ReplicaSigningImpl>) {
        self.replicas.update_replica_info(info);
    }

    /// Makes sure the payment contained
    /// within a data write, is credited
    /// to the section funds.
    pub async fn process_payment(
        &self,
        msg_id: MessageId,
        payment: TransferAgreementProof,
        data_cmd: DataCmd,
        client_signed: ClientSigned,
        origin: EndUser,
    ) -> Result<NodeDuties> {
        let num_bytes = utils::serialise(&data_cmd)?.len() as u64;

        // Make sure we are actually at the correct replicas,
        // before executing the debit.
        // (We could also add a method that executes both
        // debit + credit atomically, but this is much simpler).
        let recipient_is_not_section = payment.recipient() != self.section_wallet_id();

        use TransferError::*;
        if recipient_is_not_section {
            warn!("Payment: recipient is not section");
            let origin = SrcLocation::EndUser(origin);

            return Ok(vec![NodeDuty::Send(OutgoingMsg {
                msg: MsgType::Client(ClientMsg::Process(ProcessMsg::CmdError {
                    id: MessageId::in_response_to(&msg_id),
                    error: CmdError::Transfer(TransferRegistration(ErrorMessage::NoSuchRecipient)),
                    correlation_id: msg_id,
                })),
                section_source: false, // strictly this is not correct, but we don't expect responses to a response..
                dst: origin.to_dst(),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            })]);
        }

        let registration = self.replicas.register(&payment).await;
        let result = match registration {
            Ok(_) => match self
                .replicas
                .receive_propagated(payment.sender().into(), &payment.credit_proof())
                .await
            {
                Ok(e) => Ok(e),
                Err(error) => Err(error),
            },
            Err(error) => Err(error), // not using TransferPropagation error, since that is for NodeCmds, so wouldn't be returned to client.
        };

        match result {
            Ok(_) => {
                let (total_cost, error) = match self.store_cost.from(num_bytes).await {
                    Ok(total_cost) => {
                        if total_cost > payment.amount() {
                            // Paying too little will see the amount be forfeited.
                            // This prevents spam of the network.
                            warn!(
                                "Payment: Too low payment: {}, expected: {}",
                                payment.amount(),
                                total_cost
                            );
                            (total_cost, Some(ErrorMessage::InsufficientPayment))
                        } else {
                            (total_cost, None)
                        }
                    }
                    Err(e) => (
                        Token::from_nano(u64::MAX),
                        Some(ErrorMessage::InvalidOperation(e.to_string())), // TODO: Add `NetworkFull` error to sn_messaging
                    ),
                };
                info!("Payment: registration and propagation succeeded. (Store cost: {}, paid amount: {}.)", total_cost, payment.amount());
                info!(
                    "Section balance: {}",
                    self.replicas.balance(payment.recipient()).await?
                );
                if let Some(e) = error {
                    let origin = SrcLocation::EndUser(origin);
                    return Ok(vec![NodeDuty::Send(OutgoingMsg {
                        msg: MsgType::Client(ClientMsg::Process(ProcessMsg::CmdError {
                            id: MessageId::in_response_to(&msg_id),
                            error: CmdError::Transfer(TransferRegistration(e)),
                            correlation_id: msg_id,
                        })),
                        section_source: true, // strictly this is not correct, but we don't expect responses to a response..
                        dst: origin.to_dst(),
                        aggregation: Aggregation::AtDestination,
                    })]);
                }
                info!("Payment: forwarding data..");
                // consider having the section actor be
                // informed of this transfer as well..
                Ok(vec![NodeDuty::Send(OutgoingMsg {
                    msg: MsgType::Node(NodeMsg::NodeCmd {
                        cmd: NodeCmd::Metadata {
                            cmd: data_cmd.clone(),
                            client_signed,
                            origin,
                        },
                        id: MessageId::in_response_to(&msg_id),
                    }),
                    section_source: true, // i.e. errors go to our section
                    dst: DstLocation::Section(data_cmd.dst_address()),
                    aggregation: Aggregation::AtDestination,
                })])
            }
            Err(e) => {
                warn!("Payment: registration or propagation failed: {:?}", e);
                let origin = SrcLocation::EndUser(origin);

                Ok(vec![NodeDuty::Send(OutgoingMsg {
                    msg: MsgType::Client(ClientMsg::Process(ProcessMsg::CmdError {
                        id: MessageId::in_response_to(&msg_id),
                        error: CmdError::Transfer(TransferRegistration(
                            ErrorMessage::PaymentFailed,
                        )),
                        correlation_id: msg_id,
                    })),
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst: origin.to_dst(),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                })])
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
            Err(error) => Err(convert_to_error_message(error)),
        };
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: MsgType::Node(NodeMsg::NodeQueryResponse {
                response: Transfers(GetReplicaEvents(result)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            }),
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
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: MsgType::Client(ClientMsg::Process(ProcessMsg::QueryResponse {
                id: MessageId::in_response_to(&msg_id),
                response: QueryResponse::GetBalance(result),
                correlation_id: msg_id,
            })),
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
            msg: MsgType::Client(ClientMsg::Process(ProcessMsg::QueryResponse {
                id: MessageId::in_response_to(&msg_id),
                response: QueryResponse::GetHistory(result),
                correlation_id: msg_id,
            })),
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
        let msg = match self.replicas.validate(transfer).await {
            Ok(event) => MsgType::Client(ClientMsg::Process(ProcessMsg::Event {
                id: MessageId::new(),
                event: Event::TransferValidated { event },
                correlation_id: msg_id,
            })),
            Err(e) => {
                let message_error = convert_to_error_message(e);
                MsgType::Client(ClientMsg::Process(ProcessMsg::CmdError {
                    id: MessageId::in_response_to(&msg_id),
                    error: CmdError::Transfer(TransferError::TransferValidation(message_error)),
                    correlation_id: msg_id,
                }))
            }
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg,
            section_source: false, // strictly this is not correct, but we don't expect responses to an event..
            dst: origin.to_dst(),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Registration of a transfer is requested,
    /// with a proof of enough Elders having validated it.
    pub async fn register(
        &self,
        proof: &TransferAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        match self.replicas.register(proof).await {
            Ok(event) => {
                let location = event.transfer_proof.recipient().into();
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: MsgType::Node(NodeMsg::NodeCmd {
                        cmd: Transfers(PropagateTransfer(event.transfer_proof.credit_proof())),
                        id: MessageId::in_response_to(&msg_id),
                    }),
                    section_source: true, // i.e. errors go to our section
                    dst: DstLocation::Section(location),
                    aggregation: Aggregation::AtDestination,
                }))
            }
            Err(e) => {
                let message_error = convert_to_error_message(e);
                let dst = origin.to_dst();

                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: MsgType::Client(ClientMsg::Process(ProcessMsg::CmdError {
                        id: MessageId::in_response_to(&msg_id),
                        error: CmdError::Transfer(TransferError::TransferRegistration(
                            message_error,
                        )),
                        correlation_id: msg_id,
                    })),
                    section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                    dst,
                    aggregation: Aggregation::AtDestination,
                }))
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
                let message_error = convert_dt_error_to_error_message(error);
                NodeMsg::NodeCmdError {
                    error: NodeCmdError::Transfers(TransferPropagation(message_error)),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                }
            }
            Err(Error::UnknownSectionKey(_))
            | Err(Error::Transfer(sn_transfers::Error::SectionKeyNeverExisted)) => {
                error!(">> UnknownSectionKey at receive_propagated");
                NodeMsg::NodeCmdError {
                    error: NodeCmdError::Transfers(TransferPropagation(ErrorMessage::NoSuchKey)),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                }
            }
            Err(e) => {
                error!("Error receiving propogated: {:?}", e);

                return Err(e);
            }
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: MsgType::Node(msg),
            section_source: false, // strictly this is not correct, but we don't expect responses to an error..
            dst: origin.to_dst(),
            aggregation: Aggregation::AtDestination,
        }))
    }

    #[cfg(feature = "simulated-payouts")]
    pub async fn credit_without_proof(&mut self, transfer: Transfer) -> Result<NodeDuty> {
        self.replicas.credit_without_proof(transfer).await
    }
}

impl Display for Transfers {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transfers")
    }
}
