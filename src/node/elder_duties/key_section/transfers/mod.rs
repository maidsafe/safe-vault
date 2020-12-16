// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod genesis;
pub mod replicas;
pub mod store;

use self::replicas::Replicas;
use crate::{
    capacity::RateLimit,
    node::keys::NodeSigningKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{
        ElderDuty, IntoNodeOp, NodeMessagingDuty, NodeOperation, RewardCmd, RewardDuty,
        TransferCmd, TransferDuty, TransferQuery,
    },
    utils, Error, ReplicaInfo, Result,
};
use log::{debug, info, trace, warn};
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_data_types::{
    Address, Cmd, CmdError, CreditAgreementProof, ElderDuties, Error as NdError, Event, Message,
    MessageId, MsgEnvelope, NodeCmd, NodeCmdError, NodeEvent, NodeQuery, NodeQueryResponse,
    NodeTransferCmd, NodeTransferError, NodeTransferQuery, NodeTransferQueryResponse, PublicKey,
    QueryResponse, ReplicaEvent, SignedTransfer, TransferAgreementProof, TransferError, WalletInfo,
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

    pub async fn genesis(&self) -> Result<NodeOperation> {
        let _ = self.replicas.initiate(&[]).await?;
        // if we are genesis, we would get the genesis event via this call
        let events = self.replicas.history(self.section_wallet_id()).await?;

        match self.replicas.balance(self.section_wallet_id()).await {
            Ok(balance) => info!("Genesis balance: {}", balance),
            Err(e) => warn!("what what?!?! {}", e),
        };

        // make sure we init section wallet
        let section_key = PublicKey::Bls(self.replicas.replicas_pk_set().public_key());
        Ok(RewardDuty::ProcessCmd {
            cmd: RewardCmd::InitiateSectionWallet(WalletInfo {
                replicas: self.replicas.replicas_pk_set(),
                history: events.to_vec(),
            }),
            msg_id: MessageId::new(),
            origin: Address::Section(section_key.into()),
        }
        .into())
    }

    /// Issues a query to existing Replicas
    /// asking for their events, as to catch up and
    /// start working properly in the group.
    pub async fn catchup_with_replicas(&self) -> Result<NodeOperation> {
        info!("Transfers: Catching up with transfer Replicas!");
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
    pub async fn section_split(&self, prefix: Prefix) -> Result<NodeOperation> {
        // Removes keys that are no longer our section responsibility.
        let _ = self.replicas.keep_keys_of(prefix).await?;
        Ok(NodeOperation::NoOp)
    }

    ///
    pub fn increase_full_node_count(&mut self, node_id: PublicKey) {
        self.rate_limit.increase_full_node_count(node_id)
    }

    /// When handled by Elders in the dst
    /// section, the actual business logic is executed.
    pub async fn process_transfer_duty(&self, duty: &TransferDuty) -> Result<NodeOperation> {
        trace!("Processing transfer duty");
        use TransferDuty::*;
        match duty {
            ProcessQuery {
                query,
                msg_id,
                origin,
            } => self.process_query(query, *msg_id, origin.clone()).await,
            ProcessCmd {
                cmd,
                msg_id,
                origin,
            } => self
                .process_cmd(cmd, *msg_id, origin.clone())
                .await
                .convert(),
            NoOp => Ok(NodeOperation::NoOp),
        }
    }

    async fn process_query(
        &self,
        query: &TransferQuery,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeOperation> {
        use TransferQuery::*;
        let result = match query {
            CatchUpWithSectionWallet(wallet_id) => {
                self.catchup_with_section_wallet(*wallet_id, msg_id, origin)
                    .await
            }
            GetNewSectionWallet(wallet_id) => {
                self.get_new_section_wallet(*wallet_id, msg_id, origin)
                    .await
            }
            GetReplicaEvents => self.all_events(msg_id, origin).await,
            GetReplicaKeys(_wallet_id) => self.get_replica_pks(msg_id, origin).await,
            GetBalance(wallet_id) => self.balance(*wallet_id, msg_id, origin).await,
            GetHistory { at, since_version } => {
                self.history(at, *since_version, msg_id, origin).await
            }
            GetStoreCost { bytes, .. } => {
                let first = self.get_store_cost(*bytes, msg_id, origin).await.convert();
                let second = Ok(ElderDuty::SwitchNodeJoin(
                    self.rate_limit.check_network_storage().await,
                )
                .into());
                return Ok(vec![first, second].into());
            }
        };
        result.convert()
    }

    async fn process_cmd(
        &self,
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
            SimulatePayout(transfer) => self.replicas.credit_without_proof(transfer.clone()).await,
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
        match result {
            Ok(_) => {
                info!("Payment: registration and propagation succeeded.");
                // Paying too little will see the amount be forfeited.
                // This prevents spam of the network.
                let total_cost = self.rate_limit.from(num_bytes).await;
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
            Err(e) => {
                warn!("Payment: registration or propagation failed: {}", e);
                self.wrapping
                    .error(
                        CmdError::Transfer(TransferRegistration(NdError::NetworkOther(
                            e.to_string(),
                        ))),
                        msg.id(),
                        &msg.origin.address(),
                    )
                    .await
            }
        }
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
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    /// Get latest StoreCost for the given number of bytes.
    /// Also check for Section storage capacity and report accordingly.
    async fn get_store_cost(
        &self,
        bytes: u64,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        info!("Computing StoreCost for {:?} bytes", bytes);
        let result = self.rate_limit.from(bytes).await;

        info!("Got StoreCost {:?}", result);

        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetStoreCost(Ok(result)),
                id: MessageId::in_response_to(&msg_id),
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
                id: MessageId::in_response_to(&msg_id),
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

        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetBalance(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    async fn catchup_with_section_wallet(
        &self,
        wallet_id: PublicKey,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        info!("Handling CatchUpWithSectionWallet query");
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        // todo: validate signature
        let result = match self.replicas.history(wallet_id).await {
            Ok(history) => Ok(WalletInfo {
                replicas: self.replicas.replicas_pk_set(),
                history,
            }),
            Err(e) => Err(NdError::Unexpected(e.to_string())),
        };

        self.wrapping
            .send_to_node(Message::NodeQueryResponse {
                response: Transfers(CatchUpWithSectionWallet(result)),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                query_origin: origin,
            })
            .await
    }

    async fn get_new_section_wallet(
        &self,
        wallet_id: PublicKey,
        msg_id: MessageId,
        origin: Address,
    ) -> Result<NodeMessagingDuty> {
        info!("Handling GetNewSectionWallet query");
        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        // todo: validate signature
        let result = match self.replicas.history(wallet_id).await {
            Ok(history) => Ok(WalletInfo {
                replicas: self.replicas.replicas_pk_set(),
                history,
            }),
            Err(e) => Err(NdError::Unexpected(e.to_string())),
        };

        self.wrapping
            .send_to_node(Message::NodeQueryResponse {
                response: Transfers(GetNewSectionWallet(result)),
                id: MessageId::in_response_to(&msg_id),
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
        let result = self.replicas.history(*wallet_id).await.map_err(|_e| {
            NdError::Unexpected(format!("Could not get history for key {:?}", wallet_id))
        });
        self.wrapping
            .send_to_client(Message::QueryResponse {
                response: QueryResponse::GetHistory(result),
                id: MessageId::in_response_to(&msg_id),
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
