// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node::{
        node_duties::accumulation::Accumulation,
        node_ops::{
            AdultDuty, ChunkDuty, GatewayDuty, MetadataDuty, NodeMessagingDuty, NodeOperation,
            RewardDuty, TransferCmd, TransferDuty, TransferQuery,
        },
    },
    utils, Error, Network, Outcome, Result, TernaryResult,
};
use log::{error, info};
use sn_data_types::{
    Address, AdultDuties::ChunkStorage, Cmd, DataCmd, DataQuery, Duty, ElderDuties, Message,
    MessageId, MsgEnvelope, NodeCmd, NodeDataCmd, NodeDuties, NodeEvent, NodeQuery,
    NodeQueryResponse, NodeRewardQuery, NodeRewardQueryResponse, NodeSystemCmd, NodeTransferCmd,
    NodeTransferQuery, NodeTransferQueryResponse, Query,
};
use sn_routing::MIN_AGE;
use tiny_keccak::sha3_256;
use xor_name::XorName;

// NB: This approach is not entirely good, so will need to be improved.

/// Evaluates remote msgs from the network,
/// i.e. not msgs sent directly from a client.
pub struct NetworkMsgAnalysis {
    accumulation: Accumulation,
    routing: Network,
}

impl NetworkMsgAnalysis {
    pub fn new(routing: Network) -> Self {
        Self {
            accumulation: Accumulation::new(),
            routing,
        }
    }

    pub async fn is_dst_for(&self, msg: &MsgEnvelope) -> Result<bool> {
        let are_we_origin = self.are_we_origin(&msg).await;
        let is_dst = !are_we_origin
            && self
                .self_is_handler_for(&msg.destination()?.xorname())
                .await;
        Ok(is_dst)
    }

    async fn are_we_origin(&self, msg: &MsgEnvelope) -> bool {
        let origin = msg.origin.address().xorname();
        origin == self.routing.name().await
    }

    pub async fn evaluate(&mut self, msg: &MsgEnvelope) -> Outcome<NodeOperation> {
        let msg = if self.should_accumulate(msg).await? {
            if let Some(msg) = self.accumulation.process_message_envelope(msg)? {
                msg
            } else {
                return Ok(None);
            }
        } else {
            msg.clone() // TODO remove this clone
        };

        let result = if let Some(duty) = self.try_messaging(&msg).await? {
            // Identified as an outbound msg, to be sent on the wire.
            duty.into()
        } else if let Some(duty) = self.try_client_entry(&msg).await? {
            // Client auth cmd finalisation (Temporarily handled here, will be at app layer (Authenticator)).
            // The auth cmd has been agreed by the Gateway section.
            // (All other client msgs are handled when received from client).
            duty.into()
        } else if let Some(duty) = self.try_transfers(&msg).await? {
            duty.into()
        } else if let Some(duty) = self.try_metadata(&msg).await? {
            // Accumulated msg from `Payment`!
            duty.into()
        } else if let Some(duty) = self.try_adult(&msg).await? {
            // Accumulated msg from `Metadata`!
            duty.into()
        } else if let Some(duty) = self.try_rewards(&msg).await? {
            // Identified as a Rewards msg
            duty.into()
        } else {
            error!("Unknown message destination: {:?}", msg.id());
            return Outcome::error(Error::Logic("Unknown message destination".to_string()));
        };
        Outcome::oki(result)
    }

    async fn try_messaging(&self, msg: &MsgEnvelope) -> Outcome<NodeMessagingDuty> {
        use Address::*;
        let destined_for_network = match msg.destination()? {
            Client(address) => !self.self_is_handler_for(&address).await,
            Node(_) => self.are_we_origin(msg).await, // if we sent the msg, then it should go to network..
            Section(address) => !self.self_is_handler_for(&address).await,
        };

        if destined_for_network {
            Outcome::oki(NodeMessagingDuty::SendToSection {
                msg: msg.clone(),
                as_node: true,
            }) // Forwards without stamping the duty (was not processed).
        } else {
            Outcome::oki_no_change()
        }
    }

    // ----  Accumulation ----

    async fn should_accumulate(&self, msg: &MsgEnvelope) -> Result<bool> {
        // Incoming msg from `Payment`!
        let accumulate = self.should_accumulate_for_metadata_write(msg).await? // Metadata Elders accumulate the msgs from Payment Elders.
            // Incoming msg from `Metadata`!
            || self.should_accumulate_for_adult(msg).await? // Adults accumulate the msgs from Metadata Elders.
            || self.should_accumulate_for_rewards(msg).await?; // Rewards Elders accumulate the claim counter cmd from other Rewards Elders

        Ok(accumulate)
    }

    /// The individual Payment Elder nodes send their msgs
    /// to Metadata section, where it is accumulated.
    async fn should_accumulate_for_metadata_write(&self, msg: &MsgEnvelope) -> Result<bool> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(false);
        };

        let from_single_payment_elder = || {
            let res = msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Payment));
            info!("from single payment elder: {:?}", res);
            res
        };
        let is_data_cmd = || {
            let res = matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            });
            info!("is data cmd: {:?}", res);
            res
        };

        let accumulate = is_data_cmd()
            && from_single_payment_elder()
            && self.is_dst_for(msg).await?
            && self.is_elder().await;

        Ok(accumulate)
    }

    async fn should_accumulate_for_rewards(&self, msg: &MsgEnvelope) -> Result<bool> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(false);
        };
        let from_single_rewards_elder = || {
            let res = msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Rewards));
            info!("from single rewards elder: {:?}", res);
            res
        };
        let is_accumulating_reward_query = || {
            let res = matches!(msg.message, Message::NodeQuery {
                query: NodeQuery::Rewards(NodeRewardQuery::GetWalletId { .. }),
                ..
            });
            info!("is accumulating reward query: {:?}", res);
            res
        };

        let accumulate = is_accumulating_reward_query()
            && from_single_rewards_elder()
            && self.is_dst_for(msg).await?
            && self.is_elder().await;

        Ok(accumulate)
    }

    /// Adults accumulate the write requests from Elders.
    async fn should_accumulate_for_adult(&self, msg: &MsgEnvelope) -> Result<bool> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(false);
        };
        let from_single_metadata_elder = msg.most_recent_sender().is_elder()
            && matches!(duty, Duty::Elder(ElderDuties::Metadata));

        info!(
            "from single metadata elder: {:?}",
            from_single_metadata_elder
        );

        if !from_single_metadata_elder {
            return Ok(false);
        }

        let is_chunk_msg = matches!(msg.message,
        Message::Cmd {
            cmd:
                Cmd::Data {
                    cmd: DataCmd::Blob(_),
                    ..
                },
            ..
        }
        | Message::Query { // TODO: Should not accumulate queries, just pass them through.
            query: Query::Data(DataQuery::Blob(_)),
            ..
        });
        info!("is chunk msg: {:?}", is_chunk_msg);

        let duplication_msg = matches!(msg.message,
        Message::NodeCmd { cmd: NodeCmd::Data(NodeDataCmd::DuplicateChunk { .. }), .. });
        info!("is duplication msg: {:?}", duplication_msg);

        if !(is_chunk_msg || duplication_msg) {
            return Ok(false);
        }

        let accumulate = self.is_dst_for(msg).await? && self.is_adult().await;
        info!("Accumulating as Adult");
        Ok(accumulate)
    }

    // ---- .... -----

    // todo: eval all msg types!
    async fn try_client_entry(&self, msg: &MsgEnvelope) -> Outcome<GatewayDuty> {
        let is_our_client_msg = match msg.destination()? {
            Address::Client(address) => self.self_is_handler_for(&address).await,
            _ => false,
        };

        let shall_process = is_our_client_msg && self.is_elder().await;

        if !shall_process {
            return Ok(None);
        }

        Outcome::oki(GatewayDuty::FindClientFor(msg.clone()))
    }

    /// After the data write sent from Payment Elders has been
    /// accumulated (can be seen since the sender is `Section`),
    /// it is time to actually carry out the write operation.
    async fn try_metadata(&self, msg: &MsgEnvelope) -> Outcome<MetadataDuty> {
        let is_data_cmd = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let from_payment_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Payment))
        };

        let is_data_query = || {
            matches!(msg.message, Message::Query {
                query: Query::Data(_),
                ..
            })
        };
        let from_single_gateway_elder = || {
            msg.most_recent_sender().is_elder() && matches!(duty, Duty::Elder(ElderDuties::Gateway))
        };

        let is_correct_dst = self.is_dst_for(msg).await? && self.is_elder().await;

        let duty = if is_data_query() && from_single_gateway_elder() && is_correct_dst {
            MetadataDuty::ProcessRead(msg.clone()) // TODO: Fix these for type safety
        } else if is_data_cmd() && from_payment_section() && is_correct_dst {
            MetadataDuty::ProcessWrite(msg.clone()) // TODO: Fix these for type safety
        } else {
            return Ok(None);
        };
        Outcome::oki(duty)
    }

    /// When the write requests from Elders has been accumulated
    /// at an Adult, it is time to carry out the write operation.
    async fn try_adult(&self, msg: &MsgEnvelope) -> Outcome<AdultDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let from_metadata_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Metadata))
        };

        let from_adult_for_chunk_duplication = matches!(duty, Duty::Adult(ChunkStorage));

        // TODO: Should not accumulate queries, just pass them through.
        let is_chunk_query = || {
            matches!(msg.message, Message::Query {
                query: Query::Data(DataQuery::Blob(_)),
                ..
            })
        };

        let is_chunk_cmd = || {
            matches!(msg.message,
            Message::Cmd {
                cmd:
                    Cmd::Data {
                        cmd: DataCmd::Blob(_),
                        ..
                    },
                ..
            })
        };

        let shall_process = (from_metadata_section() || from_adult_for_chunk_duplication)
            && self.is_dst_for(&msg).await?
            && self.is_adult().await;

        if !shall_process {
            return Ok(None);
        }

        info!("Checking chunking duplication!");
        let is_chunk_duplication = match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::Data(cmd),
                ..
            } => match cmd {
                NodeDataCmd::DuplicateChunk {
                    fetch_from_holders,
                    address,
                    ..
                } => {
                    info!("Creating request for duplicating chunk");
                    Some(RequestForChunk {
                        targets: fetch_from_holders.clone(),
                        address: *address,
                        section_authority: msg.most_recent_sender().clone(),
                    })
                }
                NodeDataCmd::GetChunk {
                    section_authority,
                    new_holder,
                    address,
                    fetch_from_holders,
                } => {
                    info!("Verifying GetChunk Message!");
                    let proof_chain = self.routing.our_history().await;

                    // Recreate original MessageId from Section
                    let mut hash_bytes = Vec::new();
                    hash_bytes.extend_from_slice(&address.name().0);
                    hash_bytes.extend_from_slice(&new_holder.0);
                    let msg_id = MessageId(XorName(sha3_256(&hash_bytes)));

                    // Recreate Message that was sent by the message.
                    let message = Message::NodeCmd {
                        cmd: NodeCmd::Data(NodeDataCmd::DuplicateChunk {
                            new_holder: *new_holder,
                            address: *address,
                            fetch_from_holders: fetch_from_holders.clone(),
                        }),
                        id: msg_id,
                    };

                    // Verify that the message was
                    let verify_section_authority =
                        section_authority.verify(&utils::serialise(&message));

                    let given_section_pk =
                        &section_authority.id().public_key().bls().ok_or_else(|| {
                            Error::Logic("Section Key cannot be non-BLS".to_string())
                        })?;

                    // Verify that the DuplicateChunk Msg was sent with SectionAuthority
                    if section_authority.is_section()
                        && verify_section_authority
                        && proof_chain.has_key(given_section_pk)
                    {
                        info!("Creating internal Cmd for ReplyForDuplication");
                        Some(ReplyForDuplication {
                            address: *address,
                            new_holder: *new_holder,
                            correlation_id: msg_id,
                        })
                    } else {
                        None
                    }
                }
                NodeDataCmd::GiveChunk {
                    blob,
                    correlation_id,
                    ..
                } => {
                    info!("Verifying GiveChunk Message!");
                    // Recreate original MessageId from Section
                    let mut hash_bytes = Vec::new();
                    hash_bytes.extend_from_slice(&blob.address().name().0);
                    hash_bytes.extend_from_slice(&self.routing.name().await.0);
                    let msg_id = MessageId(XorName(sha3_256(&hash_bytes)));
                    if msg_id == *correlation_id {
                        Some(StoreDuplicatedBlob {
                            // TODO: Remove the clone
                            blob: blob.clone(),
                        })
                    } else {
                        info!("Given blob is incorrect.");
                        None
                    }
                }
            },
            _ => None,
        };

        use AdultDuty::*;
        use ChunkDuty::*;
        let duty = if is_chunk_cmd() {
            RunAsChunks(WriteChunk(msg.clone()))
        } else if is_chunk_query() {
            RunAsChunks(ReadChunk(msg.clone()))
        } else if let Some(request) = is_chunk_duplication {
            request
        } else {
            return Ok(None);
        };
        Outcome::oki(duty)
    }

    async fn try_rewards(&self, msg: &MsgEnvelope) -> Outcome<RewardDuty> {
        let result = self.try_nonacc_rewards(msg).await;
        if result.has_value() || result.is_err() {
            return result;
        }
        let result = self.try_accumulated_rewards(msg).await;
        if result.has_value() || result.is_err() {
            return result;
        }
        self.try_wallet_register(msg).await
    }

    async fn try_wallet_register(&self, msg: &MsgEnvelope) -> Outcome<RewardDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let is_node_config = || matches!(duty, Duty::Node(NodeDuties::NodeConfig));
        let shall_process =
            is_node_config() && self.is_dst_for(msg).await? && self.is_elder().await;

        if !shall_process {
            return Ok(None);
        }

        match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet { wallet, .. }),
                ..
            } => Outcome::oki(RewardDuty::SetNodeWallet {
                wallet_id: *wallet,
                node_id: msg.origin.address().xorname(),
            }),
            _ => Ok(None),
        }
    }

    // Check non-accumulated reward msgs.
    async fn try_nonacc_rewards(&self, msg: &MsgEnvelope) -> Outcome<RewardDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let from_single_rewards_elder = || {
            msg.most_recent_sender().is_elder() && matches!(duty, Duty::Elder(ElderDuties::Rewards))
        };

        let shall_process =
            from_single_rewards_elder() && self.is_dst_for(msg).await? && self.is_elder().await;

        if !shall_process {
            return Ok(None);
        }

        // SectionPayoutValidated and GetWalletId
        // do not need accumulation since they are accumulated in the domain logic.
        use NodeRewardQueryResponse::*;
        match &msg.message {
            Message::NodeEvent {
                event: NodeEvent::SectionPayoutValidated(validation),
                ..
            } => Outcome::oki(RewardDuty::ReceivePayoutValidation(validation.clone())),
            Message::NodeQueryResponse {
                response: NodeQueryResponse::Rewards(GetWalletId(Ok((wallet_id, new_node_id)))),
                ..
            } => Outcome::oki(RewardDuty::ActivateNodeRewards {
                id: *wallet_id,
                node_id: *new_node_id,
            }),
            _ => Ok(None),
        }
    }

    // Check accumulated reward msgs.
    async fn try_accumulated_rewards(&self, msg: &MsgEnvelope) -> Outcome<RewardDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let from_rewards_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Rewards))
        };

        let shall_process_accumulated =
            from_rewards_section() && self.is_dst_for(msg).await? && self.is_elder().await;

        if !shall_process_accumulated {
            return Ok(None);
        }

        use NodeRewardQuery::*;
        match &msg.message {
            Message::NodeQuery {
                query:
                    NodeQuery::Rewards(GetWalletId {
                        old_node_id,
                        new_node_id,
                    }),
                id,
            } => Outcome::oki(RewardDuty::GetWalletId {
                old_node_id: *old_node_id,
                new_node_id: *new_node_id,
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => Ok(None),
        }
    }

    // Check internal transfer cmds.
    async fn try_transfers(&self, msg: &MsgEnvelope) -> Outcome<TransferDuty> {
        use NodeTransferCmd::*;

        // From Transfer module we get `PropagateTransfer`.

        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let from_transfer_elder = || {
            msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
        };

        let shall_process =
            from_transfer_elder() && self.is_dst_for(msg).await? && self.is_elder().await;

        if shall_process {
            return match &msg.message {
                Message::NodeCmd {
                    cmd: NodeCmd::Transfers(PropagateTransfer(debit_agreement)),
                    id,
                } => Outcome::oki(TransferDuty::ProcessCmd {
                    cmd: TransferCmd::PropagateTransfer(debit_agreement.clone()),
                    msg_id: *id,
                    origin: msg.origin.address(),
                }),
                Message::NodeQuery {
                    query: NodeQuery::Transfers(NodeTransferQuery::GetReplicaEvents(public_key)),
                    id,
                } => {
                    // This comparison is a good example of the need to use `lazy messaging`,
                    // as to handle that the expected public key is not the same as the current.
                    if let Some(section_pk) = self.routing.section_public_key().await {
                        if public_key == &section_pk {
                            Outcome::oki(TransferDuty::ProcessQuery {
                                query: TransferQuery::GetReplicaEvents,
                                msg_id: *id,
                                origin: msg.origin.address(),
                            })
                        } else {
                            error!("Unexpected public key!");
                            Outcome::error(Error::Logic("Unexpected PK".to_string()))
                        }
                    } else {
                        error!("No section public key found!");
                        Outcome::error(Error::Logic("No section PK found".to_string()))
                    }
                }
                Message::NodeQueryResponse {
                    response:
                        NodeQueryResponse::Transfers(NodeTransferQueryResponse::GetReplicaEvents(
                            events,
                        )),
                    id,
                    ..
                } => Outcome::oki(TransferDuty::ProcessCmd {
                    cmd: TransferCmd::InitiateReplica(events.clone()?),
                    msg_id: *id,
                    origin: msg.origin.address(),
                }),
                _ => Outcome::oki_no_change(),
            };
        }

        // From Rewards module, we get
        // `ValidateSectionPayout` and `RegisterSectionPayout`.

        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(None);
        };
        let from_rewards_elder = || {
            msg.most_recent_sender().is_elder() && matches!(duty, Duty::Elder(ElderDuties::Rewards))
        };

        let shall_process =
            from_rewards_elder() && self.is_dst_for(msg).await? && self.is_elder().await;

        if !shall_process {
            return Ok(None);
        }

        match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::Transfers(ValidateSectionPayout(signed_transfer)),
                id,
            } => Outcome::oki(TransferDuty::ProcessCmd {
                cmd: TransferCmd::ValidateSectionPayout(signed_transfer.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            Message::NodeCmd {
                cmd: NodeCmd::Transfers(RegisterSectionPayout(debit_agreement)),
                id,
            } => Outcome::oki(TransferDuty::ProcessCmd {
                cmd: TransferCmd::RegisterSectionPayout(debit_agreement.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => Ok(None),
        }
    }

    async fn self_is_handler_for(&self, address: &XorName) -> bool {
        self.routing.matches_our_prefix(*address).await
    }

    async fn is_elder(&self) -> bool {
        self.routing.is_elder().await
    }

    pub async fn is_adult(&self) -> bool {
        !self.routing.is_elder().await && self.routing.age().await > MIN_AGE
    }
}
