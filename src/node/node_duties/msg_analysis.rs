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
            AdultDuty, AdultDuty::NoOp as AdultNoOp, ChunkReplicationCmd, ChunkReplicationDuty,
            ChunkReplicationQuery, ChunkStoreDuty, ElderDuty, GatewayDuty, MetadataDuty,
            NodeMessagingDuty, NodeOperation, RewardCmd, RewardDuty, RewardQuery, TransferCmd,
            TransferDuty, TransferQuery,
        },
    },
    Error, Network, Result,
};
use log::{error, info};
use sn_messaging::{
    Address, AdultDuties::ChunkStorage, Cmd, DataQuery, Duty, ElderDuties, Message, MessageId,
    MsgEnvelope, NodeCmd, NodeDataCmd, NodeDataQuery, NodeDataQueryResponse, NodeDuties, NodeEvent,
    NodeQuery, NodeQueryResponse, NodeRewardQuery, NodeRewardQueryResponse, NodeSystemCmd,
    NodeTransferCmd, NodeTransferQuery, NodeTransferQueryResponse, Query,
};

use sn_routing::MIN_AGE;
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
        Ok(is_dst || (are_we_origin && self.is_genesis_request().await))
    }

    async fn is_genesis_request(&self) -> bool {
        let elders = self.routing.our_elder_names().await;
        if elders.len() == 1 {
            elders.contains(&self.routing.name().await)
        } else {
            false
        }
    }

    async fn are_we_origin(&self, msg: &MsgEnvelope) -> bool {
        let origin = msg.origin.address().xorname();
        origin == self.routing.name().await
    }

    pub async fn evaluate(&mut self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        let msg = if self.should_accumulate(msg).await? {
            if let Some(msg) = self.accumulation.process_message_envelope(msg)? {
                msg
            } else {
                return Ok(NodeOperation::NoOp);
            }
        } else {
            msg.clone() // TODO remove this clone
        };

        match self.try_messaging(&msg).await? {
            // Identified as an outbound msg, to be sent on the wire.
            NodeMessagingDuty::NoOp => (),
            op => return Ok(op.into()),
        };
        match self.try_system_cmd(&msg).await? {
            NodeOperation::NoOp => (),
            op => return Ok(op),
        };
        match self.try_client_entry(&msg).await? {
            // Client auth cmd finalisation (Temporarily handled here, will be at app layer (Authenticator)).
            // The auth cmd has been agreed by the Gateway section.
            // (All other client msgs are handled when received from client).
            GatewayDuty::NoOp => (),
            op => return Ok(op.into()),
        };
        match self.try_transfers(&msg).await? {
            TransferDuty::NoOp => (),
            op => return Ok(op.into()),
        };
        match self.try_metadata(&msg).await? {
            // Accumulated msg from `Payment`!
            MetadataDuty::NoOp => (),
            op => return Ok(op.into()),
        };
        match self.try_adult(&msg).await? {
            // Accumulated msg from `Metadata`!
            AdultNoOp => (),
            op => return Ok(op.into()),
        };
        match self.try_chunk_replication(&msg).await? {
            // asdf aSdF AsDf `..`!
            AdultNoOp => (),
            op => return Ok(op.into()),
        }
        match self.try_rewards(&msg).await? {
            // Identified as a Rewards msg
            RewardDuty::NoOp => (),
            op => return Ok(op.into()),
        };
        error!("Unknown message destination: {:?}", msg.id());
        Err(Error::Logic("Unknown message destination".to_string()))
    }

    async fn try_system_cmd(&self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        use NodeCmd::*;
        use NodeSystemCmd::*;
        // Check if it a message from adult
        if !msg.origin.is_any_node() {
            return Ok(NodeOperation::NoOp);
        }
        if let Message::NodeCmd {
            cmd: System(StorageFull { node_id, .. }),
            ..
        } = &msg.message
        {
            Ok(ElderDuty::StorageFull { node_id: *node_id }.into())
        } else {
            Ok(NodeOperation::NoOp)
        }
    }

    async fn try_messaging(&self, msg: &MsgEnvelope) -> Result<NodeMessagingDuty> {
        use Address::*;
        let destined_for_network = match msg.destination()? {
            Client(address) => !self.self_is_handler_for(&address).await,
            Node(_) => !self.is_dst_for(msg).await?, // if we are not dst, then it should go to network..
            Section(address) => !self.self_is_handler_for(&address).await,
        };

        if destined_for_network {
            Ok(NodeMessagingDuty::SendToSection {
                msg: msg.clone(),
                as_node: true,
            }) // Forwards without stamping the duty (was not processed).
        } else {
            Ok(NodeMessagingDuty::NoOp)
        }
    }

    // ----  Accumulation ----

    async fn should_accumulate(&self, msg: &MsgEnvelope) -> Result<bool> {
        // Incoming msg from `Payment`!
        let accumulate = self.should_accumulate_for_metadata_write(msg).await? // Metadata(DataSection) Elders accumulate the msgs from Payment Elders.
            // Incoming msg from `Metadata`!
            || self.should_accumulate_for_adult(msg).await? // Adults accumulate the msgs from Metadata Elders.
            || self.should_accumulate_for_transfers(msg).await? // Transfer Elders accumulate GetSectionActorHistory from Rewards Elders
            || self.should_accumulate_for_rewards(msg).await?; // Rewards Elders accumulate GetWalletId from other Rewards Elders

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
            msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
        };
        let is_data_cmd = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };

        let accumulate = is_data_cmd()
            && from_single_payment_elder()
            && self.is_dst_for(msg).await?
            && self.is_elder().await;

        Ok(accumulate)
    }

    async fn should_accumulate_for_transfers(&self, msg: &MsgEnvelope) -> Result<bool> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(false);
        };
        let from_single_transfer_elder = || {
            msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
        };
        use NodeQueryResponse::Transfers as TransfersReponse;
        use NodeTransferQueryResponse::GetReplicaEvents as GetReplicaEventsResponse;
        let from_transfers_to_transfers = || {
            matches!(msg.message, Message::NodeQueryResponse {
                response:
                    TransfersReponse(GetReplicaEventsResponse(_)),
                ..
            })
        };

        let from_transfers = || from_transfers_to_transfers() && from_single_transfer_elder();

        let accumulate_for_transfers =
            from_transfers() && self.is_dst_for(msg).await? && self.is_elder().await;

        Ok(accumulate_for_transfers)
    }

    async fn should_accumulate_for_rewards(&self, msg: &MsgEnvelope) -> Result<bool> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(false);
        };

        use NodeQueryResponse::Rewards;
        use NodeRewardQueryResponse::GetWalletId as GetWalletIdResponse;
        let from_single_rewards_elder = || {
            let res = msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Rewards));
            info!("from single rewards elder: {:?}", res);
            res
        };
        let from_rewards_to_rewards = || {
            matches!(msg.message, Message::NodeQueryResponse {
                response: Rewards(GetWalletIdResponse { .. }),
                ..
            })
        };

        use NodeQueryResponse::*;
        use NodeTransferQueryResponse::*;
        let from_single_transfer_elder = || {
            let res = msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer));
            info!("from single transfer elder: {:?}", res);
            res
        };
        let from_transfers_to_rewards = || {
            let res = matches!(msg.message, Message::NodeQueryResponse {
                response:
                    Transfers(GetSectionActorHistory(_)),
                ..
            });
            info!(
                "is accumulating transfer response (GetSectionActorHistory): {:?}",
                res
            );
            res
        };

        let from_rewards = || from_rewards_to_rewards() && from_single_rewards_elder();
        let from_transfers = || from_transfers_to_rewards() && from_single_transfer_elder();

        let accumulate_for_rewards = (from_rewards() || from_transfers())
            && self.is_dst_for(msg).await?
            && self.is_elder().await;

        Ok(accumulate_for_rewards)
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
        Message::NodeCmd {
            cmd:
                NodeCmd::Data(NodeDataCmd::Blob(_)),
            ..
        }
        | Message::Query { // TODO: Should not accumulate queries, just pass them through.
            query: Query::Data(DataQuery::Blob(_)),
            ..
        });
        info!("is chunk msg: {:?}", is_chunk_msg);

        let is_replication_msg = matches!(msg.message,
        Message::NodeCmd { cmd: NodeCmd::Data(NodeDataCmd::ReplicateChunk { .. }), .. });
        info!("is replication msg: {:?}", is_replication_msg);

        if !(is_chunk_msg || is_replication_msg) {
            return Ok(false);
        }

        let accumulate = self.is_dst_for(msg).await? && self.is_adult().await;
        info!("Accumulating as Adult: {:?}", self.is_adult().await);
        info!("Accumulating as Adult: {:?}", accumulate);
        Ok(accumulate)
    }

    // ---- .... -----

    // todo: eval all msg types!
    async fn try_client_entry(&self, msg: &MsgEnvelope) -> Result<GatewayDuty> {
        let is_our_client_msg = match msg.destination()? {
            Address::Client(address) => self.self_is_handler_for(&address).await,
            _ => false,
        };

        let shall_process = is_our_client_msg && self.is_elder().await;

        if !shall_process {
            return Ok(GatewayDuty::NoOp);
        }

        Ok(GatewayDuty::FindClientFor(msg.clone()))
    }

    /// After the data write sent from Payment Elders has been
    /// accumulated (can be seen since the sender is `Section`),
    /// it is time to actually carry out the write operation.
    async fn try_metadata(&self, msg: &MsgEnvelope) -> Result<MetadataDuty> {
        let is_data_cmd = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(MetadataDuty::NoOp);
        };
        let from_payment_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
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
            return Ok(MetadataDuty::NoOp);
        };
        Ok(duty)
    }

    /// When the write requests from Elders has been accumulated
    /// at an Adult, it is time to carry out the write operation.
    async fn try_adult(&self, msg: &MsgEnvelope) -> Result<AdultDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(AdultNoOp);
        };
        let from_metadata_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Metadata))
        };

        let from_adult_for_chunk_replication = matches!(duty, Duty::Adult(ChunkStorage));

        // TODO: Should not accumulate queries, just pass them through.
        let is_chunk_query = || {
            matches!(msg.message, Message::Query {
                query: Query::Data(DataQuery::Blob(_)),
                ..
            })
        };

        let is_chunk_cmd = || {
            matches!(msg.message,
            Message::NodeCmd {
                cmd:NodeCmd::Data(NodeDataCmd::Blob(_)),
                ..
            })
        };

        let shall_process = (from_metadata_section() || from_adult_for_chunk_replication)
            && self.is_dst_for(&msg).await?
            && self.is_adult().await;

        if !shall_process {
            return Ok(AdultNoOp);
        }

        use AdultDuty::*;
        use ChunkStoreDuty::*;
        let duty = if is_chunk_cmd() {
            RunAsChunkStore(WriteChunk(msg.clone()))
        } else if is_chunk_query() {
            RunAsChunkStore(ReadChunk(msg.clone()))
        } else {
            return Ok(AdultNoOp);
        };
        Ok(duty)
    }

    async fn try_chunk_replication(&self, msg: &MsgEnvelope) -> Result<AdultDuty> {
        info!("Trying chunk replication");
        use ChunkReplicationDuty::*;

        use ChunkReplicationCmd::*;
        use ChunkReplicationQuery::*;
        let chunk_replication = match &msg.message {
            Message::NodeCmd {
                cmd:
                    NodeCmd::Data(NodeDataCmd::ReplicateChunk {
                        address,
                        current_holders,
                        ..
                    }),
                ..
            } => {
                info!("Origin of Replicate Chunk: {:?}", msg.origin.clone());
                Some(ProcessCmd {
                    cmd: ReplicateChunk {
                        current_holders: current_holders.clone(),
                        address: *address,
                        section_authority: msg.most_recent_sender().clone(),
                    },
                    msg_id: Default::default(),
                    origin: msg.most_recent_sender().clone(),
                })
            }
            Message::NodeQueryResponse {
                response: NodeQueryResponse::Data(NodeDataQueryResponse::GetChunk(result)),
                correlation_id,
                ..
            } => {
                let blob = result.to_owned()?;
                info!("Verifying GetChunk NodeQueryResponse!");
                // Recreate original MessageId from Section
                let msg_id =
                    MessageId::combine(vec![*blob.address().name(), self.routing.name().await]);
                if msg_id == *correlation_id {
                    Some(ProcessCmd {
                        cmd: StoreReplicatedBlob(blob),
                        msg_id,
                        origin: msg.origin.clone(),
                    })
                } else {
                    info!("Given blob is incorrect.");
                    None
                }
            }
            Message::NodeQuery {
                query:
                    NodeQuery::Data(NodeDataQuery::GetChunk {
                        section_authority,
                        new_holder,
                        address,
                        current_holders,
                    }),
                ..
            } => {
                info!("Verifying GetChunk query!");
                let proof_chain = self.routing.our_history().await;

                // Recreate original MessageId from Section
                let msg_id = MessageId::combine(vec![*address.name(), *new_holder]);

                // Recreate cmd that was sent by the section.
                let message = Message::NodeCmd {
                    cmd: NodeCmd::Data(NodeDataCmd::ReplicateChunk {
                        new_holder: *new_holder,
                        address: *address,
                        current_holders: current_holders.clone(),
                    }),
                    id: msg_id,
                };

                // Verify that the message was sent from the section
                let verify_section_authority = section_authority.verify(&message.serialize()?);

                let given_section_pk = &section_authority
                    .id()
                    .public_key()
                    .bls()
                    .ok_or_else(|| Error::Logic("Section Key cannot be non-BLS".to_string()))?;

                // Verify that the original ReplicateChunk cmd was sent with SectionAuthority
                if section_authority.is_section()
                    && verify_section_authority
                    && proof_chain.has_key(given_section_pk)
                {
                    info!("Internal ChunkReplicationQuery ProcessQuery");
                    Some(ProcessQuery {
                        query: GetChunk(*address),
                        msg_id,
                        origin: msg.origin.address(),
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        use AdultDuty::*;
        let duty = if let Some(request) = chunk_replication {
            RunAsChunkReplication(request)
        } else {
            return Ok(AdultNoOp);
        };
        Ok(duty)
    }

    async fn try_rewards(&self, msg: &MsgEnvelope) -> Result<RewardDuty> {
        match self.try_nonacc_rewards(msg).await? {
            RewardDuty::NoOp => (),
            op => return Ok(op),
        };
        match self.try_accumulated_rewards(msg).await? {
            RewardDuty::NoOp => (),
            op => return Ok(op),
        };
        self.try_wallet_register(msg).await
    }

    async fn try_wallet_register(&self, msg: &MsgEnvelope) -> Result<RewardDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(RewardDuty::NoOp);
        };
        let is_node_config = || matches!(duty, Duty::Node(NodeDuties::NodeConfig));
        let shall_process =
            is_node_config() && self.is_dst_for(msg).await? && self.is_elder().await;

        if !shall_process {
            return Ok(RewardDuty::NoOp);
        }

        match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet { wallet, .. }),
                id,
                ..
            } => Ok(RewardDuty::ProcessCmd {
                cmd: RewardCmd::SetNodeWallet {
                    wallet_id: *wallet,
                    node_id: msg.origin.address().xorname(),
                },
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => Ok(RewardDuty::NoOp),
        }
    }

    // Check non-accumulated reward msgs.
    async fn try_nonacc_rewards(&self, msg: &MsgEnvelope) -> Result<RewardDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(RewardDuty::NoOp);
        };
        let from_single_rewards_elder = || {
            msg.most_recent_sender().is_elder() && matches!(duty, Duty::Elder(ElderDuties::Rewards))
        };

        let shall_process =
            from_single_rewards_elder() && self.is_dst_for(msg).await? && self.is_elder().await;

        if !shall_process {
            return Ok(RewardDuty::NoOp);
        }
        // SectionPayoutValidated and GetWalletId
        // do not need accumulation since they are accumulated in the domain logic.

        use NodeRewardQuery::GetWalletId;
        match &msg.message {
            Message::NodeEvent {
                event: NodeEvent::SectionPayoutValidated(validation),
                id,
                ..
            } => Ok(RewardDuty::ProcessCmd {
                cmd: RewardCmd::ReceivePayoutValidation(validation.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            Message::NodeQuery {
                query:
                    NodeQuery::Rewards(GetWalletId {
                        old_node_id,
                        new_node_id,
                    }),
                id,
            } => Ok(RewardDuty::ProcessQuery {
                query: RewardQuery::GetWalletId {
                    old_node_id: *old_node_id,
                    new_node_id: *new_node_id,
                },
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => Ok(RewardDuty::NoOp),
        }
    }

    // Check accumulated reward msgs.
    async fn try_accumulated_rewards(&self, msg: &MsgEnvelope) -> Result<RewardDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(RewardDuty::NoOp);
        };
        let from_rewards_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Rewards))
        };
        let shall_process_accumulated =
            from_rewards_section() && self.is_dst_for(msg).await? && self.is_elder().await;

        if shall_process_accumulated {
            use NodeQueryResponse::Rewards;
            use NodeRewardQueryResponse::GetWalletId;
            return match &msg.message {
                Message::NodeQueryResponse {
                    response: Rewards(GetWalletId(Ok((wallet_id, new_node_id)))),
                    id,
                    ..
                } => Ok(RewardDuty::ProcessCmd {
                    cmd: RewardCmd::ActivateNodeRewards {
                        id: *wallet_id,
                        node_id: *new_node_id,
                    },
                    msg_id: *id,
                    origin: msg.origin.address(),
                }),
                _ => Ok(RewardDuty::NoOp),
            };
        }

        // From Transfer module, we get
        // `GetSectionActorHistory` query response.

        let from_transfer_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
        };
        let shall_process =
            from_transfer_section() && self.is_dst_for(msg).await? && self.is_elder().await;
        if !shall_process {
            return Ok(RewardDuty::NoOp);
        }

        use NodeQueryResponse::Transfers;
        use NodeTransferQueryResponse::*;
        match &msg.message {
            Message::NodeQueryResponse {
                response: Transfers(GetSectionActorHistory(Ok(events))),
                id,
                ..
            } => {
                info!("We have a GetSectionActorHistory query response!");
                Ok(RewardDuty::ProcessCmd {
                    cmd: RewardCmd::InitiateSectionActor(events.clone()),
                    msg_id: *id,
                    origin: msg.origin.address(),
                })
            }
            _ => Ok(RewardDuty::NoOp),
        }
    }

    // Check internal transfer cmds.
    async fn try_transfers(&self, msg: &MsgEnvelope) -> Result<TransferDuty> {
        info!("Msg analysis: try_nonacc_transfers..");
        match self.try_nonacc_transfers(msg).await? {
            TransferDuty::NoOp => (),
            op => return Ok(op),
        };
        info!("Msg analysis: try_accumulated_transfers..");
        self.try_accumulated_transfers(msg).await
    }

    // Check accumulated transfer msgs.
    async fn try_accumulated_transfers(&self, msg: &MsgEnvelope) -> Result<TransferDuty> {
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(TransferDuty::NoOp);
        };

        let from_transfers_section = || {
            msg.most_recent_sender().is_section()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
        };
        let shall_process_accumulated =
            from_transfers_section() && self.is_dst_for(msg).await? && self.is_elder().await;
        if !shall_process_accumulated {
            return Ok(TransferDuty::NoOp);
        }

        use NodeQueryResponse::Transfers;
        use NodeTransferQueryResponse::GetReplicaEvents;
        match &msg.message {
            Message::NodeQueryResponse {
                response: Transfers(GetReplicaEvents(events)),
                id,
                ..
            } => Ok(TransferDuty::ProcessCmd {
                cmd: TransferCmd::InitiateReplica(events.clone()?),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => Ok(TransferDuty::NoOp),
        }
    }

    // Check non accumulated transfer msgss.
    async fn try_nonacc_transfers(&self, msg: &MsgEnvelope) -> Result<TransferDuty> {
        // From Transfer module we get `PropagateTransfer`.
        let duty = if let Some(duty) = msg.most_recent_sender().duty() {
            duty
        } else {
            return Ok(TransferDuty::NoOp);
        };
        let from_transfer_elder = || {
            msg.most_recent_sender().is_elder()
                && matches!(duty, Duty::Elder(ElderDuties::Transfer))
        };
        let shall_process =
            from_transfer_elder() && self.is_dst_for(msg).await? && self.is_elder().await;

        if shall_process {
            use NodeTransferQuery::GetReplicaEvents;
            return match &msg.message {
                Message::NodeCmd {
                    cmd: NodeCmd::Transfers(PropagateTransfer(proof)),
                    id,
                } => Ok(TransferDuty::ProcessCmd {
                    cmd: TransferCmd::PropagateTransfer(proof.credit_proof()),
                    msg_id: *id,
                    origin: msg.origin.address(),
                }),
                Message::NodeQuery {
                    query: NodeQuery::Transfers(GetReplicaEvents(public_key)),
                    id,
                } => {
                    // This comparison is a good example of the need to use `lazy messaging`,
                    // as to handle that the expected public key is not the same as the current.
                    if let Some(section_pk) = self.routing.section_public_key().await {
                        if public_key == &section_pk {
                            Ok(TransferDuty::ProcessQuery {
                                query: TransferQuery::GetReplicaEvents,
                                msg_id: *id,
                                origin: msg.origin.address(),
                            })
                        } else {
                            error!("Unexpected public key!");
                            Err(Error::Logic("Unexpected PK".to_string()))
                        }
                    } else {
                        error!("No section public key found!");
                        Err(Error::Logic("No section PK found".to_string()))
                    }
                }
                _ => Ok(TransferDuty::NoOp),
            };
        }

        // From Rewards module, we get
        // `ValidateSectionPayout` and `RegisterSectionPayout`.

        let from_rewards_elder = || {
            msg.most_recent_sender().is_elder() && matches!(duty, Duty::Elder(ElderDuties::Rewards))
        };
        let shall_process =
            from_rewards_elder() && self.is_dst_for(msg).await? && self.is_elder().await;
        if !shall_process {
            return Ok(TransferDuty::NoOp);
        }

        use NodeTransferCmd::*;
        use NodeTransferQuery::GetSectionActorHistory;
        match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::Transfers(ValidateSectionPayout(signed_transfer)),
                id,
            } => Ok(TransferDuty::ProcessCmd {
                cmd: TransferCmd::ValidateSectionPayout(signed_transfer.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            Message::NodeCmd {
                cmd: NodeCmd::Transfers(RegisterSectionPayout(debit_agreement)),
                id,
            } => Ok(TransferDuty::ProcessCmd {
                cmd: TransferCmd::RegisterSectionPayout(debit_agreement.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            Message::NodeQuery {
                query: NodeQuery::Transfers(GetSectionActorHistory(public_key)),
                id,
            } => {
                // This comparison is a good example of the need to use `lazy messaging`,
                // as to handle that the expected public key is not the same as the current.
                if let Some(section_pk) = self.routing.section_public_key().await {
                    if public_key == &section_pk {
                        info!("TransferQuery::GetSectionActorHistory received!");
                        Ok(TransferDuty::ProcessQuery {
                            query: TransferQuery::GetSectionActorHistory,
                            msg_id: *id,
                            origin: msg.origin.address(),
                        })
                    } else {
                        error!("Unexpected public key!");
                        Err(Error::Logic("Unexpected PK".to_string()))
                    }
                } else {
                    error!("No section public key found!");
                    Err(Error::Logic("No section PK found".to_string()))
                }
            }
            _ => Ok(TransferDuty::NoOp),
        }
    }

    async fn self_is_handler_for(&self, address: &XorName) -> bool {
        self.routing.matches_our_prefix(*address).await
    }

    pub async fn is_elder(&self) -> bool {
        self.routing.is_elder().await
    }

    pub async fn is_adult(&self) -> bool {
        !self.routing.is_elder().await && self.routing.age().await > MIN_AGE
    }

    pub async fn no_of_elders(&self) -> usize {
        self.routing.our_elder_addresses().await.len()
    }

    pub async fn no_of_adults(&self) -> usize {
        self.routing.our_adults().await.len()
    }
}
