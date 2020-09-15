// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::node_duties::accumulation::Accumulation;
use crate::node::node_ops::{
    AdultDuty, ChunkDuty, GatewayDuty, MetadataDuty, NodeMessagingDuty, NodeOperation, RewardDuty,
    TransferCmd, TransferDuty, TransferQuery,
};
use crate::Network;
use log::error;
use sn_data_types::{
    Address, Cmd, DataCmd, DataQuery, Duty, ElderDuties, Message, MsgEnvelope, MsgSender, NodeCmd,
    NodeDuties, NodeEvent, NodeQuery, NodeQueryResponse, NodeRewardQuery, NodeRewardQueryResponse,
    NodeSystemCmd, NodeTransferCmd, NodeTransferQuery, NodeTransferQueryResponse, Query,
};
use xor_name::XorName;

// NB: This approach is not entirely good, so will be improved.

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

    pub async fn is_dst_for(&self, msg: &MsgEnvelope) -> bool {
        self.self_is_handler_for(&msg.destination().xorname()).await
    }

    pub fn evaluate(&mut self, msg: &MsgEnvelope) -> Option<NodeOperation> {
        let result = if self.should_accumulate(msg).await {
            let msg = self.accumulation.process_message_envelope(msg)?;
            self.evaluate(&msg)?
        } else if let Some(duty) = self.try_messaging(msg).await {
            // Identified as an outbound msg, to be sent on the wire.
            duty.into()
        } else if let Some(duty) = self.try_client_entry(&msg).await {
            // Client auth cmd finalisation (Temporarily handled here, will be at app layer (Authenticator)).
            // The auth cmd has been agreed by the Gateway section.
            // (All other client msgs are handled when received from client).
            duty.into()
        } else if let Some(duty) = self.try_transfers(&msg).await {
            duty.into()
        } else if let Some(duty) = self.try_metadata(&msg).await {
            // Accumulated msg from `Payment`!
            duty.into()
        } else if let Some(duty) = self.try_adult(&msg).await {
            // Accumulated msg from `Metadata`!
            duty.into()
        } else if let Some(duty) = self.try_rewards(&msg).await {
            // Identified as a Rewards msg
            duty.into()
        } else {
            error!("Unknown message destination: {:?}", msg.id());
            return None;
        };
        Some(result)
    }

    async fn try_messaging(&self, msg: &MsgEnvelope) -> Option<NodeMessagingDuty> {
        use Address::*;
        let destined_for_network = match msg.destination() {
            Client(address) => !self.self_is_handler_for(&address).await,
            Node(address) => address != self.routing.our_name().await,
            Section(address) => !self.self_is_handler_for(&address).await,
        };

        if destined_for_network {
            Some(NodeMessagingDuty::SendToSection(msg.clone())) // Forwards without stamping the duty (was not processed).
        } else {
            None
        }
    }

    // ----  Accumulation ----

    async fn should_accumulate(&self, msg: &MsgEnvelope) -> bool {
        // Incoming msg from `Payment`!
        self.should_accumulate_for_metadata_write(msg).await // Metadata Elders accumulate the msgs from Payment Elders.
        // Incoming msg from `Metadata`!
        || self.should_accumulate_for_adult(msg).await // Adults accumulate the msgs from Metadata Elders.
        || self.should_accumulate_for_rewards(msg).await // Rewards Elders accumulate the claim counter cmd from other Rewards Elders
    }

    /// The individual Payment Elder nodes send their msgs
    /// to Metadata section, where it is accumulated.
    async fn should_accumulate_for_metadata_write(&self, msg: &MsgEnvelope) -> bool {
        let from_single_payment_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Payment),
                ..
            })
        };
        let is_data_cmd = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };

        is_data_cmd()
            && from_single_payment_elder()
            && self.is_dst_for(msg).await
            && self.is_elder().await
    }

    async fn should_accumulate_for_rewards(&self, msg: &MsgEnvelope) -> bool {
        let from_single_rewards_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Rewards),
                ..
            })
        };
        let is_accumulating_reward_query = || {
            matches!(msg.message, Message::NodeQuery {
                query: NodeQuery::Rewards(NodeRewardQuery::GetWalletId { .. }),
                ..
            })
        };

        is_accumulating_reward_query()
            && from_single_rewards_elder()
            && self.is_dst_for(msg).await
            && self.is_elder().await
    }

    /// Adults accumulate the write requests from Elders.
    async fn should_accumulate_for_adult(&self, msg: &MsgEnvelope) -> bool {
        let from_single_metadata_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Metadata),
                ..
            })
        };
        let is_chunk_msg = || {
            matches!(msg.message,
            Message::Cmd {
                cmd:
                    Cmd::Data {
                        cmd: DataCmd::Blob(_),
                        ..
                    },
                ..
            }
            | Message::Query {
                query: Query::Data(DataQuery::Blob(_)),
                ..
            })
        };

        is_chunk_msg()
            && from_single_metadata_elder()
            && self.is_dst_for(msg).await
            && self.is_adult().await
    }

    // ---- .... -----

    // todo: eval all msg types!
    async fn try_client_entry(&self, msg: &MsgEnvelope) -> Option<GatewayDuty> {
        let is_our_client_msg = match msg.destination() {
            Address::Client(address) => self.self_is_handler_for(&address).await,
            _ => false,
        };

        let shall_process = is_our_client_msg && self.is_elder().await;

        if !shall_process {
            return None;
        }

        Some(GatewayDuty::FindClientFor(msg.clone()))
    }

    /// After the data write sent from Payment Elders has been
    /// accumulated (can be seen since the sender is `Section`),
    /// it is time to actually carry out the write operation.
    async fn try_metadata(&self, msg: &MsgEnvelope) -> Option<MetadataDuty> {
        let is_data_cmd = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };
        let from_payment_section = || {
            matches!(msg.most_recent_sender(), MsgSender::Section {
                duty: Duty::Elder(ElderDuties::Payment),
                ..
            })
        };

        let is_data_query = || {
            matches!(msg.message, Message::Query {
                query: Query::Data(_),
                ..
            })
        };
        let from_single_gateway_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Gateway),
                ..
            })
        };

        let is_correct_dst = self.is_dst_for(msg).await && self.is_elder().await;

        let duty = if is_data_query() && from_single_gateway_elder() && is_correct_dst {
            MetadataDuty::ProcessRead(msg.clone()) // TODO: Fix these for type safety
        } else if is_data_cmd() && from_payment_section() && is_correct_dst {
            MetadataDuty::ProcessWrite(msg.clone()) // TODO: Fix these for type safety
        } else {
            return None;
        };
        Some(duty)
    }

    /// When the write requests from Elders has been accumulated
    /// at an Adult, it is time to carry out the write operation.
    async fn try_adult(&self, msg: &MsgEnvelope) -> Option<AdultDuty> {
        let from_metadata_section = || {
            matches!(msg.most_recent_sender(), MsgSender::Section {
                duty: Duty::Elder(ElderDuties::Metadata),
                ..
            })
        };

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

        let shall_process =
            from_metadata_section() && self.is_dst_for(msg).await && self.is_adult().await;

        if !shall_process {
            return None;
        }

        use AdultDuty::*;
        use ChunkDuty::*;
        let duty = if is_chunk_cmd() {
            RunAsChunks(WriteChunk(msg.clone()))
        } else if is_chunk_query() {
            RunAsChunks(ReadChunk(msg.clone()))
        } else {
            return None;
        };
        Some(duty)
    }

    async fn try_rewards(&self, msg: &MsgEnvelope) -> Option<RewardDuty> {
        let result = self.try_nonacc_rewards(msg).await;
        if result.is_some() {
            return result;
        }
        let result = self.try_accumulated_rewards(msg).await;
        if result.is_some() {
            return result;
        }
        self.try_wallet_register(msg).await
    }

    async fn try_wallet_register(&self, msg: &MsgEnvelope) -> Option<RewardDuty> {
        let from_node = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Node(NodeDuties::NodeConfig),
                ..
            })
        };
        let shall_process = from_node() && self.is_dst_for(msg).await && self.is_elder().await;

        if !shall_process {
            return None;
        }

        match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet { wallet, .. }),
                ..
            } => Some(RewardDuty::SetNodeWallet {
                wallet_id: *wallet,
                node_id: msg.origin.address().xorname(),
            }),
            _ => None,
        }
    }

    // Check non-accumulated reward msgs.
    async fn try_nonacc_rewards(&self, msg: &MsgEnvelope) -> Option<RewardDuty> {
        let from_rewards_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Rewards),
                ..
            })
        };
        let shall_process =
            from_rewards_elder() && self.is_dst_for(msg).await && self.is_elder().await;

        if !shall_process {
            return None;
        }

        // SectionPayoutValidated and GetWalletId
        // do not need accumulation since they are accumulated in the domain logic.
        use NodeRewardQueryResponse::*;
        match &msg.message {
            Message::NodeEvent {
                event: NodeEvent::SectionPayoutValidated(validation),
                ..
            } => Some(RewardDuty::ReceivePayoutValidation(validation.clone())),
            Message::NodeQueryResponse {
                response: NodeQueryResponse::Rewards(GetWalletId(Ok((wallet_id, new_node_id)))),
                ..
            } => Some(RewardDuty::ActivateNodeRewards {
                id: *wallet_id,
                node_id: *new_node_id,
            }),
            _ => None,
        }
    }

    // Check accumulated reward msgs.
    async fn try_accumulated_rewards(&self, msg: &MsgEnvelope) -> Option<RewardDuty> {
        let from_rewards_section = || {
            matches!(msg.most_recent_sender(), MsgSender::Section {
                duty: Duty::Elder(ElderDuties::Rewards),
                ..
            })
        };
        let shall_process_accumulated =
            from_rewards_section() && self.is_dst_for(msg).await && self.is_elder().await;

        if !shall_process_accumulated {
            return None;
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
            } => Some(RewardDuty::GetWalletId {
                old_node_id: *old_node_id,
                new_node_id: *new_node_id,
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => None,
        }
    }

    // Check internal transfer cmds.
    async fn try_transfers(&self, msg: &MsgEnvelope) -> Option<TransferDuty> {
        use NodeTransferCmd::*;

        // From Transfer module we get `PropagateTransfer`.

        let from_transfer_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Transfer),
                ..
            })
        };
        let shall_process =
            from_transfer_elder() && self.is_dst_for(msg).await && self.is_elder().await;

        if shall_process {
            return match &msg.message {
                Message::NodeCmd {
                    cmd: NodeCmd::Transfers(PropagateTransfer(debit_agreement)),
                    id,
                } => Some(TransferDuty::ProcessCmd {
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
                    if public_key == &self.routing.public_key().await? {
                        Some(TransferDuty::ProcessQuery {
                            query: TransferQuery::GetReplicaEvents,
                            msg_id: *id,
                            origin: msg.origin.address(),
                        })
                    } else {
                        None
                    }
                }
                Message::NodeQueryResponse {
                    response:
                        NodeQueryResponse::Transfers(NodeTransferQueryResponse::GetReplicaEvents(
                            events,
                        )),
                    id,
                    ..
                } => Some(TransferDuty::ProcessCmd {
                    cmd: TransferCmd::InitiateReplica(events.clone().ok()?),
                    msg_id: *id,
                    origin: msg.origin.address(),
                }),
                _ => None,
            };
        }

        // From Rewards module, we get
        // `ValidateSectionPayout` and `RegisterSectionPayout`.

        let from_rewards_elder = || {
            matches!(msg.most_recent_sender(), MsgSender::Node {
                duty: Duty::Elder(ElderDuties::Rewards),
                ..
            })
        };

        let shall_process =
            from_rewards_elder() && self.is_dst_for(msg).await && self.is_elder().await;

        if !shall_process {
            return None;
        }

        match &msg.message {
            Message::NodeCmd {
                cmd: NodeCmd::Transfers(ValidateSectionPayout(signed_transfer)),
                id,
            } => Some(TransferDuty::ProcessCmd {
                cmd: TransferCmd::ValidateSectionPayout(signed_transfer.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            Message::NodeCmd {
                cmd: NodeCmd::Transfers(RegisterSectionPayout(debit_agreement)),
                id,
            } => Some(TransferDuty::ProcessCmd {
                cmd: TransferCmd::RegisterSectionPayout(debit_agreement.clone()),
                msg_id: *id,
                origin: msg.origin.address(),
            }),
            _ => None,
        }
    }

    async fn self_is_handler_for(&self, address: &XorName) -> bool {
        self.routing.matches_our_prefix(*address).await
    }

    async fn is_elder(&self) -> bool {
        self.routing.is_elder().await
    }

    async fn is_adult(&self) -> bool {
        self.routing.is_adult().await
    }
}
