// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "simulated-payouts")]
use safe_nd::Transfer;

use crate::node::economy::MintingMetrics;
use routing::{event::Event as NetworkEvent, TransportEvent as ClientEvent};
use safe_nd::{
    AccountId, Address, AuthCmd, DebitAgreementProof, HandshakeResponse, MessageId, MsgEnvelope,
    MsgSender, PaymentQuery, PublicId, PublicKey, RewardCounter, SignedTransfer, TransferValidated,
    XorName,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr};

/// Internal messages are what is passed along
/// within a node, between the entry point and
/// exit point of remote messages.
/// In other words, when communication from another
/// participant at the network arrives, it is analysed
/// and interpreted into an internal message, that can
/// then be passed along to its proper processing module
/// at the node. At a node module, the result of such a call
/// is also an internal message.
/// Finally, an internal message might be destined for Messaging
/// module, by which it leaves the physical boundary of this node
/// and is sent on the wire to some other destination(s) on the network.
///
// #[derive(Debug)]
// #[allow(clippy::large_enum_variant)]

pub enum NodeOperation {
    Single(NetworkDuty),
    Multiple(Vec<NetworkDuty>),
}

impl NodeOperation {
    fn from_many(ops: Vec<NodeOperation>) -> NodeOperation {
        use NodeOperation::*;
        let multiple = ops
            .into_iter()
            .map(|c| match c {
                Single(duty) => vec![duty],
                Multiple(duties) => duties,
            })
            .flatten()
            .collect();
        Multiple(multiple)
    }
}

impl Into<NodeOperation> for Vec<NodeOperation> {
    fn into(self) -> NodeOperation {
        NodeOperation::from_many(self.into_iter().collect())
    }
}

impl Into<NodeOperation> for Vec<Option<NodeOperation>> {
    fn into(self) -> NodeOperation {
        NodeOperation::from_many(self.into_iter().filter_map(|c| c).collect())
    }
}

pub enum NetworkDuty {
    RunAsAdult(AdultDuty),
    RunAsElder(ElderDuty),
    RunAsNode(NodeDuty),
    Unknown,
}

// Need to Serialize/Deserialize to go through the consensus process.
/// A GroupDecision is something only
/// taking place at the network Gateways.
#[derive(Debug, Clone, Serialize, Deserialize)] // Debug,
pub enum GroupDecision {
    /// When Gateway nodes consider a request
    /// valid, they will vote for it to be forwarded.
    /// As they reach consensus, this is then carried out.
    Process {
        cmd: AuthCmd,
        msg_id: MessageId,
        origin: MsgSender,
    },
}

// --------------- Node ---------------

/// Common duties run by all nodes.
pub enum NodeDuty {
    ///
    BecomeAdult,
    ///
    BecomeElder,
    ///
    ProcessMessaging(MessagingDuty),
    ///
    ProcessNetworkEvent(NetworkEvent),
}

impl Into<NodeOperation> for NodeDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsNode(self))
    }
}

// --------------- Messaging ---------------

/// This duty is at the border of infrastructural
/// and domain duties. Messaging is such a fundamental
/// part of the system, that it can be considered domain.
//#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MessagingDuty {
    /// Send to a client.
    SendToClient {
        address: SocketAddr,
        msg: MsgEnvelope,
    },
    /// Send to a single node.
    SendToNode(MsgEnvelope),
    /// Send to a section.
    SendToSection(MsgEnvelope),
    /// Send the same request to each individual Adult.
    SendToAdults {
        targets: BTreeSet<XorName>,
        msg: MsgEnvelope,
    },
    /// Vote for a cmd so we can process the deferred action on consensus.
    /// (Currently immediately.)
    VoteFor(GroupDecision),
    ///
    SendHandshake {
        address: SocketAddr,
        response: HandshakeResponse,
    },
    ///
    DisconnectClient(SocketAddr),
}

impl Into<NodeOperation> for MessagingDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeDuty::*;
        use NodeOperation::*;
        Single(RunAsNode(ProcessMessaging(self)))
    }
}

// --------------- Elder ---------------

/// Duties only run as an Elder.
pub enum ElderDuty {
    ProcessLostMember {
        name: XorName,
        age: u8,
    },
    ProcessElderChange {
        // /// The prefix of our section.
        // prefix: Prefix,
        /// The BLS public key of our section.
        key: PublicKey,
        /// The set of elders of our section.
        elders: BTreeSet<XorName>,
    },
    ProcessJoinedMember {
        old_node_id: XorName,
        new_node_id: XorName,
    },
    RunAsKeySection(KeySectionDuty),
    RunAsDataSection(DataSectionDuty),
}

impl Into<NodeOperation> for ElderDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(self))
    }
}

// --------------- Adult ---------------

/// Duties only run as an Adult.
pub enum AdultDuty {
    ///
    RunAsChunks(ChunkDuty),
}

impl Into<NodeOperation> for AdultDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsAdult(self))
    }
}

// -- All duties below solely process and produce internal msgs
// -- for further handling locally - of which MessagingDuty is the
// -- most common next local step. From there, it is sent out on the network.
// -- It is important to stress that _only_ MessagingDuty does sending on to the network.

// --------------- KeySection ---------------

/// Duties only run as a Key section.
pub enum KeySectionDuty {
    ///
    EvaluateClientMsg {
        public_id: PublicId,
        msg: MsgEnvelope,
    },
    ///
    ProcessGroupDecision(GroupDecision),
    ///
    RunAsAuth(AuthDuty),
    ///
    RunAsGateway(GatewayDuty),
    ///
    RunAsPayment(PaymentDuty),
    ///
    RunAsTransfers(TransferDuty),
}

impl Into<NodeOperation> for KeySectionDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsKeySection(self)))
    }
}

// --------------- DataSection ---------------

/// Duties only run as a Data section.
pub enum DataSectionDuty {
    ///
    RunAsMetadata(MetadataDuty),
    ///
    RunAsRewards(RewardDuty),
}

// --------------- Auth (Temporary!) ---------------

/// These things will be handled client
/// side instead, in the Authenticator app.
pub enum AuthDuty {
    ///
    Process {
        ///
        cmd: AuthCmd,
        ///
        msg_id: MessageId,
        ///
        origin: MsgSender,
    },
    ///
    ListAuthKeysAndVersion {
        /// The Client id.
        client: PublicKey,
        ///
        msg_id: MessageId,
        ///
        origin: MsgSender,
    },
}

impl Into<NodeOperation> for AuthDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use KeySectionDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsKeySection(RunAsAuth(self))))
    }
}

// --------------- Gateway ---------------

/// Gateway duties imply interfacing with clients.
pub enum GatewayDuty {
    /// Messages from network to client
    /// such as query responses, events and errors,
    /// are piped through the Gateway, to find the
    /// connection info to the client.
    FindClientFor(MsgEnvelope),
    /// Incoming events from clients are parsed
    /// at the Gateway, and forwarded to other modules.
    ProcessClientEvent(ClientEvent),
}

impl Into<NodeOperation> for GatewayDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use KeySectionDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsKeySection(RunAsGateway(self))))
    }
}

// --------------- Payment ---------------

/// Payment for data.
pub enum PaymentDuty {
    ///
    ProcessPayment(MsgEnvelope),
    ///
    ProcessQuery {
        query: PaymentQuery,
        ///
        msg_id: MessageId,
        ///
        origin: Address,
    },
}

impl Into<NodeOperation> for PaymentDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use KeySectionDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsKeySection(RunAsPayment(self))))
    }
}

// --------------- Metadata ---------------

///
pub enum MetadataDuty {
    ///
    ProcessRead(MsgEnvelope),
    ///
    ProcessWrite(MsgEnvelope),
}

impl Into<NodeOperation> for MetadataDuty {
    fn into(self) -> NodeOperation {
        use DataSectionDuty::*;
        use ElderDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsDataSection(RunAsMetadata(self))))
    }
}

// --------------- Chunks ---------------

/// Chunk storage and retrieval is done at Adults.
pub enum ChunkDuty {
    ///
    ReadChunk(MsgEnvelope),
    ///
    WriteChunk(MsgEnvelope),
}

// --------------- Rewards ---------------

/// Nodes participating in the system are
/// rewarded for their work.
/// Elders are responsible for the duties of
/// keeping track of rewards, and issuing
/// payouts form the section account.
pub enum RewardDuty {
    /// Whenever there has been write
    /// operations on the network, we
    /// accumulate rewards for the nodes
    /// of our section.
    AccumulateReward {
        /// The points can be anything,
        /// but in our StorageReward system,
        /// it is the number of bytes of a write
        /// operation.
        points: u64,
        /// Idempotency.
        /// An individual write operation can
        /// only lead to a farming reward once.
        msg_id: MessageId,
    },
    ///
    AddNewAccount {
        ///
        id: AccountId,
        ///
        node_id: XorName,
    },
    /// We add relocated nodes to our rewards
    /// system, so that they can participate
    /// in the farming rewards.
    AddRelocatedAccount {
        ///
        old_node_id: XorName,
        ///
        new_node_id: XorName,
    },
    /// When a node is relocated from us, the other
    /// section will claim the reward counter, so that
    /// they can pay it out to their new node.
    ClaimRewardCounter {
        ///
        old_node_id: XorName,
        ///
        new_node_id: XorName,
        ///
        msg_id: MessageId,
        ///
        origin: Address,
    },
    /// When a node has been relocated to our section
    /// we receive the reward counter from the other section.
    ReceiveClaimedRewards {
        ///
        id: AccountId,
        ///
        node_id: XorName,
        ///
        counter: RewardCounter,
    },
    /// When a node has left for some reason,
    /// we prepare for its reward counter to be claimed.
    PrepareAccountMove { node_id: XorName },
    /// The distributed Actor of a section,
    /// receives and accumulates the validated
    /// reward payout from its Replicas,
    ReceivePayoutValidation(TransferValidated),
    /// Updates the figures used in reward calculation.
    UpdateRewards(MintingMetrics),
}

impl Into<NodeOperation> for RewardDuty {
    fn into(self) -> NodeOperation {
        use DataSectionDuty::*;
        use ElderDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsDataSection(RunAsRewards(self))))
    }
}

// --------------- Transfers ---------------

///
pub enum TransferDuty {
    ///
    ProcessQuery {
        query: TransferQuery,
        ///
        msg_id: MessageId,
        ///
        origin: Address,
    },
    ///
    ProcessCmd {
        cmd: TransferCmd,
        ///
        msg_id: MessageId,
        ///
        origin: Address,
    },
}

impl Into<NodeOperation> for TransferDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use KeySectionDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsElder(RunAsKeySection(RunAsTransfers(self))))
    }
}

pub enum TransferQuery {
    /// Get the PublicKeySet for replicas of a given PK
    GetReplicaKeys(AccountId),
    /// Get key balance.
    GetBalance(AccountId),
    /// Get key transfers since specified version.
    GetHistory {
        /// The balance key.
        at: AccountId,
        /// The last version of transfers we know of.
        since_version: usize,
    },
}

pub enum TransferCmd {
    #[cfg(feature = "simulated-payouts")]
    /// Cmd to simulate a farming payout
    SimulatePayout(Transfer),
    /// The cmd to validate a transfer.
    ValidateTransfer(SignedTransfer),
    /// The cmd to register the consensused transfer.
    RegisterTransfer(DebitAgreementProof),
    ///
    PropagateTransfer(DebitAgreementProof),
    ///
    ValidateSectionPayout(SignedTransfer),
    ///
    RegisterSectionPayout(DebitAgreementProof),
}

impl From<safe_nd::TransferCmd> for TransferCmd {
    fn from(cmd: safe_nd::TransferCmd) -> Self {
        match cmd {
            #[cfg(feature = "simulated-payouts")]
            safe_nd::TransferCmd::SimulatePayout(transfer) => Self::SimulatePayout(transfer),
            safe_nd::TransferCmd::ValidateTransfer(signed_transfer) => {
                Self::ValidateTransfer(signed_transfer)
            }
            safe_nd::TransferCmd::RegisterTransfer(debit_agreement) => {
                Self::RegisterTransfer(debit_agreement)
            }
        }
    }
}

impl From<safe_nd::TransferQuery> for TransferQuery {
    fn from(cmd: safe_nd::TransferQuery) -> Self {
        match cmd {
            safe_nd::TransferQuery::GetReplicaKeys(transfer) => Self::GetReplicaKeys(transfer),
            safe_nd::TransferQuery::GetBalance(signed_transfer) => {
                Self::GetBalance(signed_transfer)
            }
            safe_nd::TransferQuery::GetHistory { at, since_version } => {
                Self::GetHistory { at, since_version }
            }
        }
    }
}
