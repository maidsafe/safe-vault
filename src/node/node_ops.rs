// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;

use crate::Result;
use serde::export::Formatter;
use sn_data_types::{
    Address, Blob, BlobAddress, CreditAgreementProof, MessageId, MsgEnvelope, MsgSender, PublicKey,
    ReplicaEvent, SignedTransfer, TransferAgreementProof, TransferValidated,
};
use sn_routing::{Event as RoutingEvent, Prefix};
use std::collections::BTreeSet;
use std::fmt::Debug;
use xor_name::XorName;

pub trait Blah {
    fn convert(self) -> Result<NodeOperation>;
}

impl Blah for Result<NodeMessagingDuty> {
    fn convert(self) -> Result<NodeOperation> {
        match self? {
            NodeMessagingDuty::NoOp => Ok(NodeOperation::NoOp),
            op => Ok(op.into()),
        }
    }
}

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
/// module, by which it leaves the process boundary of this node
/// and is sent on the wire to some other destination(s) on the network.

/// The main operation type
/// which encompasses all duties
/// carried out by the node in the network.
#[derive(Debug)]
pub enum NodeOperation {
    /// A single operation.
    Single(NetworkDuty),
    /// Multiple operations, that will
    /// be carried out sequentially.
    Multiple(Vec<NetworkDuty>),
    // No op.
    NoOp,
}

impl NodeOperation {
    fn from_many(ops: Vec<NodeOperation>) -> NodeOperation {
        use NodeOperation::*;
        if ops.is_empty() {
            return NoOp;
        }
        if ops.len() == 1 {
            let mut ops = ops;
            return ops.remove(0);
        }
        let multiple = ops
            .into_iter()
            .map(|c| match c {
                Single(duty) => vec![duty],
                Multiple(duties) => duties,
                NoOp => vec![],
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

impl Into<NodeOperation> for Vec<Result<NodeOperation>> {
    /// NB: This drops errors!
    fn into(self) -> NodeOperation {
        NodeOperation::from_many(self.into_iter().flatten().collect())
    }
}

/// All duties carried out by
/// a node in the network.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum NetworkDuty {
    RunAsAdult(AdultDuty),
    RunAsElder(ElderDuty),
    RunAsNode(NodeDuty),
    NoOp,
}

// --------------- Node ---------------

/// Common duties run by all nodes.
#[allow(clippy::large_enum_variant)]
pub enum NodeDuty {
    ///
    RegisterWallet(PublicKey),
    /// On being promoted, an Infant node becomes an Adult.
    BecomeAdult,
    /// On being promoted, an Adult node becomes an Elder.
    BecomeElder,
    /// Sending messages on to the network.
    ProcessMessaging(NodeMessagingDuty),
    /// Receiving and processing events from the network.
    ProcessNetworkEvent(RoutingEvent),
    NoOp,
}

impl Into<NodeOperation> for NodeDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeOperation::*;
        Single(RunAsNode(self))
    }
}

impl Debug for NodeDuty {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegisterWallet(_) => write!(f, "RegisterWallet"),
            Self::BecomeAdult => write!(f, "BecomeAdult"),
            Self::BecomeElder => write!(f, "BecomeElder"),
            Self::ProcessMessaging(duty) => duty.fmt(f),
            Self::ProcessNetworkEvent(event) => event.fmt(f),
            Self::NoOp => write!(f, "No op."),
        }
    }
}

// --------------- Messaging ---------------

/// This duty is at the border of infrastructural
/// and domain duties. Messaging is such a fundamental
/// part of the system, that it can be considered domain.
#[allow(clippy::large_enum_variant)]
pub enum NodeMessagingDuty {
    /// Send to client
    SendToClient(MsgEnvelope),
    /// Send to a single node.
    SendToNode(MsgEnvelope),
    /// Send to a section.
    SendToSection {
        /// Msg to be sent
        msg: MsgEnvelope,
        /// Send as a Node.(send as Section if set to false)
        as_node: bool,
    },
    /// Send the same request to each individual Adult.
    SendToAdults {
        targets: BTreeSet<XorName>,
        msg: MsgEnvelope,
    },
    // No operation
    NoOp,
}

impl From<NodeMessagingDuty> for NodeOperation {
    fn from(duty: NodeMessagingDuty) -> Self {
        use NetworkDuty::*;
        use NodeDuty::*;
        use NodeOperation::*;
        if matches!(duty, NodeMessagingDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsNode(ProcessMessaging(duty)))
        }
    }
}

impl Debug for NodeMessagingDuty {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendToAdults { targets, msg } => {
                write!(f, "SendToAdults [ target: {:?}, msg: {:?} ]", targets, msg)
            }
            Self::SendToClient(msg) => write!(f, "SendToClient [ msg: {:?} ]", msg),
            Self::SendToNode(msg) => write!(f, "SendToNode [ msg: {:?} ]", msg),
            Self::SendToSection { msg, .. } => write!(f, "SendToSection [ msg: {:?} ]", msg),
            Self::NoOp => write!(f, "No op."),
        }
    }
}

// --------------- Elder ---------------

/// Duties only run as an Elder.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ElderDuty {
    ProcessNewMember(XorName),
    /// As members are lost for various reasons
    /// there are certain things the Elders need
    /// to do, to update for that.
    ProcessLostMember {
        name: XorName,
        age: u8,
    },
    /// Elder changes means the section public key
    /// changes as well, which leads to necessary updates
    /// of various places using the multisig of the section.
    ProcessElderChange {
        /// The prefix of our section.
        prefix: Prefix,
        /// The BLS public key of our section.
        key: PublicKey,
        /// The set of elders of our section.
        elders: BTreeSet<XorName>,
    },
    ProcessRelocatedMember {
        /// The id of the node at the previous section.
        old_node_id: XorName,
        /// The id of the node at its new section (i.e. this one).
        new_node_id: XorName,
        // The age of the node (among things determines if it is eligible for rewards yet).
        age: u8,
    },
    /// A key section interfaces with clients.
    RunAsKeySection(KeySectionDuty),
    /// A data section receives requests relayed
    /// via key sections.
    RunAsDataSection(DataSectionDuty),
    NoOp,
}

impl Into<NodeOperation> for ElderDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, ElderDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsElder(self))
        }
    }
}

// --------------- Adult ---------------

/// Duties only run as an Adult.
#[derive(Debug)]
pub enum AdultDuty {
    /// The main duty of an Adult is
    /// storage and retrieval of data chunks.
    RunAsChunks(ChunkDuty),
    /// Request for duplicate chunk
    RequestForChunk {
        ///
        targets: BTreeSet<XorName>,
        ///
        address: BlobAddress,
        ///
        section_authority: MsgSender,
    },
    ReplyForDuplication {
        ///
        address: BlobAddress,
        ///
        new_holder: XorName,
        ///
        correlation_id: MessageId,
    },
    StoreDuplicatedBlob {
        blob: Blob,
    },
    NoOp,
}

impl Into<NodeOperation> for AdultDuty {
    fn into(self) -> NodeOperation {
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, AdultDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsAdult(self))
        }
    }
}

// --------------- KeySection ---------------

/// Duties only run as a Key section.
#[derive(Debug)]
pub enum KeySectionDuty {
    /// Incoming client msgs
    /// are to be evaluated and
    /// sent to their respective module.
    EvaluateClientMsg(MsgEnvelope),
    /// As a Gateway, the node interfaces with
    /// clients, interpreting handshakes and msgs,
    /// and also correlating network msgs (such as cmd errors
    /// and query responses) with earlier client
    /// msgs, as to route them to the correct client.
    RunAsGateway(GatewayDuty),
    /// Transfers of money between keys, hence also payment for data writes.
    RunAsTransfers(TransferDuty),
    NoOp,
}

impl Into<NodeOperation> for KeySectionDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, KeySectionDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsElder(RunAsKeySection(self)))
        }
    }
}

// --------------- DataSection ---------------

/// Duties only run as a Data section.
#[derive(Debug)]
pub enum DataSectionDuty {
    /// Metadata is the info about
    /// data types structures, ownership
    /// and permissions. This is distinct
    /// from the actual data, that is in chunks.
    /// NB: Full separation between metadata and chunks is not yet implemented.
    RunAsMetadata(MetadataDuty),
    /// Dealing out rewards for contributing to
    /// the network by storing metadata / data, and
    /// carrying out operations on those.
    RunAsRewards(RewardDuty),
    NoOp,
}

// --------------- Gateway ---------------

/// Gateway duties imply interfacing with clients.
#[derive(Debug)]
pub enum GatewayDuty {
    /// Messages from network to client
    /// such as query responses, events and errors,
    /// are piped through the Gateway, to find the
    /// connection info to the client.
    FindClientFor(MsgEnvelope),
    /// Incoming events from clients are parsed
    /// at the Gateway, and forwarded to other modules.
    ProcessClientEvent(RoutingEvent),
    NoOp,
}

impl Into<NodeOperation> for GatewayDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use KeySectionDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, GatewayDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsElder(RunAsKeySection(RunAsGateway(self))))
        }
    }
}

// --------------- Metadata ---------------

/// Reading and writing data.
/// The reads/writes potentially concerns
/// metadata only, but could include
/// chunks, and are then relayed to
/// Adults (i.e. chunk holders).
#[derive(Debug)]
pub enum MetadataDuty {
    /// Reads.
    ProcessRead(MsgEnvelope),
    /// Writes.
    ProcessWrite(MsgEnvelope),
    NoOp,
}

impl Into<NodeOperation> for MetadataDuty {
    fn into(self) -> NodeOperation {
        use DataSectionDuty::*;
        use ElderDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, MetadataDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsElder(RunAsDataSection(RunAsMetadata(self))))
        }
    }
}

// --------------- Chunks ---------------

/// Chunk storage and retrieval is done at Adults.
#[derive(Debug)]
pub enum ChunkDuty {
    /// Reads.
    ReadChunk(MsgEnvelope),
    /// Writes.
    WriteChunk(MsgEnvelope),
    NoOp,
}

// --------------- Rewards ---------------

/// Nodes participating in the system are
/// rewarded for their work.
/// Elders are responsible for the duties of
/// keeping track of rewards, and issuing
/// payouts from the section account.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RewardDuty {
    /// Initiates a new SectionActor with the
    /// state of existing Replicas in the group.
    InitiateSectionActor(Vec<ReplicaEvent>),
    /// With the node id.
    AddNewNode(XorName),
    /// Set the account for a node.
    SetNodeWallet {
        /// The node which accumulated the rewards.
        node_id: XorName,
        /// The account to which the accumulated
        /// rewards should be paid out.
        wallet_id: PublicKey,
    },
    /// We add relocated nodes to our rewards
    /// system, so that they can participate
    /// in the farming rewards.
    AddRelocatingNode {
        /// The id of the node at the previous section.
        old_node_id: XorName,
        /// The id of the node at its new section (i.e. this one).
        new_node_id: XorName,
        // The age of the node, determines if it is eligible for rewards yet.
        age: u8,
    },
    /// When a node is relocated from us, the other
    /// section will claim the reward counter, so that
    /// they can pay it out to their new node.
    GetWalletId {
        /// The id of the node at the previous section.
        old_node_id: XorName,
        /// The id of the node at its new section (i.e. this one).
        new_node_id: XorName,
        /// The id of the remote msg.
        msg_id: MessageId,
        /// The origin of the remote msg.
        origin: Address,
    },
    /// When a node has been relocated to our section
    /// we receive the account id from the other section.
    ActivateNodeRewards {
        /// The account to which the accumulated
        /// rewards should be paid out.
        id: PublicKey,
        /// The node which accumulated the rewards.
        node_id: XorName,
    },
    /// When a node has left for some reason,
    /// we deactivate it.
    DeactivateNode(XorName),
    /// The distributed Actor of a section,
    /// receives and accumulates the validated
    /// reward payout from its Replicas,
    ReceivePayoutValidation(TransferValidated),
    NoOp,
}

impl Into<NodeOperation> for RewardDuty {
    fn into(self) -> NodeOperation {
        use DataSectionDuty::*;
        use ElderDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, RewardDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsElder(RunAsDataSection(RunAsRewards(self))))
        }
    }
}

// --------------- Transfers ---------------

/// Transfers of money on the network
/// and querying of balances and history.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
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
    NoOp,
}

impl Into<NodeOperation> for TransferDuty {
    fn into(self) -> NodeOperation {
        use ElderDuty::*;
        use KeySectionDuty::*;
        use NetworkDuty::*;
        use NodeOperation::*;
        if matches!(self, TransferDuty::NoOp) {
            NodeOperation::NoOp
        } else {
            Single(RunAsElder(RunAsKeySection(RunAsTransfers(self))))
        }
    }
}

/// Queries for information on accounts,
/// handled by AT2 Replicas.
#[derive(Debug)]
pub enum TransferQuery {
    /// Get the PublicKeySet for replicas of a given PK
    GetReplicaKeys(PublicKey),
    /// Get key balance.
    GetBalance(PublicKey),
    /// Get key transfers since specified version.
    GetHistory {
        /// The balance key.
        at: PublicKey,
        /// The last version of transfers we know of.
        since_version: usize,
    },
    GetReplicaEvents,
    /// Get the latest cost for writing given number of bytes to network.
    GetStoreCost {
        /// The requester's key.
        requester: PublicKey,
        ///
        bytes: u64,
    },
}

/// Cmds carried out on AT2 Replicas.
#[derive(Debug)]
#[allow(clippy::clippy::large_enum_variant)]
pub enum TransferCmd {
    /// Initiates a new Replica with the
    /// state of existing Replicas in the group.
    InitiateReplica(Vec<ReplicaEvent>),
    ProcessPayment(MsgEnvelope),
    #[cfg(feature = "simulated-payouts")]
    /// Cmd to simulate a farming payout
    SimulatePayout(Transfer),
    /// The cmd to validate a transfer.
    ValidateTransfer(SignedTransfer),
    /// The cmd to register the consensused transfer.
    RegisterTransfer(TransferAgreementProof),
    /// As a transfer has been propagated to the
    /// crediting section, it is applied there.
    PropagateTransfer(CreditAgreementProof),
    /// The validation of a section transfer.
    ValidateSectionPayout(SignedTransfer),
    /// The registration of a section transfer.
    RegisterSectionPayout(TransferAgreementProof),
}

impl From<sn_data_types::TransferCmd> for TransferCmd {
    fn from(cmd: sn_data_types::TransferCmd) -> Self {
        match cmd {
            #[cfg(feature = "simulated-payouts")]
            sn_data_types::TransferCmd::SimulatePayout(transfer) => Self::SimulatePayout(transfer),
            sn_data_types::TransferCmd::ValidateTransfer(signed_transfer) => {
                Self::ValidateTransfer(signed_transfer)
            }
            sn_data_types::TransferCmd::RegisterTransfer(debit_agreement) => {
                Self::RegisterTransfer(debit_agreement)
            }
        }
    }
}

impl From<sn_data_types::TransferQuery> for TransferQuery {
    fn from(cmd: sn_data_types::TransferQuery) -> Self {
        match cmd {
            sn_data_types::TransferQuery::GetReplicaKeys(transfer) => {
                Self::GetReplicaKeys(transfer)
            }
            sn_data_types::TransferQuery::GetBalance(public_key) => Self::GetBalance(public_key),
            sn_data_types::TransferQuery::GetHistory { at, since_version } => {
                Self::GetHistory { at, since_version }
            }
            sn_data_types::TransferQuery::GetStoreCost { requester, bytes } => {
                Self::GetStoreCost { requester, bytes }
            }
        }
    }
}
