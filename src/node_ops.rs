// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_data_types::{
    ActorHistory, Blob, BlobAddress, CreditAgreementProof, NodeAge, PublicKey, RewardAccumulation,
    RewardProposal, SignedTransfer, TransferAgreementProof,
};
use sn_messaging::{
    client::{BlobRead, BlobWrite, Message, ProcessMsg},
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};
use sn_routing::Prefix;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Formatter},
};
use xor_name::XorName;

/// Internal messages are what is passed along
/// within a node, between the entry point and
/// exit point of remote messages.
/// In other words, when communication from another
/// participant at the network arrives, it is mapped
/// to an internal message, that can
/// then be passed along to its proper processing module
/// at the node. At a node module, the result of such a call
/// is also an internal message.
/// Finally, an internal message might be destined for messaging
/// module, by which it leaves the process boundary of this node
/// and is sent on the wire to some other destination(s) on the network.

/// Vec of NodeDuty
pub type NodeDuties = Vec<NodeDuty>;

/// Common duties run by all nodes.
#[allow(clippy::large_enum_variant)]
pub enum NodeDuty {
    AddPayment(CreditAgreementProof),
    GetNodeWalletKey {
        node_name: XorName,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    PropagateTransfer {
        proof: CreditAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    SetNodeWallet {
        wallet_id: PublicKey,
        node_id: XorName,
    },
    GetTransferReplicaEvents {
        msg_id: MessageId,
        origin: SrcLocation,
    },
    /// Validate a transfer from a client
    ValidateClientTransfer {
        signed_transfer: SignedTransfer,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    /// Register a transfer from a client
    RegisterTransfer {
        proof: TransferAgreementProof,
        msg_id: MessageId,
    },
    /// TEMP: Simulate a transfer from a client
    SimulatePayout {
        transfer: Transfer,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    ReadChunk {
        read: BlobRead,
        msg_id: MessageId,
        origin: EndUser,
    },
    WriteChunk {
        write: BlobWrite,
        msg_id: MessageId,
        origin: EndUser,
    },
    /// Get section elders.
    GetSectionElders {
        msg_id: MessageId,
        origin: SrcLocation,
    },
    /// Get key transfers since specified version.
    GetTransfersHistory {
        /// The wallet key.
        at: PublicKey,
        /// The last version of transfers we know of.
        since_version: usize,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    /// Get Balance at a specific key
    GetBalance {
        at: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    GetStoreCost {
        /// Number of bytes to write.
        bytes: u64,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    /// Proposal of payout of rewards.
    ReceiveRewardProposal(RewardProposal),
    /// Accumulation of payout of rewards.
    ReceiveRewardAccumulation(RewardAccumulation),
    Genesis,
    EldersChanged {
        /// Our section prefix.
        our_prefix: Prefix,
        /// our section public key
        our_key: PublicKey,
        /// oldie or newbie?
        newbie: bool,
    },
    SectionSplit {
        /// Our section prefix.
        our_prefix: Prefix,
        /// our section public key
        our_key: PublicKey,
        /// The PK of the sibling section, as this event is fired during a split.
        sibling_key: PublicKey,
        /// oldie or newbie?
        newbie: bool,
    },
    /// When demoted, node levels down
    LevelDown,
    /// Initiates the node with state from peers.
    SynchState {
        /// The registered wallet keys for nodes earning rewards
        node_rewards: BTreeMap<XorName, (NodeAge, PublicKey)>,
        /// The wallets of users on the network.
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    },
    /// As members are lost for various reasons
    /// there are certain things nodes need
    /// to do, to update for that.
    ProcessLostMember {
        name: XorName,
        age: u8,
    },
    /// Storage reaching max capacity.
    ReachingMaxCapacity,
    /// Increment count of full nodes in the network
    IncrementFullNodeCount {
        /// Node ID of node that reached max capacity.
        node_id: PublicKey,
    },
    /// Sets joining allowed to true or false.
    SetNodeJoinsAllowed(bool),
    /// Send a message to the specified dst.
    Send(OutgoingMsg),
    /// Send the same request to each individual node.
    SendToNodes {
        msg: ProcessMsg,
        targets: BTreeSet<XorName>,
        aggregation: Aggregation,
    },
    /// Process read of data
    ProcessRead {
        query: sn_messaging::client::DataQuery,
        id: MessageId,
        origin: EndUser,
    },
    /// Process write of data
    ProcessWrite {
        cmd: sn_messaging::client::DataCmd,
        id: MessageId,
        origin: EndUser,
    },
    /// Process Payment for a DataCmd
    ProcessDataPayment {
        msg: ProcessMsg,
        origin: EndUser,
    },
    ///
    FinishReplication(Blob),
    /// Receive a chunk that is being replicated.
    /// This is run at an Adult (the new holder).
    ReplicateChunk(Blob),
    /// Retrieve a chunk
    /// and send it back to to the requesting Elders
    /// for them to replicate it on new nodes.
    ReturnChunkToElders {
        address: BlobAddress,
        id: MessageId,
        section: XorName,
    },
    NoOp,
}

impl From<NodeDuty> for NodeDuties {
    fn from(duty: NodeDuty) -> Self {
        if matches!(duty, NodeDuty::NoOp) {
            vec![]
        } else {
            vec![duty]
        }
    }
}

impl Debug for NodeDuty {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Genesis { .. } => write!(f, "Genesis"),
            Self::AddPayment { .. } => write!(f, "AddPayment"),
            Self::GetNodeWalletKey { .. } => write!(f, "GetNodeWalletKey"),
            Self::PropagateTransfer { .. } => write!(f, "PropagateTransfer"),
            Self::SetNodeWallet { .. } => write!(f, "SetNodeWallet"),
            Self::GetTransferReplicaEvents { .. } => write!(f, "GetTransferReplicaEvents"),
            Self::ValidateClientTransfer { .. } => write!(f, "ValidateClientTransfer"),
            Self::RegisterTransfer { .. } => write!(f, "RegisterTransfer"),
            Self::GetBalance { .. } => write!(f, "GetBalance"),
            Self::GetStoreCost { .. } => write!(f, "GetStoreCost"),
            Self::SimulatePayout { .. } => write!(f, "SimulatePayout"),
            Self::GetTransfersHistory { .. } => write!(f, "GetTransfersHistory"),
            Self::ReadChunk { .. } => write!(f, "ReadChunk"),
            Self::WriteChunk { .. } => write!(f, "WriteChunk"),
            Self::ReceiveRewardProposal { .. } => write!(f, "ReceiveRewardProposal"),
            Self::ReceiveRewardAccumulation { .. } => write!(f, "ReceiveRewardAccumulation"),
            // ------
            Self::LevelDown => write!(f, "LevelDown"),
            Self::SynchState { .. } => write!(f, "SynchState"),
            Self::EldersChanged { .. } => write!(f, "EldersChanged"),
            Self::SectionSplit { .. } => write!(f, "SectionSplit"),
            Self::GetSectionElders { .. } => write!(f, "GetSectionElders"),
            Self::NoOp => write!(f, "No op."),
            Self::ReachingMaxCapacity => write!(f, "ReachingMaxCapacity"),
            Self::ProcessLostMember { .. } => write!(f, "ProcessLostMember"),
            //Self::ProcessRelocatedMember { .. } => write!(f, "ProcessRelocatedMember"),
            Self::IncrementFullNodeCount { .. } => write!(f, "IncrementFullNodeCount"),
            Self::SetNodeJoinsAllowed(_) => write!(f, "SetNodeJoinsAllowed"),
            Self::Send(msg) => write!(f, "Send [ msg: {:?} ]", msg),
            Self::SendToNodes {
                msg,
                targets,
                aggregation,
            } => {
                write!(
                    f,
                    "SendToNodes [ msg: {:?}, targets: {:?}, aggregation: {:?} ]",
                    msg, targets, aggregation
                )
            }
            Self::ProcessRead { .. } => write!(f, "ProcessRead"),
            Self::ProcessWrite { .. } => write!(f, "ProcessWrite"),
            Self::ProcessDataPayment { .. } => write!(f, "ProcessDataPayment"),
            Self::ReturnChunkToElders { .. } => write!(f, "ReturnChunkToElders"),
            Self::FinishReplication(_) => write!(f, "FinishReplication"),
            Self::ReplicateChunk(_) => write!(f, "ReplicateChunk"),
        }
    }
}

// --------------- Messaging ---------------

#[derive(Debug, Clone)]
pub struct OutgoingMsg {
    pub msg: ProcessMsg,
    pub dst: DstLocation,
    pub section_source: bool,
    pub aggregation: Aggregation,
}

impl OutgoingMsg {
    pub fn id(&self) -> MessageId {
        self.msg.id()
    }
}
