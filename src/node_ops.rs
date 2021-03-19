// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls::PublicKeySet;
#[cfg(feature = "simulated-payouts")]
use sn_data_types::Transfer;
use sn_data_types::{
    ActorHistory, Blob, BlobAddress, Credit, CreditAgreementProof, NodeRewardStage, PublicKey,
    ReplicaEvent, SectionElders, SignatureShare, SignedCredit, SignedTransfer, SignedTransferShare,
    Token, TransferAgreementProof, TransferValidated, WalletHistory,
};
use sn_messaging::{
    client::{BlobRead, BlobWrite, Message, NodeSystemCmd},
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};
use sn_routing::{Elders, NodeElderChange, Prefix};
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
    GetNodeWalletKey {
        old_node_id: XorName,
        new_node_id: XorName,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    PayoutNodeReward {
        wallet: PublicKey,
        node_id: XorName,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    PropagateTransfer {
        proof: CreditAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    RegisterSectionPayout {
        debit_agreement: TransferAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    SetNodeWallet {
        wallet_id: PublicKey,
        node_id: XorName,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    ReceivePayoutValidation {
        validation: TransferValidated,
        msg_id: MessageId,
        origin: SrcLocation,
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

    ValidateSectionPayout {
        signed_transfer: SignedTransferShare,
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
    ContinueWalletChurn {
        replicas: SectionElders,
        msg_id: MessageId,
        origin: SrcLocation,
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

    // GetStoreCost {
    //     /// The requester's key.
    //     requester: PublicKey,
    //     /// Number of bytes to write.
    //     bytes: u64,
    // },
    /// On being promoted, an Adult node becomes an Elder.
    BeginFormingGenesisSection,
    /// Bootstrap of genesis section actor.
    ReceiveGenesisProposal {
        /// The genesis credit.
        credit: Credit,
        /// An individual elder's sig over the credit.
        sig: SignatureShare,
    },
    /// Bootstrap of genesis section actor.
    ReceiveGenesisAccumulation {
        /// The genesis credit.
        signed_credit: SignedCredit,
        /// An individual elder's sig over the credit.
        sig: SignatureShare,
    },
    /// Transition of section actor.
    ReceiveWalletProposal {
        /// The genesis credit.
        credit: Credit,
        /// An individual elder's sig over the credit.
        sig: SignatureShare,
    },
    /// Bootstrap of genesis section actor.
    ReceiveWalletAccumulation {
        /// The genesis credit.
        signed_credit: SignedCredit,
        /// An individual elder's sig over the credit.
        sig: SignatureShare,
    },
    ChurnMembers {
        /// The Elders of our section.
        elders: Elders,
        /// The Elders of the sibling section, if this event is fired during a split.
        /// Otherwise `None`.
        sibling_elders: Option<Elders>,
        /// oldie or newbie?
        newbie: bool,
    },
    /// When demoted, node levels down
    LevelDown,
    /// Initiates the node with state from peers.
    SynchState {
        /// The registered wallet keys for nodes earning rewards
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
        /// The wallets of users on the network.
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    },
    ProcessNewMember(XorName),
    /// As members are lost for various reasons
    /// there are certain things nodes need
    /// to do, to update for that.
    ProcessLostMember {
        name: XorName,
        age: u8,
    },
    ProcessRelocatedMember {
        /// The id of the node at the previous section.
        old_node_id: XorName,
        /// The id of the node at its new section (i.e. this one).
        new_node_id: XorName,
        // The age of the node (among things determines if it is eligible for rewards yet).
        age: u8,
    },
    /// Storage reaching max capacity.
    ReachingMaxCapacity,
    /// Increment count of full nodes in the network
    IncrementFullNodeCount {
        /// Node ID of node that reached max capacity.
        node_id: PublicKey,
    },
    SwitchNodeJoin(bool),
    /// Send a message to the specified dst.
    Send(OutgoingMsg),
    /// Send the same request to each individual node.
    SendToNodes {
        targets: BTreeSet<XorName>,
        msg: Message,
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
        msg: Message,
        origin: EndUser,
    },
    /// Process replication of a chunk on `MemberLeft`
    /// This is run at the node which is the new holder
    /// of a chunk
    ReplicateChunk {
        address: BlobAddress,
        current_holders: BTreeSet<XorName>,
        id: MessageId,
    },
    /// Process a GetChunk operation
    /// and send it back to to the requesting node
    /// for replication
    GetChunkForReplication {
        address: BlobAddress,
        new_holder: XorName,
        id: MessageId,
    },
    /// Store a chunk that is a result of data replication
    /// on `MemberLeft`
    StoreChunkForReplication {
        data: Blob,
        correlation_id: MessageId,
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
            Self::GetNodeWalletKey { .. } => write!(f, "GetNodeWalletKey"),
            Self::PayoutNodeReward { .. } => write!(f, "PayoutNodeReward"),
            Self::PropagateTransfer { .. } => write!(f, "PropagateTransfer"),
            Self::RegisterSectionPayout { .. } => write!(f, "RegisterSectionPayout"),
            Self::SetNodeWallet { .. } => write!(f, "SetNodeWallet"),
            Self::ReceivePayoutValidation { .. } => write!(f, "ReceivePayoutValidation"),
            Self::GetTransferReplicaEvents { .. } => write!(f, "GetTransferReplicaEvents"),
            Self::ValidateSectionPayout { .. } => write!(f, "ValidateSectionPayout"),
            Self::ValidateClientTransfer { .. } => write!(f, "ValidateClientTransfer"),
            Self::RegisterTransfer { .. } => write!(f, "RegisterTransfer"),
            Self::GetBalance { .. } => write!(f, "GetBalance"),
            Self::SimulatePayout { .. } => write!(f, "SimulatePayout"),
            Self::GetTransfersHistory { .. } => write!(f, "GetTransfersHistory"),
            Self::ReadChunk { .. } => write!(f, "ReadChunk"),
            Self::WriteChunk { .. } => write!(f, "WriteChunk"),
            Self::ContinueWalletChurn { .. } => write!(f, "ContinueWalletChurn"),
            Self::ReceiveWalletProposal { .. } => write!(f, "ReceiveWalletProposal"),
            Self::ReceiveWalletAccumulation { .. } => write!(f, "ReceiveWalletAccumulation"),
            // ------
            Self::LevelDown => write!(f, "LevelDown"),
            Self::SynchState { .. } => write!(f, "SynchState"),
            Self::ChurnMembers { .. } => write!(f, "ChurnMembers"),
            Self::GetSectionElders { .. } => write!(f, "GetSectionElders"),
            Self::ReceiveGenesisProposal { .. } => write!(f, "ReceiveGenesisProposal"),
            Self::ReceiveGenesisAccumulation { .. } => write!(f, "ReceiveGenesisAccumulation"),
            Self::BeginFormingGenesisSection => write!(f, "BeginFormingGenesisSection"),

            Self::NoOp => write!(f, "No op."),
            Self::ReachingMaxCapacity => write!(f, "ReachingMaxCapacity"),
            Self::ProcessNewMember(_) => write!(f, "ProcessNewMember"),
            Self::ProcessLostMember { .. } => write!(f, "ProcessLostMember"),
            Self::ProcessRelocatedMember { .. } => write!(f, "ProcessRelocatedMember"),
            Self::IncrementFullNodeCount { .. } => write!(f, "IncrementFullNodeCount"),
            Self::SwitchNodeJoin(_) => write!(f, "SwitchNodeJoin"),
            Self::Send(msg) => write!(f, "Send [ msg: {:?} ]", msg),
            Self::SendToNodes { targets, msg } => {
                write!(f, "SendToNodes [ targets: {:?}, msg: {:?} ]", targets, msg)
            }
            Self::ProcessRead { .. } => write!(f, "ProcessRead"),
            Self::ProcessWrite { .. } => write!(f, "ProcessWrite"),
            Self::ProcessDataPayment { .. } => write!(f, "ProcessDataPayment"),
            Self::ReplicateChunk { .. } => write!(f, "ReplicateChunk"),
            Self::GetChunkForReplication { .. } => write!(f, "GetChunkForReplication"),
            Self::StoreChunkForReplication { .. } => write!(f, "StoreChunkForReplication"),
        }
    }
}

// --------------- Messaging ---------------

#[derive(Debug, Clone)]
pub struct OutgoingMsg {
    pub msg: Message,
    pub dst: DstLocation,
    pub section_source: bool,
    pub aggregation: Aggregation,
}

impl OutgoingMsg {
    pub fn id(&self) -> MessageId {
        self.msg.id()
    }
}
