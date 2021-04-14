// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    chunk_store::UsedSpace,
    chunks::Chunks,
    event_mapping::{map_routing_event, LazyError, Mapping, MsgContext},
    metadata::{adult_reader::AdultReader, Metadata},
    network::Network,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{reward_stage::RewardStage, Credits, SectionFunds},
    state_db::store_new_reward_keypair,
    transfers::{
        get_replicas::transfer_replicas, replica_signing::ReplicaSigningImpl,
        replicas::ReplicaInfo, Transfers,
    },
    Config, Error, Result,
};
use bls::SecretKey;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use hex_fmt::HexFmt;
use log::{debug, error, info, trace, warn};
use sn_data_types::{
    ActorHistory, Blob, BlobAddress, CreditAgreementProof, CreditId, NodeAge, PublicKey,
    RewardAccumulation, RewardProposal, SectionElders, SignedTransfer, Token, Transfer,
    TransferAgreementProof, TransferPropagated, WalletHistory,
};
use sn_messaging::{
    client::{
        BlobRead, BlobWrite, DataCmd, DataQuery, Message, NodeCmd, NodeEvent, NodeQuery,
        NodeQueryResponse, NodeSystemCmd, NodeSystemQuery, NodeSystemQueryResponse,
        NodeTransferCmd,
    },
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};

use sn_routing::{
    Event as RoutingEvent, EventStream, NodeElderChange, Prefix, XorName,
    ELDER_SIZE as GENESIS_ELDER_COUNT, MIN_AGE,
};
use sn_transfers::{TransferActor, Wallet};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

#[allow(clippy::large_enum_variant)]
pub enum AdultStateCommand {
    GetChunkForReplication {
        address: BlobAddress,
        id: MessageId,
        section: XorName,
    },
    StoreChunkForReplication(Blob),
    WriteChunk {
        write: BlobWrite,
        msg_id: MessageId,
        origin: EndUser,
    },
    ReadChunk {
        read: BlobRead,
        msg_id: MessageId,
        origin: EndUser,
    },
    CheckStorage,
}

#[allow(clippy::large_enum_variant)]
pub enum ElderStateCommand {
    ReceiveWalletAccumulation {
        accumulation: RewardAccumulation,
        section_key: PublicKey,
    },
    ReceiveChurnProposal(RewardProposal),
    MergeUserWallets(BTreeMap<PublicKey, ActorHistory>),
    SetNodeRewardsWallets(BTreeMap<XorName, (NodeAge, PublicKey)>),
    SetSectionFunds(SectionFunds),
    RemoveNodeWallet(XorName),
    AddPayment(CreditAgreementProof),
    UpdateReplicaInfo(ReplicaInfo<ReplicaSigningImpl>),
    DecreaseFullNodeCount(XorName),
    IncreaseFullNodeCount(PublicKey),
    TriggerChunkReplication(XorName),
    FinishChunkReplication(Blob),
    ProcessPayment {
        msg: Message,
        origin: EndUser,
    },
    WriteDataCmd {
        cmd: DataCmd,
        id: MessageId,
        origin: EndUser,
    },
    ReadDataCmd {
        query: DataQuery,
        id: MessageId,
        origin: EndUser,
    },
    RegisterTransfer {
        proof: TransferAgreementProof,
        msg_id: MessageId,
    },
    GetStoreCost {
        bytes: u64,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    GetTransfersBalance {
        at: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    GetTransfersHistory {
        at: PublicKey,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    CreditWithoutProof(Transfer),
    ValidateTransfer {
        signed_transfer: SignedTransfer,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    ReceivePropagated {
        proof: CreditAgreementProof,
        msg_id: MessageId,
        origin: SrcLocation,
    },
    GetTransferReplicaEvents {
        msg_id: MessageId,
        origin: SrcLocation,
    },
}
