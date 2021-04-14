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
    RewardAccumulation, RewardProposal, SectionElders, Token, TransferPropagated, WalletHistory,
};
use sn_messaging::{
    client::{
        Message, NodeCmd, NodeEvent, NodeQuery, NodeQueryResponse, NodeSystemCmd, NodeSystemQuery,
        NodeSystemQueryResponse, NodeTransferCmd,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};

use sn_routing::{
    Event as RoutingEvent, EventStream, NodeElderChange, Prefix, XorName,
    ELDER_SIZE as GENESIS_ELDER_COUNT, MIN_AGE,
};
use sn_transfers::{TransferActor, Wallet};
use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

pub(crate) struct AdultRole {
    // immutable chunks
    pub chunks: Chunks,
}

pub(crate) struct ElderRole {
    // data operations
    pub meta_data: Metadata,
    // transfers
    pub transfers: Transfers,
    // reward payouts
    pub section_funds: SectionFunds,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum Role {
    Adult(AdultRole),
    Elder(ElderRole),
}

impl Role {
    pub fn as_adult(&self) -> Result<&AdultRole> {
        match self {
            Self::Adult(adult_state) => Ok(adult_state),
            _ => Err(Error::NotAnAdult),
        }
    }

    pub fn as_adult_mut(&mut self) -> Result<&mut AdultRole> {
        match self {
            Self::Adult(adult_state) => Ok(adult_state),
            _ => Err(Error::NotAnAdult),
        }
    }

    pub fn as_elder(&self) -> Result<&ElderRole> {
        match self {
            Self::Elder(elder_state) => Ok(elder_state),
            _ => Err(Error::NotAnElder),
        }
    }

    pub fn as_elder_mut(&mut self) -> Result<&mut ElderRole> {
        match self {
            Self::Elder(elder_state) => Ok(elder_state),
            _ => Err(Error::NotAnElder),
        }
    }
}
