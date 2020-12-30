// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::io;
use thiserror::Error;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    /// Not enough space in `ChunkStore` to perform `put`.
    #[error("Not enough space")]
    NotEnoughSpace,
    /// Key, Value pair not found in `ChunkStore`.
    #[error("No such chunk")]
    NoSuchChunk,
    /// Creating temp directory failed.
    #[error("Could not create temp store: {0}")]
    TempDirCreationFailed(String),

    /// Chunk Store Id could not be found
    #[error("Could not fetch StoreId")]
    NoStoreId,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialisation error.
    #[error("JSON serialisation error:: {0}")]
    JsonSerialisation(#[from] serde_json::Error),

    /// Bincode error.
    #[error("Bincode error:: {0}")]
    Bincode(#[from] bincode::Error),

    /// PickleDb error.
    #[error("PickleDb error:: {0}")]
    PickleDb(#[from] pickledb::error::Error),

    /// NetworkData error.
    #[error("Network data error:: {0}")]
    NetworkData(#[from] sn_data_types::Error),

    /// sn_transfers error.
    #[error("Transfer data error:: {0}")]
    Transfer(#[from] sn_transfers::Error),

    /// NetworkData Entry error.
    #[error("Network data entry error: {0:?}")]
    NetworkDataEntry(sn_data_types::EntryError),

    /// Routing error.
    #[error("Routing error:: {0}")]
    Routing(#[from] sn_routing::Error),
    /// Onboarding error
    #[error("Onboarding error")]
    Onboarding,
    /// Message is invalid.
    #[error("Message is invalid")]
    InvalidMessage,
    /// Logic error.
    #[error("Logic error: {0}")]
    Logic(String),
}

/// Specialisation of `std::Result` for Node.
pub type Result<T, E = Error> = std::result::Result<T, E>;
