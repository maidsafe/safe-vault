// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::Error as DtError;
use sn_messaging::Error as ErrorMessage;
use std::io;
use thiserror::Error;
#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    /// The key balance already exists when it was expected to be empty (during section genesis)
    #[error("Balance already exists.")]
    BalanceExists,
    /// Not enough space in `ChunkStore` to perform `put`.
    #[error("Not enough space")]
    NotEnoughSpace,
    /// Node not found for rewarding
    #[error("Node not found")]
    NodeNotFound,
    /// Key, Value pair not found in `ChunkStore`.
    #[error("No such chunk")]
    NoSuchChunk,
    /// Creating temp directory failed.
    #[error("Could not create temp store: {0}")]
    TempDirCreationFailed(String),

    /// Chunk Store Id could not be found
    #[error("Could not fetch StoreId")]
    NoStoreId,

    /// Threshold crypto combine signatures error
    #[error("Could not combine signatures")]
    CouldNotCombineSignatures,
    /// Chunk already exists for this node
    #[error("Data already exists at this node")]
    DataExists,

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialisation error.
    #[error("JSON serialisation error:: {0}")]
    JsonSerialisation(#[from] serde_json::Error),

    /// Bincode error.
    #[error("Bincode error:: {0}")]
    Bincode(#[from] bincode::Error),

    /// Network message error.
    #[error("Network message error:: {0}")]
    Message(#[from] sn_messaging::Error),

    /// PickleDb error.
    #[error("PickleDb error:: {0}")]
    PickleDb(#[from] pickledb::error::Error),

    /// NetworkData error.
    #[error("Network data error:: {0}")]
    NetworkData(#[from] sn_data_types::Error),

    /// sn_transfers error.
    #[error("Transfer data error:: {0}")]
    Transfer(#[from] sn_transfers::Error),

    /// Routing error.
    #[error("Routing error:: {0}")]
    Routing(#[from] sn_routing::Error),
    /// Onboarding error
    #[error("Onboarding error")]
    Onboarding,
    /// Transfer has already been registered
    #[error("Transfer has already been registered")]
    TransferAlreadyRegistered,
    /// Message is invalid.
    #[error("Message is invalid")]
    InvalidMessage,

    /// Data owner provided is invalid.
    #[error("Provided PublicKey is not a valid owner. Provided PublicKey: {0}")]
    InvalidOwners(sn_data_types::PublicKey),

    /// Data operation is invalid, eg private operation on public data
    #[error("Invalid operation")]
    InvalidOperation,

    /// Logic error.
    #[error("Logic error: {0}")]
    Logic(String),
}

pub(crate) fn convert_to_error_message(error: Error) -> sn_messaging::Error {
    match error {
        Error::InvalidOperation => ErrorMessage::InvalidOperation,
        Error::NetworkData(error) => convert_dt_error_to_error_message(error),
        error => ErrorMessage::UnexpectedNodeError(error.to_string()),
    }
}
pub(crate) fn convert_dt_error_to_error_message(error: DtError) -> sn_messaging::Error {
    match error {
        DtError::InvalidOperation => ErrorMessage::InvalidOperation,
        DtError::PolicyNotSet => ErrorMessage::PolicyNotSet,
        DtError::NoSuchEntry => ErrorMessage::NoSuchEntry,
        DtError::CrdtUnexpectedState => ErrorMessage::CrdtUnexpectedState,
        DtError::OpNotCausallyReady => ErrorMessage::OpNotCausallyReady,
        DtError::AccessDenied(pk) => ErrorMessage::AccessDenied(pk),

        error => ErrorMessage::UnexpectedNodeError(error.to_string()),
    }
}

/// Specialisation of `std::Result` for Node.
pub type Result<T, E = Error> = std::result::Result<T, E>;
