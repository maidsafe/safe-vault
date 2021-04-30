// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::{DataAddress, Error as DtError, PublicKey};
use sn_messaging::{client::Error as ErrorMessage, MessageId};
use std::io;
use thiserror::Error;
use xor_name::XorName;

/// Specialisation of `std::Result` for Node.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[allow(clippy::large_enum_variant)]
#[derive(Error, Debug)]
#[non_exhaustive]
/// Node error variants.
pub enum Error {
    /// Attempted to perform an operation meant only for Adults when we are not one.
    #[error("Attempted Adult operation when not an Adult")]
    NotAnAdult,
    /// Attempted to perform an operation meant only for Elders when we are not one.
    #[error("Attempted Elder operation when not an Elder")]
    NotAnElder,
    /// The key balance already exists when it was expected to be empty (during section genesis)
    #[error("Balance already exists.")]
    BalanceExists,
    /// Not enough space in `ChunkStore` to perform `put`.
    #[error("Not enough space")]
    NotEnoughSpace,
    /// Not Section PublicKey.
    #[error("Not section public key returned from routing")]
    NoSectionPublicKey,
    /// Unknown as a Section PublicKey.
    #[error("PublicKey provided was not identified as a section {0}")]
    UnknownSectionKey(PublicKey),
    /// Not a Section PublicKeyShare.
    #[error("PublicKey provided for signing as elder is not a BLS PublicKeyShare")]
    ProvidedPkIsNotBlsShare,
    /// Not a Section PublicKey.
    #[error("PublicKey provided for signing as elder is not a BLS")]
    ProvidedPkIsNotBls,
    /// Not Section PublicKeySet.
    #[error("Not section public key set returned from routing")]
    NoSectionPublicKeySet,
    /// Not Section PublicKey.
    #[error("Not section public key returned from routing for xorname {0}")]
    NoSectionPublicKeyKnown(XorName),
    /// Unable to parse reward proposal.
    #[error("Cannot parse reward proposal at this stage")]
    InvalidRewardStage,
    /// Node not found for rewarding
    #[error("Node not found for rewards")]
    NodeNotFoundForReward,
    /// Node not found in holders db.
    #[error("No chunks held at node")]
    NodeDoesNotHoldChunks,
    /// No holders of chunk in metadata db.
    #[error("No holders found for chunk")]
    NoHoldersOfChunk,
    /// Key, Value pair not found in `ChunkStore`.
    #[error("No such chunk: {0:?}")]
    NoSuchChunk(DataAddress),
    /// Unable to process fund churn message.
    #[error("Cannot process fund churn message")]
    NotChurningFunds,
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
    #[error("Client message error:: {0}")]
    ClientMessage(#[from] sn_messaging::client::Error),
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
    /// Transfer message is invalid.
    #[error("Signed transfer for Dot: '{0:?}' is not valid. Debit or credit are missing")]
    InvalidSignedTransfer(crdts::Dot<PublicKey>),
    /// Transfer message is invalid.
    #[error("Propagated Credit Agreement proof is not valid. Proof received: {0:?}")]
    InvalidPropagatedTransfer(sn_data_types::CreditAgreementProof),
    /// Message is invalid.
    #[error("Message with id: '{0:?}' is invalid. {1}")]
    InvalidMessage(MessageId, String),
    /// Data owner provided is invalid.
    #[error("Provided PublicKey is not a valid owner. Provided PublicKey: {0}")]
    InvalidOwners(PublicKey),
    /// Operation is invalid, eg signing validation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    /// No mapping to sn_messages::Error could be found. Either we need a new error there, or we need to handle or convert this error before sending it as a message
    #[error("No mapping to sn_messages error is set up for this NodeError {0}")]
    NoErrorMapping(String),
    /// Logic error.
    #[error("Logic error: {0}")]
    Logic(String),
    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),
}

pub(crate) fn convert_to_error_message(error: Error) -> sn_messaging::client::Error {
    match error {
        Error::InvalidOperation(msg) => ErrorMessage::InvalidOperation(msg),
        Error::InvalidMessage(_, msg) => ErrorMessage::InvalidOperation(msg),
        Error::InvalidOwners(key) => ErrorMessage::InvalidOwners(key),
        Error::InvalidSignedTransfer(_) => ErrorMessage::InvalidSignature,
        Error::TransferAlreadyRegistered => ErrorMessage::TransactionIdExists,
        Error::NoSuchChunk(address) => ErrorMessage::DataNotFound(address),
        Error::NotEnoughSpace => ErrorMessage::NotEnoughSpace,
        Error::BalanceExists => ErrorMessage::BalanceExists,
        Error::TempDirCreationFailed(_) => ErrorMessage::FailedToWriteFile,
        Error::DataExists => ErrorMessage::DataExists,
        Error::NetworkData(error) => convert_dt_error_to_error_message(error),
        other => ErrorMessage::InvalidOperation(format!("Failed to perform operation: {}", other)),
    }
}
pub(crate) fn convert_dt_error_to_error_message(error: DtError) -> sn_messaging::client::Error {
    match error {
        DtError::InvalidOperation => {
            ErrorMessage::InvalidOperation("DtError::InvalidOperation".to_string())
        }
        DtError::NoSuchEntry => ErrorMessage::NoSuchEntry,
        DtError::AccessDenied(pk) => ErrorMessage::AccessDenied(pk),
        other => ErrorMessage::InvalidOperation(format!("DtError: {:?}", other)),
    }
}
