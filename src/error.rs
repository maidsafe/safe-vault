// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use log::debug;
use sn_data_types::{Error as DtError, PublicKey};
use sn_messaging::{
    client::{Error as ErrorMessage, Message},
    MessageId,
};
use std::io;
use thiserror::Error;
use xor_name::XorName;

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
    /// ActorHistory must contain only transfers of a single actor.
    #[error("ActorHistory must contain only transfers of a single actor..")]
    InvalidActorHistory,
    /// Not enough space in `ChunkStore` to perform `put`.
    #[error("Sync not valid for the current state of section funds")]
    InvalidSectionFundsStage,
    /// Not enough space in `ChunkStore` to perform `put`.
    #[error("Not enough space")]
    NotEnoughSpace,
    /// No source message provided for ProcessingError
    #[error("No source message for ProcessingError")]
    NoSourceMessageForProcessingError,
    /// No source message provided for ProcessingError
    #[error("Unexpected Process msg. A ProcessingError was expected here...")]
    UnexpectedProcessMsg,
    /// Node does not manage any section funds.
    #[error("Node does not currently manage any section funds")]
    NoSectionFunds,
    /// Node does not manage any metadata, so is likely not a fully prepared elder yet.
    #[error("Node does not currently manage any section metadata")]
    NoSectionMetaData,
    /// Node does not manage any immutable chunks.
    #[error("Node does not currently manage any immutable chunks")]
    NoImmutableChunks,
    /// Node is currently churning so cannot perform the request.
    #[error("Cannot complete request due to churning of funds")]
    NodeChurningFunds,
    /// Node is currently churning, but failed to sign a message.
    #[error("Error signing message during churn")]
    ChurnSignError,
    /// The node is not in genesis stage.
    #[error("Not in genesis stage")]
    NotInGenesis,
    /// Target xorname could not be determined from DstLocation
    #[error("No destination name found")]
    NoDestinationName,
    /// Failed to activate a node, due to it being active already
    #[error("Cannot activate node: Node is already active")]
    NodeAlreadyActive,
    /// Not Section PublicKey.
    #[error("Not section public key returned from routing")]
    NoSectionPublicKey,
    /// Unknown as a Section PublicKey.
    #[error("PublicKey provided was not identified as a section {0}")]
    UnknownSectionKey(PublicKey),
    /// Nodes cannot send direct messages
    #[error("Node cannot send direct messages. This functionality will be deprecated in routing.")]
    CannotDirectMessage,
    /// Node cannot be updated, message cannot be resent
    #[error("Process error could not be handled. We cannot update the problem node.")]
    CannotUpdateProcessErrorNode,
    /// Not Section PublicKey.
    #[error("Not section public key returned from routing for xorname {0}")]
    NoSectionPublicKeyKnown(XorName),
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
    #[error("No such chunk")]
    NoSuchChunk,
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
    /// Network processing error message.
    #[error("Procesing error:: {0:?}")]
    ProcessingError(sn_messaging::client::ProcessingError),
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
    /// No mapping to sn_messages::Error could be found. Either we need a new error there, or we need to handle or convert this error before sending it as a message
    #[error("No mapping to sn_messages error is set up for this NodeError {0}")]
    NoErrorMapping(String),
    /// Logic error.
    #[error("Logic error: {0}")]
    Logic(String),
    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),
    /// Unable to send message
    #[error("Unable to send message: {0:?}")]
    UnableToSend(Message),
}

pub(crate) fn convert_to_error_message(error: Error) -> Result<sn_messaging::client::Error> {
    // debug!("Attempting to map sn_node error to sn_messaging error");
    match error {
        Error::NoSectionMetaData => Ok(ErrorMessage::NoSectionMetaData),
        Error::NoImmutableChunks => Ok(ErrorMessage::NoImmutableChunks),
        Error::NodeChurningFunds => Ok(ErrorMessage::NodeChurningFunds),
        Error::NoSectionFunds => Ok(ErrorMessage::NoSectionFunds),
        Error::InvalidOwners(key) => Ok(ErrorMessage::InvalidOwners(key)),
        Error::InvalidSignedTransfer(_) => Ok(ErrorMessage::InvalidSignature),
        Error::TransferAlreadyRegistered => Ok(ErrorMessage::TransactionIdExists),
        Error::NoSuchChunk => Ok(ErrorMessage::NoSuchData),
        Error::NotEnoughSpace => Ok(ErrorMessage::NotEnoughSpace),
        Error::BalanceExists => Ok(ErrorMessage::BalanceExists),
        Error::TempDirCreationFailed(_) => Ok(ErrorMessage::FailedToWriteFile),
        Error::DataExists => Ok(ErrorMessage::DataExists),
        Error::NetworkData(error) => convert_dt_error_to_error_message(error),
        error => Err(Error::NoErrorMapping(error.to_string())),
    }
}
pub(crate) fn convert_dt_error_to_error_message(
    error: DtError,
) -> Result<sn_messaging::client::Error> {
    match error {
        DtError::InvalidOperation => Ok(ErrorMessage::InvalidOperation),
        DtError::PolicyNotSet => Ok(ErrorMessage::PolicyNotSet),
        DtError::NoSuchEntry => Ok(ErrorMessage::NoSuchEntry),
        DtError::CrdtUnexpectedState => Ok(ErrorMessage::CrdtUnexpectedState),
        DtError::OpNotCausallyReady => Ok(ErrorMessage::OpNotCausallyReady),
        DtError::AccessDenied(pk) => Ok(ErrorMessage::AccessDenied(pk)),
        error => Err(Error::NoErrorMapping(error.to_string())),
    }
}

/// Specialisation of `std::Result` for Node.
pub type Result<T, E = Error> = std::result::Result<T, E>;
