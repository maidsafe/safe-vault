// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{SequenceChunkStore, UsedSpace},
    error::convert_to_error_message,
    node_ops::{NodeDuty, OutgoingMsg},
    Error, Network, Result,
};
use log::info;
use sn_data_types::{
    Error as DtError, Sequence, SequenceAction, SequenceAddress, SequenceEntry, SequenceIndex,
    SequenceOp, SequenceUser,
};
use sn_messaging::{
    client::{CmdError, ProcessMsg, QueryResponse, SequenceRead, SequenceWrite},
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};

use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};

/// Operations over the data type Sequence.
pub(super) struct SequenceStorage {
    chunks: SequenceChunkStore,
}

impl SequenceStorage {
    pub(super) async fn new(path: &Path, used_space: UsedSpace) -> Result<Self> {
        let chunks = SequenceChunkStore::new(path, used_space).await?;
        Ok(Self { chunks })
    }

    pub(super) async fn read(
        &self,
        read: &SequenceRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use SequenceRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, origin).await,
            GetRange { address, range } => self.get_range(*address, *range, msg_id, origin).await,
            GetLastEntry(address) => self.get_last_entry(*address, msg_id, origin).await,
            GetOwner(address) => self.get_owner(*address, msg_id, origin).await,
            GetUserPermissions { address, user } => {
                self.get_user_permissions(*address, *user, msg_id, origin)
                    .await
            }
            GetPublicPolicy(address) => self.get_public_policy(*address, msg_id, origin).await,
            GetPrivatePolicy(address) => self.get_private_policy(*address, msg_id, origin).await,
        }
    }

    pub(super) async fn write(
        &mut self,
        write: SequenceWrite,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use SequenceWrite::*;
        info!("Matching Sequence Write");
        match write {
            New(data) => self.store(&data, msg_id, origin).await,
            Edit(operation) => {
                info!("Editing Sequence");
                self.edit(operation, msg_id, origin).await
            }
            Delete(address) => self.delete(address, msg_id, origin).await,
        }
    }

    async fn store(
        &mut self,
        data: &Sequence,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(Error::DataExists)
        } else {
            self.chunks.put(&data).await
        };
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn get(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.get_chunk(address, SequenceAction::Read, origin) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequence(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    fn get_chunk(
        &self,
        address: SequenceAddress,
        action: SequenceAction,
        origin: EndUser,
    ) -> Result<Sequence> {
        let data = self.chunks.get(&address)?;
        data.check_permission(action, Some(*origin.id()))?;
        Ok(data)
    }

    async fn delete(
        &mut self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.chunks.get(&address).and_then(|sequence| {
            // TODO - Sequence::check_permission() doesn't support Delete yet in safe-nd
            if sequence.address().is_public() {
                return Err(Error::InvalidMessage(
                    msg_id,
                    "Sequence::check_permission() doesn't support Delete yet in safe-nd"
                        .to_string(),
                ));
            }

            let public_key = *origin.id();
            let policy = sequence.private_policy(Some(public_key))?;
            if public_key != policy.owner {
                Err(Error::InvalidOwners(public_key))
            } else {
                Ok(())
            }
        }) {
            Ok(()) => self.chunks.delete(&address).await,
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, origin).await
    }

    async fn get_range(
        &self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                sequence
                    .in_range(range.0, range.1, Some(*origin.id()))?
                    .ok_or(Error::NetworkData(DtError::NoSuchEntry))
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequenceRange(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_last_entry(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| match sequence.last_entry(Some(*origin.id()))? {
                Some(entry) => Ok((sequence.len(Some(*origin.id()))? - 1, entry.to_vec())),
                None => Err(Error::NetworkData(DtError::NoSuchEntry)),
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequenceLastEntry(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_owner(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                if sequence.is_public() {
                    let policy = sequence.public_policy()?;
                    Ok(policy.owner)
                } else {
                    let policy = sequence.private_policy(Some(*origin.id()))?;
                    Ok(policy.owner)
                }
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequenceOwner(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_user_permissions(
        &self,
        address: SequenceAddress,
        user: SequenceUser,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                sequence
                    .permissions(user, Some(*origin.id()))
                    .map_err(|e| e.into())
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequenceUserPermissions(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_public_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let res = if sequence.is_public() {
                    let policy = sequence.public_policy()?;
                    policy.clone()
                } else {
                    return Err(Error::NetworkData(DtError::CrdtUnexpectedState));
                };
                Ok(res)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequencePublicPolicy(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_private_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let res = if !sequence.is_public() {
                    let policy = sequence.private_policy(Some(*origin.id()))?;
                    policy.clone()
                } else {
                    return Err(Error::NetworkData(DtError::CrdtUnexpectedState));
                };
                Ok(res)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetSequencePrivatePolicy(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn edit(
        &mut self,
        write_op: SequenceOp<SequenceEntry>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let address = write_op.address;
        info!("Editing Sequence chunk");
        let result = self
            .edit_chunk(
                address,
                SequenceAction::Append,
                origin,
                move |mut sequence| {
                    sequence.apply_op(write_op)?;
                    Ok(sequence)
                },
            )
            .await;
        if result.is_ok() {
            info!("Editing Sequence chunk SUCCESSFUL!");
        } else {
            info!("Editing Sequence chunk FAILEDDD!");
        }
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn edit_chunk<F>(
        &mut self,
        address: SequenceAddress,
        action: SequenceAction,
        origin: EndUser,
        write_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(Sequence) -> Result<Sequence>,
    {
        info!("Getting Sequence chunk for Edit");
        let result = self.get_chunk(address, action, origin)?;
        let sequence = write_fn(result)?;
        info!("Edited Sequence chunk successfully");
        self.chunks.put(&sequence).await
    }

    async fn ok_or_error<T>(
        &self,
        result: Result<T>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let error = match result {
            Ok(_) => return Ok(NodeDuty::NoOp),
            Err(error) => {
                info!("Error on writing Sequence! {:?}", error);
                convert_to_error_message(error)?
            }
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::CmdError {
                id: MessageId::in_response_to(&msg_id),
                error: CmdError::Data(error),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an error..
            dst: DstLocation::Section(origin.name()),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }
}

impl Display for SequenceStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SequenceStorage")
    }
}
