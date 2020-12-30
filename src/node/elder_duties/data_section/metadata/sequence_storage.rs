// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{SequenceChunkStore, UsedSpace},
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::NodeMessagingDuty,
    node::state_db::NodeInfo,
    Error, Result,
};
use log::{error,info};
use sn_data_types::{
    CmdError, Error as DtError, Message, MessageId, MsgSender, QueryResponse, Result as NdResult,
    Sequence, SequenceAction, SequenceAddress, SequenceDataWriteOp, SequenceEntry, SequenceIndex,
    SequencePolicyWriteOp, SequencePrivatePolicy, SequencePublicPolicy, SequenceRead, SequenceUser,
    SequenceWrite,
};
use std::fmt::{self, Display, Formatter};

/// Operations over the data type Sequence.
pub(super) struct SequenceStorage {
    chunks: SequenceChunkStore,
    wrapping: ElderMsgWrapping,
}

impl SequenceStorage {
    pub(super) async fn new(
        node_info: &NodeInfo,
        used_space: UsedSpace,
        wrapping: ElderMsgWrapping,
    ) -> Result<Self> {
        let chunks =
            SequenceChunkStore::new(node_info.path(), used_space, node_info.init_mode).await?;
        Ok(Self { chunks, wrapping })
    }

    pub(super) async fn read(
        &self,
        read: &SequenceRead,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        use SequenceRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, &origin).await,
            GetRange { address, range } => self.get_range(*address, *range, msg_id, &origin).await,
            GetLastEntry(address) => self.get_last_entry(*address, msg_id, &origin).await,
            GetOwner(address) => self.get_owner(*address, msg_id, &origin).await,
            GetUserPermissions { address, user } => {
                self.get_user_permissions(*address, *user, msg_id, &origin)
                    .await
            }
            GetPublicPolicy(address) => self.get_public_policy(*address, msg_id, &origin).await,
            GetPrivatePolicy(address) => self.get_private_policy(*address, msg_id, &origin).await,
        }
    }

    pub(super) async fn write(
        &mut self,
        write: SequenceWrite,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        use SequenceWrite::*;
        info!("Matching Sequence Write");
        match write {
            New(data) => self.store(&data, msg_id, origin).await,
            Edit(operation) => {
                info!("Editing Sequence");
                self.edit(operation, msg_id, origin).await
            }
            Delete(address) => self.delete(address, msg_id, origin).await,
            SetPublicPolicy(operation) => {
                self.set_public_permissions(operation, msg_id, origin).await
            }
            SetPrivatePolicy(operation) => {
                self.set_private_permissions(operation, msg_id, origin)
                    .await
            }
        }
    }

    async fn store(
        &mut self,
        data: &Sequence,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(DtError::DataExists)
        } else {
            self.chunks
                .put(&data)
                .await
                .map_err(|error| DtError::NetworkOther(error.to_string()))
        };
        self.ok_or_error(result, msg_id, &origin).await
    }

    async fn get(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self.get_chunk(address, SequenceAction::Read, origin);
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequence(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    fn get_chunk(
        &self,
        address: SequenceAddress,
        action: SequenceAction,
        origin: &MsgSender,
    ) -> Result<Sequence, DtError> {
        //let requester_key = utils::own_key(requester).ok_or(DtError::AccessDenied)?;
        let data = self.chunks.get(&address)
            .map_err(|error|  
                {
                    error!("Error getting chun: {:?}", error);
                    DtError::NoSuchData }
                )?;
                // match error {
            // Error::NoSuchChunk => DtError::NoSuchData,
            // err => err DtError::
        // })?;

        data.check_permission(action, Some(origin.id().public_key()), None)?;
        Ok(data)
    }

    async fn delete(
        &mut self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = match self
            .chunks
            .get(&address)
            .map_err(|error| match error {
                Error::NoSuchChunk => DtError::NoSuchData,
                error => DtError::NetworkOther(error.to_string().into()),
            })
            .and_then(|sequence| {
                // TODO - Sequence::check_permission() doesn't support Delete yet in safe-nd
                if sequence.address().is_pub() {
                    return Err(DtError::InvalidOperation);
                }

                if origin.is_client() {
                    let pk = origin.id().public_key();
                    let policy = sequence.private_policy(Some(pk))?;

                    if policy.owner != pk {
                        Err(DtError::InvalidOwners)
                    } else {
                        Ok(())
                    }
                } else {
                    Err(DtError::InvalidOwners)
                }
            }) {
            Ok(()) => self
                .chunks
                .delete(&address)
                .await
                .map_err(|error| DtError::NetworkOther(error.to_string().into())),
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, &origin).await
    }

    async fn get_range(
        &self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                sequence
                    .in_range(range.0, range.1, Some(origin.id().public_key()))?
                    .ok_or(DtError::NoSuchEntry)
            });
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequenceRange(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    async fn get_last_entry(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(
                |sequence| match sequence.last_entry(Some(origin.id().public_key()))? {
                    Some(entry) => Ok((
                        sequence.len(Some(origin.id().public_key()))? - 1,
                        entry.to_vec(),
                    )),
                    None => Err(DtError::NoSuchEntry),
                },
            );
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequenceLastEntry(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    async fn get_owner(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                if sequence.is_pub() {
                    let policy = sequence.public_policy()?;
                    Ok(policy.owner)
                } else {
                    let policy = sequence.private_policy(Some(origin.id().public_key()))?;
                    Ok(policy.owner)
                }
            });
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequenceOwner(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    async fn get_user_permissions(
        &self,
        address: SequenceAddress,
        user: SequenceUser,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| sequence.permissions(user, Some(origin.id().public_key())));
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequenceUserPermissions(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    async fn get_public_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let res = if sequence.is_pub() {
                    let policy = sequence.public_policy()?;
                    policy.clone()
                } else {
                    return Err(DtError::CrdtUnexpectedState);
                };
                Ok(res)
            });
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequencePublicPolicy(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    async fn get_private_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let res = if !sequence.is_pub() {
                    let policy = sequence.private_policy(Some(origin.id().public_key()))?;
                    policy.clone()
                } else {
                    return Err(DtError::CrdtUnexpectedState);
                };
                Ok(res)
            });
        self.wrapping
            .send_to_section(
                Message::QueryResponse {
                    response: QueryResponse::GetSequencePrivatePolicy(result),
                    id: MessageId::in_response_to(&msg_id),
                    query_origin: origin.address(),
                    correlation_id: msg_id,
                },
                true,
            )
            .await
    }

    async fn set_public_permissions(
        &mut self,
        write_op: SequencePolicyWriteOp<SequencePublicPolicy>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let address = write_op.address;
        let result = self
            .edit_chunk(
                address,
                SequenceAction::Admin,
                origin,
                move |mut sequence| {
                    sequence.apply_public_policy_op(write_op)?;
                    Ok(sequence)
                },
            )
            .await;
        self.ok_or_error(result, msg_id, &origin).await
    }

    async fn set_private_permissions(
        &mut self,
        write_op: SequencePolicyWriteOp<SequencePrivatePolicy>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let address = write_op.address;
        let result = self
            .edit_chunk(
                address,
                SequenceAction::Admin,
                origin,
                move |mut sequence| {
                    sequence.apply_private_policy_op(write_op)?;
                    Ok(sequence)
                },
            )
            .await;
        self.ok_or_error(result, msg_id, origin).await
    }

    // fn set_owner(
    //     &mut self,
    //     write_op: SequenceDataWriteOp<SequenceOwner>,
    //     msg_id: MessageId,
    //     origin: &MsgSender,
    // ) -> Result<NodeMessagingDuty> {
    //     let address = write_op.address;
    //     let result = self.edit_chunk(
    //         address,
    //         SequenceAction::Admin,
    //         origin,
    //         move |mut sequence| {
    //             sequence.apply_crdt_owner_op(write_op.crdt_op);
    //             Ok(sequence)
    //         },
    //     );
    //     self.ok_or_error(result, msg_id, &origin)
    // }

    async fn edit(
        &mut self,
        write_op: SequenceDataWriteOp<SequenceEntry>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let address = write_op.address;
        info!("Editing Sequence chunk");
        let result = self
            .edit_chunk(
                address,
                SequenceAction::Append,
                origin,
                move |mut sequence| {
                    sequence.apply_data_op(write_op)?;
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
        origin: &MsgSender,
        write_fn: F,
    ) -> NdResult<()>
    where
        F: FnOnce(Sequence) -> NdResult<Sequence>,
    {
        info!("Getting Sequence chunk for Edit");
        let result = self.get_chunk(address, action, origin)?;
        let sequence = write_fn(result)?;
        info!("Edited Sequence chunk successfully");
        self.chunks
            .put(&sequence)
            .await
            .map_err(|error| DtError::NetworkOther(error.to_string().into()),)
    }

    async fn ok_or_error<T>(
        &self,
        result: NdResult<T>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Result<NodeMessagingDuty> {
        let error = match result {
            Ok(_) => return Ok(NodeMessagingDuty::NoOp),
            Err(error) => {
                info!("Error on writing Sequence! {:?}", error);
                error
            }
        };
        self.wrapping
            .send_to_section(
                Message::CmdError {
                    id: MessageId::new(),
                    error: CmdError::Data(error),
                    correlation_id: msg_id,
                    cmd_origin: origin.address(),
                },
                false,
            )
            .await
    }
}

impl Display for SequenceStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SequenceStorage")
    }
}
