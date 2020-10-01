// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{error::Error as ChunkStoreError, SequenceChunkStore, UsedSpace},
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::NodeMessagingDuty,
    node::state_db::NodeInfo,
    Result,
};
use sn_data_types::{
    CmdError, Error as NdError, Message, MessageId, MsgSender, QueryResponse, Result as NdResult,
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
    ) -> Option<NodeMessagingDuty> {
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
    ) -> Option<NodeMessagingDuty> {
        use SequenceWrite::*;
        match write {
            New(data) => self.store(&data, msg_id, origin).await,
            Edit(operation) => self.edit(operation, msg_id, origin).await,
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
    ) -> Option<NodeMessagingDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(NdError::DataExists)
        } else {
            self.chunks
                .put(&data)
                .await
                .map_err(|error| error.to_string().into())
        };
        self.ok_or_error(result, msg_id, &origin).await
    }

    async fn get(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self.get_chunk(address, SequenceAction::Read, origin);
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequence(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    fn get_chunk(
        &self,
        address: SequenceAddress,
        action: SequenceAction,
        origin: &MsgSender,
    ) -> Result<Sequence, NdError> {
        //let requester_key = utils::own_key(requester).ok_or(NdError::AccessDenied)?;
        let data = self.chunks.get(&address).map_err(|error| match error {
            ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
            _ => error.to_string().into(),
        })?;
        data.check_permission(action, origin.id())?;
        Ok(data)
    }

    async fn delete(
        &mut self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = match self
            .chunks
            .get(&address)
            .map_err(|error| match error {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                error => error.to_string().into(),
            })
            .and_then(|sequence| {
                // TODO - Sequence::check_permission() doesn't support Delete yet in safe-nd
                if sequence.address().is_pub() {
                    Err(NdError::InvalidOperation)
                } else {
                    let version = sequence.policy_version();
                    let policy = sequence.private_policy(version)?;
                    if policy.owner != origin.id() {
                        Err(NdError::InvalidOwners)
                    } else {
                        Ok(())
                    }
                }
            }) {
            Ok(()) => self
                .chunks
                .delete(&address)
                .await
                .map_err(|error| error.to_string().into()),
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
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                sequence
                    .in_range(range.0, range.1)
                    .ok_or(NdError::NoSuchEntry)
            });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequenceRange(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    async fn get_last_entry(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| match sequence.last_entry() {
                Some(entry) => Ok((sequence.len() - 1, entry.to_vec())),
                None => Err(NdError::NoSuchEntry),
            });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequenceLastEntry(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    async fn get_owner(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let version = sequence.policy_version() - 1;

                if sequence.is_pub() {
                    let policy = sequence.public_policy(version)?;
                    Ok(policy.owner)
                } else {
                    let policy = sequence.private_policy(version)?;
                    Ok(policy.owner)
                }
            });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequenceOwner(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    async fn get_user_permissions(
        &self,
        address: SequenceAddress,
        user: SequenceUser,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let index = sequence.policy_version() - 1;
                sequence.permissions(user, index)
            });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequenceUserPermissions(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    async fn get_public_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let index = sequence.policy_version() - 1;
                let res = if sequence.is_pub() {
                    let policy = sequence.public_policy(index)?;
                    policy.clone()
                } else {
                    return Err(NdError::from(
                        "Cannot get public policy of private sequence.",
                    ));
                };
                Ok(res)
            });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequencePublicPolicy(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    async fn get_private_policy(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let index = sequence.policy_version() - 1;
                let res = if !sequence.is_pub() {
                    let policy = sequence.private_policy(index)?;
                    policy.clone()
                } else {
                    return Err(NdError::from(
                        "Cannot get private policy of public sequence.",
                    ));
                };
                Ok(res)
            });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetSequencePrivatePolicy(result),
                id: MessageId::new(),
                query_origin: origin.address(),
                correlation_id: msg_id,
            })
            .await
    }

    async fn set_public_permissions(
        &mut self,
        write_op: SequencePolicyWriteOp<SequencePublicPolicy>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
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
    ) -> Option<NodeMessagingDuty> {
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
    // ) -> Option<NodeMessagingDuty> {
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
    ) -> Option<NodeMessagingDuty> {
        let address = write_op.address;
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
        let result = self.get_chunk(address, action, origin)?;
        let sequence = write_fn(result)?;

        self.chunks
            .put(&sequence)
            .await
            .map_err(|error| error.to_string().into())
    }

    async fn ok_or_error<T>(
        &self,
        result: NdResult<T>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let error = match result {
            Ok(_) => return None,
            Err(error) => error,
        };
        self.wrapping
            .send_to_section(Message::CmdError {
                id: MessageId::new(),
                error: CmdError::Data(error),
                correlation_id: msg_id,
                cmd_origin: origin.address(),
            })
            .await
    }
}

impl Display for SequenceStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SequenceStorage")
    }
}
