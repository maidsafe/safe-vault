// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{error::Error as ChunkStoreError, SequenceChunkStore},
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::MessagingDuty,
    node::state_db::NodeInfo,
    Result,
};
use safe_nd::{
    CmdError, Error as NdError, Message, MessageId, MsgSender, QueryResponse, Result as NdResult,
    Sequence, SequenceAction, SequenceAddress, SequenceEntry, SequenceIndex, SequenceOwner,
    SequencePermissions, SequencePrivatePermissions, SequencePublicPermissions, SequenceRead,
    SequenceUser, SequenceWrite, SequenceWriteOp,
};
use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

/// Operations over the data type Sequence.
pub(super) struct SequenceStorage {
    chunks: SequenceChunkStore,
    wrapping: ElderMsgWrapping,
}

impl SequenceStorage {
    pub(super) fn new(
        node_info: NodeInfo,
        total_used_space: &Rc<Cell<u64>>,
        wrapping: ElderMsgWrapping,
    ) -> Result<Self> {
        let chunks = SequenceChunkStore::new(
            node_info.path(),
            node_info.max_storage_capacity,
            Rc::clone(total_used_space),
            node_info.init_mode,
        )?;
        Ok(Self { chunks, wrapping })
    }

    pub(super) fn read(
        &self,
        read: &SequenceRead,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        use SequenceRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, &origin),
            GetRange { address, range } => self.get_range(*address, *range, msg_id, &origin),
            GetLastEntry(address) => self.get_last_entry(*address, msg_id, &origin),
            GetOwner(address) => self.get_owner(*address, msg_id, &origin),
            GetUserPermissions { address, user } => {
                self.get_user_permissions(*address, *user, msg_id, &origin)
            }
            GetPermissions(address) => self.get_permissions(*address, msg_id, &origin),
        }
    }

    pub(super) fn write(
        &mut self,
        write: SequenceWrite,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        use SequenceWrite::*;
        match write {
            New(data) => self.store(&data, msg_id, origin),
            Edit(operation) => self.edit(operation, msg_id, origin),
            Delete(address) => self.delete(address, msg_id, origin),
            SetOwner(operation) => self.set_owner(operation, msg_id, origin),
            SetPublicPermissions(operation) => {
                self.set_public_permissions(operation, msg_id, origin)
            }
            SetPrivatePermissions(operation) => {
                self.set_private_permissions(operation, msg_id, origin)
            }
        }
    }

    fn store(
        &mut self,
        data: &Sequence,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(NdError::DataExists)
        } else {
            self.chunks
                .put(&data)
                .map_err(|error| error.to_string().into())
        };
        self.ok_or_error(result, msg_id, &origin)
    }

    fn get(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self.get_chunk(address, SequenceAction::Read, origin);
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetSequence(result),
            id: MessageId::new(),
            query_origin: origin.address(),
            correlation_id: msg_id,
        })
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

    fn delete(
        &mut self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        //let requester_pk = *utils::own_key(&requester)?;
        let result = self
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
                    sequence.check_is_last_owner(origin.id())
                }
            })
            .and_then(|_| {
                self.chunks
                    .delete(&address)
                    .map_err(|error| error.to_string().into())
            });

        self.ok_or_error(result, msg_id, &origin)
    }

    fn get_range(
        &self,
        address: SequenceAddress,
        range: (SequenceIndex, SequenceIndex),
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                sequence
                    .in_range(range.0, range.1)
                    .ok_or(NdError::NoSuchEntry)
            });
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetSequenceRange(result),
            id: MessageId::new(),
            query_origin: origin.address(),
            correlation_id: msg_id,
        })
    }

    fn get_last_entry(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| match sequence.last_entry() {
                Some(entry) => Ok((sequence.entries_index() - 1, entry.to_vec())),
                None => Err(NdError::NoSuchEntry),
            });
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetSequenceLastEntry(result),
            id: MessageId::new(),
            query_origin: origin.address(),
            correlation_id: msg_id,
        })
    }

    fn get_owner(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let index = sequence.owners_index() - 1;
                sequence.owner(index).cloned().ok_or(NdError::InvalidOwners)
            });
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetSequenceOwner(result),
            id: MessageId::new(),
            query_origin: origin.address(),
            correlation_id: msg_id,
        })
    }

    fn get_user_permissions(
        &self,
        address: SequenceAddress,
        user: SequenceUser,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let index = sequence.permissions_index() - 1;
                sequence.user_permissions(user, index)
            });
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetSequenceUserPermissions(result),
            id: MessageId::new(),
            query_origin: origin.address(),
            correlation_id: msg_id,
        })
    }

    fn get_permissions(
        &self,
        address: SequenceAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let result = self
            .get_chunk(address, SequenceAction::Read, origin)
            .and_then(|sequence| {
                let index = sequence.permissions_index() - 1;
                let res = if sequence.is_pub() {
                    SequencePermissions::from(sequence.pub_permissions(index)?.clone())
                } else {
                    SequencePermissions::from(sequence.private_permissions(index)?.clone())
                };
                Ok(res)
            });
        self.wrapping.send(Message::QueryResponse {
            response: QueryResponse::GetSequencePermissions(result),
            id: MessageId::new(),
            query_origin: origin.address(),
            correlation_id: msg_id,
        })
    }

    fn set_public_permissions(
        &mut self,
        write_op: SequenceWriteOp<SequencePublicPermissions>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let address = write_op.address;
        let result = self.edit_chunk(
            address,
            SequenceAction::ManagePermissions,
            origin,
            move |mut sequence| {
                sequence.apply_crdt_pub_perms_op(write_op.crdt_op)?;
                Ok(sequence)
            },
        );
        self.ok_or_error(result, msg_id, &origin)
    }

    fn set_private_permissions(
        &mut self,
        write_op: SequenceWriteOp<SequencePrivatePermissions>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let address = write_op.address;
        let result = self.edit_chunk(
            address,
            SequenceAction::ManagePermissions,
            origin,
            move |mut sequence| {
                sequence.apply_crdt_private_perms_op(write_op.crdt_op)?;
                Ok(sequence)
            },
        );
        self.ok_or_error(result, msg_id, origin)
    }

    fn set_owner(
        &mut self,
        write_op: SequenceWriteOp<SequenceOwner>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let address = write_op.address;
        let result = self.edit_chunk(
            address,
            SequenceAction::ManagePermissions,
            origin,
            move |mut sequence| {
                sequence.apply_crdt_owner_op(write_op.crdt_op);
                Ok(sequence)
            },
        );
        self.ok_or_error(result, msg_id, &origin)
    }

    fn edit(
        &mut self,
        write_op: SequenceWriteOp<SequenceEntry>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let address = write_op.address;
        let result = self.edit_chunk(
            address,
            SequenceAction::Append,
            origin,
            move |mut sequence| {
                sequence.apply_crdt_op(write_op.crdt_op);
                Ok(sequence)
            },
        );
        self.ok_or_error(result, msg_id, origin)
    }

    fn edit_chunk<F>(
        &mut self,
        address: SequenceAddress,
        action: SequenceAction,
        origin: &MsgSender,
        write_fn: F,
    ) -> NdResult<()>
    where
        F: FnOnce(Sequence) -> NdResult<Sequence>,
    {
        self.get_chunk(address, action, origin)
            .and_then(write_fn)
            .and_then(move |sequence| {
                self.chunks
                    .put(&sequence)
                    .map_err(|error| error.to_string().into())
            })
    }

    fn ok_or_error<T>(
        &self,
        result: NdResult<T>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<MessagingDuty> {
        let error = match result {
            Ok(_) => return None,
            Err(error) => error,
        };
        self.wrapping.send(Message::CmdError {
            id: MessageId::new(),
            error: CmdError::Data(error),
            correlation_id: msg_id,
            cmd_origin: origin.address(),
        })
    }
}

impl Display for SequenceStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SequenceStorage")
    }
}
