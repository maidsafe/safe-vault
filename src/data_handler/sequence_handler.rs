// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chunk_store::{error::Error as ChunkStoreError, SequenceChunkStore},
    rpc::Rpc,
    utils,
    vault::Init,
    Config, Result,
};
use log::error;

use safe_nd::{
    AccessList, AccessType, Address, AppendOperation, Error as NdError, MessageId, NodePublicId,
    Owner, PrivateAccessList, PublicAccessList, PublicId, PublicKey, Response, Result as NdResult,
    Sequence, User, Version,
};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(super) struct SequenceHandler {
    id: NodePublicId,
    chunks: SequenceChunkStore,
}

impl SequenceHandler {
    pub(super) fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        let root_dir = config.root_dir()?;
        let max_capacity = config.max_capacity();
        let chunks = SequenceChunkStore::new(
            &root_dir,
            max_capacity,
            Rc::clone(total_used_space),
            init_mode,
        )?;
        Ok(Self { id, chunks })
    }

    pub(super) fn put(
        &mut self,
        requester: PublicId,
        data: Sequence,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = if self.chunks.has(data.address()) {
            Err(NdError::DataExists)
        } else {
            self.chunks
                .put(&data)
                .map_err(|error| error.to_string().into())
        };
        let refund = utils::get_refund_for_put(&result);
        Some(Action::RespondToClientHandlers {
            sender: *data.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::Mutation(result),
                message_id,
                refund,
            },
        })
    }

    pub(super) fn delete(
        &mut self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let requester_pk = utils::own_key(&requester)?;
        let result = self
            .chunks
            .get(&address)
            .map_err(|error| match error {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                error => error.to_string().into(),
            })
            .and_then(|data| {
                // TODO - Sequence::check_permission() doesn't support Delete yet in safe-nd
                if data.address().is_public() {
                    Err(NdError::InvalidOperation)
                } else if data.is_owner(requester_pk) {
                    Ok(data)
                } else {
                    Err(NdError::AccessDenied)
                }
            })
            .and_then(|_| {
                self.chunks
                    .delete(&address)
                    .map_err(|error| error.to_string().into())
            });
        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::Mutation(result),
                message_id,
                // Deletion is free so no refund
                refund: None,
            },
        })
    }

    pub(super) fn get(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self.try_read(&requester, address);

        let response = Response::GetSequence(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_shell(
        &self,
        requester: PublicId,
        address: Address,
        data_version: Option<Version>,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| data.shell(data_version));

        let response = Response::GetSequenceShell(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_range(
        &self,
        requester: PublicId,
        address: Address,
        range: (Version, Version),
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| data.in_range(range.0, range.1).ok_or(NdError::NoSuchEntry));

        let response = Response::GetSequenceRange(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_versions(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| Ok(data.versions()));

        let response = Response::GetSequenceExpectedVersions(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_current_entry(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| data.current_data_entry().ok_or(NdError::NoSuchEntry));

        let response = Response::GetSequenceCurrentEntry(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_owner(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self.try_read(&requester, address).and_then(|data| {
            data.owner_at(Version::FromEnd(0))
                .cloned()
                .ok_or(NdError::InvalidOwners)
        });

        let response = Response::GetSequenceOwner(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_owner_at(
        &self,
        requester: PublicId,
        address: Address,
        version: Version,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self.try_read(&requester, address).and_then(|data| {
            data.owner_at(version)
                .cloned()
                .ok_or(NdError::InvalidOwners)
        });

        let response = Response::GetSequenceOwnerAt(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_owner_history(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.owner_history()));

        let response = Response::GetSequenceOwnerHistory(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_owner_history_range(
        &self,
        requester: PublicId,
        address: Address,
        start: Version,
        end: Version,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref_vec(data.owner_history_range(start, end)));

        let response = Response::GetSequenceOwnerHistoryRange(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_access_list(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let response = {
            let result = self.try_read(&requester, address).and_then(|data| {
                let res = if data.is_public() {
                    AccessList::from(data.public_access_list_at(Version::FromEnd(0))?.clone())
                } else {
                    AccessList::from(data.private_access_list_at(Version::FromEnd(0))?.clone())
                };

                Ok(res)
            });
            Response::GetSequenceAccessList(result)
        };

        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_access_list_at(
        &self,
        requester: PublicId,
        address: Address,
        version: Version,
        message_id: MessageId,
    ) -> Option<Action> {
        let response = {
            let result = self.try_read(&requester, address).and_then(|data| {
                let res = if data.is_public() {
                    AccessList::from(data.public_access_list_at(version)?.clone())
                } else {
                    AccessList::from(data.private_access_list_at(version)?.clone())
                };

                Ok(res)
            });
            Response::GetSequenceAccessListAt(result)
        };

        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_public_access_list_history(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.public_access_list_history()));

        let response = Response::GetPublicSequenceAccessListHistory(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_public_access_list_history_range(
        &self,
        requester: PublicId,
        address: Address,
        start: Version,
        end: Version,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| data.public_access_list_history_range(start, end));

        let response = Response::GetPublicSequenceAccessListHistoryRange(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_private_access_list_history(
        &self,
        requester: PublicId,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.private_access_list_history()));

        let response = Response::GetPrivateSequenceAccessListHistory(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_private_access_list_history_range(
        &self,
        requester: PublicId,
        address: Address,
        start: Version,
        end: Version,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| data.private_access_list_history_range(start, end));

        let response = Response::GetPrivateSequenceAccessListHistoryRange(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_public_user_access(
        &self,
        requester: PublicId,
        address: Address,
        user: User,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.public_user_access_at(user, Version::FromEnd(0))));

        let response = Response::GetPublicSequenceUserPermissions(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_private_user_access(
        &self,
        requester: PublicId,
        address: Address,
        user: &PublicKey,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.private_user_access_at(user, Version::FromEnd(0))));

        let response = Response::GetPrivateSequenceUserPermissions(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_public_user_access_at(
        &self,
        requester: PublicId,
        address: Address,
        version: Version,
        user: User,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.public_user_access_at(user, version)));

        let response = Response::GetPublicSequenceUserPermissionsAt(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_private_user_access_at(
        &self,
        requester: PublicId,
        address: Address,
        version: Version,
        public_key:  &PublicKey,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| self.deref(data.private_user_access_at(public_key, version)));

        let response = Response::GetPrivateSequenceUserPermissionsAt(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn get_value(
        &self,
        requester: PublicId,
        address: Address,
        version: Version,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .try_read(&requester, address)
            .and_then(|data| data.get(version).cloned().ok_or(NdError::NoSuchEntry));

        let response = Response::GetSequenceValue(result);
        self.respond_on_get(requester, response, address, message_id)
    }

    pub(super) fn set_public_access_list(
        &mut self,
        requester: PublicId,
        address: Address,
        access_list: PublicAccessList,
        expected_version: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        self.mutate(
            &requester,
            address,
            AccessType::ModifyPermissions,
            message_id,
            move |mut data| {
                match data {
                    Sequence::Public(ref mut data) => {
                        data.set_access_list(access_list, expected_version)?;
                    }
                    _ => {
                        return {
                            error!("{}: Unexpected chunk encountered", own_id);
                            Err(NdError::InvalidOperation)
                        }
                    }
                }
                Ok(data)
            },
        )
    }

    pub(super) fn set_private_access_list(
        &mut self,
        requester: PublicId,
        address: Address,
        access_list: PrivateAccessList,
        expected_version: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        self.mutate(
            &requester,
            address,
            AccessType::ModifyPermissions,
            message_id,
            move |mut data| {
                match data {
                    Sequence::Private(ref mut data) => {
                        data.set_access_list(access_list, expected_version)?;
                    }
                    _ => {
                        error!("{}: Unexpected chunk encountered", own_id);
                        return Err(NdError::InvalidOperation);
                    }
                }
                Ok(data)
            },
        )
    }

    pub(super) fn set_owner(
        &mut self,
        requester: PublicId,
        address: Address,
        owner: Owner,
        expected_version: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        self.mutate(
            &requester,
            address,
            AccessType::ModifyPermissions,
            message_id,
            move |mut data| match data.set_owner(owner, expected_version) {
                Ok(_) => Ok(data),
                Err(msg) => Err(msg),
            },
        )
    }

    pub(super) fn append(
        &mut self,
        requester: PublicId,
        operation: &AppendOperation,
        message_id: MessageId,
    ) -> Option<Action> {
        let address = operation.address;
        self.mutate(
            &requester,
            address,
            AccessType::Append,
            message_id,
            move |mut data| match data.append(operation) {
                Ok(_) => Ok(data),
                Err(error) => Err(error),
            },
        )
    }

    fn respond_on_get(
        &self,
        requester: PublicId,
        response: Response,
        address: Address,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response,
                message_id,
                refund: None,
            },
        })
    }

    fn deref_vec<T>(&self, result: safe_nd::Result<Vec<&T>>) -> safe_nd::Result<Vec<T>> where T: Clone {
        Ok(result?.into_iter().cloned().collect())
     }

    fn deref<T>(&self, result: safe_nd::Result<&T>) -> safe_nd::Result<T> where T: Clone {
        Ok(result?.clone())
    }

    fn try_read(&self, requester: &PublicId, address: Address) -> Result<Sequence, NdError> {
        self.try_get(requester, address, AccessType::Read)
    }

    fn try_get(
        &self,
        requester: &PublicId,
        address: Address,
        action: AccessType,
    ) -> Result<Sequence, NdError> {
        let requester_key = utils::own_key(requester).ok_or(NdError::AccessDenied)?;
        let data = self.chunks.get(&address).map_err(|error| match error {
            ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
            _ => error.to_string().into(),
        })?;

        if data.is_allowed(action, requester_key) {
            Ok(data)
        } else {
            Err(NdError::AccessDenied)
        }
    }

    fn mutate<F>(
        &mut self,
        requester: &PublicId,
        address: Address,
        action: AccessType,
        message_id: MessageId,
        mutation_fn: F,
    ) -> Option<Action>
    where
        F: FnOnce(Sequence) -> NdResult<Sequence>,
    {
        let result = self
            .try_get(requester, address, action)
            .and_then(mutation_fn)
            .and_then(move |data| {
                self.chunks
                    .put(&data)
                    .map_err(|error| error.to_string().into())
            });
        let refund = utils::get_refund_for_put(&result);
        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester: requester.clone(),
                response: Response::Mutation(result),
                message_id,
                refund,
            },
        })
    }
}

impl Display for SequenceHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
