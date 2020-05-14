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
use log::info;

use safe_nd::{
    Error as NdError, MessageId, NodePublicId, PublicId, PublicKey, Response, Result as NdResult,
    SData, SDataAction, SDataAddress, SDataAppendOperation, SDataIndex, SDataPermissions,
    SDataRequest, SDataUser,
};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(super) struct SDataHandler {
    id: NodePublicId,
    chunks: SequenceChunkStore,
}

impl SDataHandler {
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

    pub(super) fn handle_request(
        &mut self,
        requester: PublicId,
        request: SDataRequest,
        message_id: MessageId,
    ) -> Option<Action> {
        use SDataRequest::*;
        match request {
            Store(data) => self.handle_store_req(requester, &data, message_id),
            Get(address) => self.handle_get_req(requester, address, message_id),
            GetRange { address, range } => {
                self.handle_get_range_req(requester, address, range, message_id)
            }
            GetLastEntry(address) => self.handle_get_last_entry_req(requester, address, message_id),
            GetOwner {
                address,
                owners_index,
            } => self.handle_get_owner_req(requester, address, owners_index, message_id),
            GetUserPermissions {
                address,
                permissions_index,
                user,
            } => self.handle_get_user_permissions_req(
                requester,
                address,
                permissions_index,
                user,
                message_id,
            ),
            GetPermissions {
                address,
                permissions_index,
            } => self.handle_get_permissions_req(requester, address, permissions_index, message_id),
            Delete(address) => self.handle_delete_req(requester, address, message_id),
            SetPermissions {
                address,
                permissions,
            } => self.handle_set_permissions_req(&requester, address, permissions, message_id),
            SetOwner { address, owner } => {
                self.handle_set_owner_req(&requester, address, owner, message_id)
            }
            Append(operation) => self.handle_append_req(&requester, operation, message_id),
        }
    }

    fn handle_store_req(
        &mut self,
        requester: PublicId,
        data: &SData,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("STORE SDATA: {:?}", data);
        let result = if self.chunks.has(data.address()) {
            Err(NdError::DataExists)
        } else {
            self.chunks
                .put(&data)
                .map_err(|error| error.to_string().into())
        };
        info!("STORE SDATA RESULT: {:?}", result);
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

    fn handle_get_req(
        &mut self,
        requester: PublicId,
        address: SDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self.get_sdata(&requester, address, SDataAction::Read);
        info!("GET SDATA: {:?}", result);

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetSData(result),
                message_id,
                refund: None,
            },
        })
    }

    fn get_sdata(
        &self,
        requester: &PublicId,
        address: SDataAddress,
        action: SDataAction,
    ) -> Result<SData, NdError> {
        let requester_key = utils::own_key(requester).ok_or(NdError::AccessDenied)?;
        let data = self.chunks.get(&address).map_err(|error| match error {
            ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
            _ => error.to_string().into(),
        })?;

        data.check_permission(action, *requester_key)?;
        Ok(data)
    }

    fn handle_delete_req(
        &mut self,
        requester: PublicId,
        address: SDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let requester_pk = *utils::own_key(&requester)?;
        let result = self
            .chunks
            .get(&address)
            .map_err(|error| match error {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                error => error.to_string().into(),
            })
            .and_then(|sdata| {
                // TODO - AData::check_permission() doesn't support Delete yet in safe-nd
                if sdata.address().is_pub() {
                    Err(NdError::InvalidOperation)
                } else {
                    sdata.check_is_last_owner(requester_pk)
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

    fn handle_get_range_req(
        &mut self,
        requester: PublicId,
        address: SDataAddress,
        range: (SDataIndex, SDataIndex),
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_sdata(&requester, address, SDataAction::Read)
            .and_then(|sdata| sdata.in_range(range.0, range.1).ok_or(NdError::NoSuchEntry));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetSDataRange(result),
                message_id,
                refund: None,
            },
        })
    }

    fn handle_get_last_entry_req(
        &self,
        requester: PublicId,
        address: SDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_sdata(&requester, address, SDataAction::Read)
            .and_then(|sdata| match sdata.last_entry() {
                Some(entry) => Ok((sdata.entries_index() - 1, entry.to_vec())),
                None => Err(NdError::NoSuchEntry),
            });

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetSDataLastEntry(result),
                message_id,
                refund: None,
            },
        })
    }

    fn handle_get_owner_req(
        &self,
        requester: PublicId,
        address: SDataAddress,
        owners_index: SDataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_sdata(&requester, address, SDataAction::Read)
            .and_then(|sdata| {
                sdata
                    .owner(owners_index)
                    .cloned()
                    .ok_or(NdError::InvalidOwners)
            });

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetSDataOwner(result),
                message_id,
                refund: None,
            },
        })
    }

    fn handle_get_user_permissions_req(
        &self,
        requester: PublicId,
        address: SDataAddress,
        permissions_index: SDataIndex,
        user: SDataUser,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_sdata(&requester, address, SDataAction::Read)
            .and_then(|sdata| sdata.user_permissions(user, permissions_index));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetSDataUserPermissions(result),
                message_id,
                refund: None,
            },
        })
    }

    fn handle_get_permissions_req(
        &self,
        requester: PublicId,
        address: SDataAddress,
        permissions_index: SDataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        let response = {
            let result = self
                .get_sdata(&requester, address, SDataAction::Read)
                .and_then(|sdata| {
                    let res = if sdata.is_pub() {
                        SDataPermissions::from(sdata.pub_permissions(permissions_index)?.clone())
                    } else {
                        SDataPermissions::from(sdata.priv_permissions(permissions_index)?.clone())
                    };

                    Ok(res)
                });
            Response::GetSDataPermissions(result)
        };

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

    fn handle_set_permissions_req(
        &mut self,
        requester: &PublicId,
        address: SDataAddress,
        permissions: SDataPermissions,
        message_id: MessageId,
    ) -> Option<Action> {
        self.mutate_sdata_chunk(
            &requester,
            address,
            SDataAction::ManagePermissions,
            message_id,
            move |mut sdata| {
                sdata.set_permissions(&permissions)?;
                Ok(sdata)
            },
        )
    }

    fn handle_set_owner_req(
        &mut self,
        requester: &PublicId,
        address: SDataAddress,
        owner: PublicKey,
        message_id: MessageId,
    ) -> Option<Action> {
        self.mutate_sdata_chunk(
            &requester,
            address,
            SDataAction::ManagePermissions,
            message_id,
            move |mut sdata| {
                sdata.set_owner(owner);
                Ok(sdata)
            },
        )
    }

    fn handle_append_req(
        &mut self,
        requester: &PublicId,
        operation: SDataAppendOperation,
        message_id: MessageId,
    ) -> Option<Action> {
        let address = operation.address;
        self.mutate_sdata_chunk(
            &requester,
            address,
            SDataAction::Append,
            message_id,
            move |mut sdata| {
                info!("APPENDING TO SEQUENCE!");
                sdata.append(operation.values)?;
                Ok(sdata)
            },
        )
    }

    fn mutate_sdata_chunk<F>(
        &mut self,
        requester: &PublicId,
        address: SDataAddress,
        action: SDataAction,
        message_id: MessageId,
        mutation_fn: F,
    ) -> Option<Action>
    where
        F: FnOnce(SData) -> NdResult<SData>,
    {
        let result = self
            .get_sdata(requester, address, action)
            .and_then(mutation_fn)
            .and_then(move |sdata| {
                self.chunks
                    .put(&sdata)
                    .map_err(|error| error.to_string().into())
            });
        info!("MUTATED SEQ: {:?}", result);
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

impl Display for SDataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
