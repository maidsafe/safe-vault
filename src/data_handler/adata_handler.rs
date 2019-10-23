// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chunk_store::{error::Error as ChunkStoreError, AppendOnlyChunkStore},
    rpc::Rpc,
    utils,
    vault::Init,
    Config, Result,
};
use log::error;

use safe_nd::{
    AData, ADataAction, ADataAddress, ADataAppendOperation, ADataIndex, ADataOwner,
    ADataPermissions, ADataPubPermissions, ADataUnpubPermissions, ADataUser, AppendOnlyData,
    Error as NdError, MessageId, NodePublicId, PublicId, PublicKey, Response, Result as NdResult,
    SeqAppendOnly, UnseqAppendOnly,
};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(super) struct ADataHandler {
    id: NodePublicId,
    chunks: AppendOnlyChunkStore,
}

impl ADataHandler {
    pub(super) fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        let root_dir = config.root_dir()?;
        let max_capacity = config.max_capacity();
        let chunks = AppendOnlyChunkStore::new(
            &root_dir,
            max_capacity,
            Rc::clone(total_used_space),
            init_mode,
        )?;
        Ok(Self { id, chunks })
    }

    pub(super) fn handle_put_adata_req(
        &mut self,
        requester: PublicId,
        data: AData,
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

    pub(super) fn handle_delete_adata_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
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
            .and_then(|adata| {
                // TODO - AData::check_permission() doesn't support Delete yet in safe-nd
                if adata.address().is_pub() {
                    Err(NdError::InvalidOperation)
                } else {
                    adata.check_is_last_owner(requester_pk)
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

    pub(super) fn handle_get_adata_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self.get_adata(&requester, address, ADataAction::Read);

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetAData(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_adata_shell_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        data_index: ADataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.shell(data_index));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataShell(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_adata_range_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        range: (ADataIndex, ADataIndex),
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.in_range(range.0, range.1).ok_or(NdError::NoSuchEntry));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataRange(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_adata_indices_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.indices());

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataIndices(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_adata_last_entry_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.last_entry().cloned().ok_or(NdError::NoSuchEntry));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataLastEntry(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_adata_owners_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        owners_index: ADataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| {
                adata
                    .owner(owners_index)
                    .cloned()
                    .ok_or(NdError::InvalidOwners)
            });

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataOwners(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_pub_adata_user_permissions_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        permissions_index: ADataIndex,
        user: ADataUser,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.pub_user_permissions(user, permissions_index));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetPubADataUserPermissions(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_unpub_adata_user_permissions_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        permissions_index: ADataIndex,
        public_key: PublicKey,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.unpub_user_permissions(public_key, permissions_index));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetUnpubADataUserPermissions(result),
                message_id,
                refund: None,
            },
        })
    }

    pub(super) fn handle_get_adata_permissions_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        permissions_index: ADataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        let response = {
            let result = self
                .get_adata(&requester, address, ADataAction::Read)
                .and_then(|adata| {
                    let res = if adata.is_pub() {
                        ADataPermissions::from(adata.pub_permissions(permissions_index)?.clone())
                    } else {
                        ADataPermissions::from(adata.unpub_permissions(permissions_index)?.clone())
                    };

                    Ok(res)
                });
            Response::GetADataPermissions(result)
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

    pub(super) fn handle_get_adata_value_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        key: Vec<u8>,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_adata(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.get(&key).cloned().ok_or(NdError::NoSuchEntry));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataValue(result),
                message_id,
                refund: None,
            },
        })
    }

    fn get_adata(
        &self,
        requester: &PublicId,
        address: ADataAddress,
        action: ADataAction,
    ) -> Result<AData, NdError> {
        let requester_key = utils::own_key(requester).ok_or(NdError::AccessDenied)?;
        let data = self.chunks.get(&address).map_err(|error| match error {
            ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
            _ => error.to_string().into(),
        })?;

        data.check_permission(action, *requester_key)?;
        Ok(data)
    }

    pub(super) fn handle_add_pub_adata_permissions_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        permissions: ADataPubPermissions,
        permissions_idx: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        self.mutate_adata_chunk(
            &requester,
            address,
            ADataAction::ManagePermissions,
            message_id,
            move |mut adata| {
                match adata {
                    AData::PubSeq(ref mut pub_seq_data) => {
                        pub_seq_data.append_permissions(permissions, permissions_idx)?;
                    }
                    AData::PubUnseq(ref mut pub_unseq_data) => {
                        pub_unseq_data.append_permissions(permissions, permissions_idx)?;
                    }
                    _ => {
                        return {
                            error!("{}: Unexpected chunk encountered", own_id);
                            Err(NdError::InvalidOperation)
                        }
                    }
                }
                Ok(adata)
            },
        )
    }

    pub(super) fn handle_add_unpub_adata_permissions_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        permissions: ADataUnpubPermissions,
        permissions_idx: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        self.mutate_adata_chunk(
            &requester,
            address,
            ADataAction::ManagePermissions,
            message_id,
            move |mut adata| {
                match adata {
                    AData::UnpubSeq(ref mut unpub_seq_data) => {
                        unpub_seq_data.append_permissions(permissions, permissions_idx)?;
                    }
                    AData::UnpubUnseq(ref mut unpub_unseq_data) => {
                        unpub_unseq_data.append_permissions(permissions, permissions_idx)?;
                    }
                    _ => {
                        error!("{}: Unexpected chunk encountered", own_id);
                        return Err(NdError::InvalidOperation);
                    }
                }
                Ok(adata)
            },
        )
    }

    pub(super) fn handle_set_adata_owner_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        owner: ADataOwner,
        owners_idx: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        self.mutate_adata_chunk(
            &requester,
            address,
            ADataAction::ManagePermissions,
            message_id,
            move |mut adata| {
                match adata {
                    AData::PubSeq(ref mut adata) => adata.append_owner(owner, owners_idx)?,
                    AData::PubUnseq(ref mut adata) => adata.append_owner(owner, owners_idx)?,
                    AData::UnpubSeq(ref mut adata) => adata.append_owner(owner, owners_idx)?,
                    AData::UnpubUnseq(ref mut adata) => adata.append_owner(owner, owners_idx)?,
                }
                Ok(adata)
            },
        )
    }

    pub(super) fn handle_append_seq_req(
        &mut self,
        requester: PublicId,
        append: ADataAppendOperation,
        index: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        let address = append.address;
        self.mutate_adata_chunk(
            &requester,
            address,
            ADataAction::Append,
            message_id,
            move |mut adata| {
                match adata {
                    AData::PubSeq(ref mut adata) => adata.append(append.values, index)?,
                    AData::UnpubSeq(ref mut adata) => adata.append(append.values, index)?,
                    AData::PubUnseq(_) | AData::UnpubUnseq(_) => {
                        error!("{}: Unexpected unseqential chunk encountered", own_id);
                        return Err(NdError::InvalidOperation);
                    }
                }
                Ok(adata)
            },
        )
    }

    pub(super) fn handle_append_unseq_req(
        &mut self,
        requester: PublicId,
        operation: ADataAppendOperation,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        let address = operation.address;
        self.mutate_adata_chunk(
            &requester,
            address,
            ADataAction::Append,
            message_id,
            move |mut adata| {
                match adata {
                    AData::PubUnseq(ref mut adata) => adata.append(operation.values)?,
                    AData::UnpubUnseq(ref mut adata) => adata.append(operation.values)?,
                    AData::PubSeq(_) | AData::UnpubSeq(_) => {
                        error!("{}: Unexpected sequential chunk encountered", own_id);
                        return Err(NdError::InvalidOperation);
                    }
                }
                Ok(adata)
            },
        )
    }

    fn mutate_adata_chunk<F>(
        &mut self,
        requester: &PublicId,
        address: ADataAddress,
        action: ADataAction,
        message_id: MessageId,
        mutation_fn: F,
    ) -> Option<Action>
    where
        F: FnOnce(AData) -> NdResult<AData>,
    {
        let result = self
            .get_adata(requester, address, action)
            .and_then(mutation_fn)
            .and_then(move |adata| {
                self.chunks
                    .put(&adata)
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

impl Display for ADataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
