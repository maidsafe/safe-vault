// Copyright 2019 MaidSafe.net limited.
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
    AData, ADataAction, ADataAddress, ADataAppendOperation, ADataIndex, ADataOwner,
    ADataPermissions, ADataPubPermissions, ADataUnpubPermissions, ADataUser, Error as NdError,
    MessageId, NodePublicId, PublicId, PublicKey, Response, Result as NdResult, Sequence,
};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(super) struct ADataHandler {
    id: NodePublicId,
    crdt_chunks: SequenceChunkStore,
}

impl ADataHandler {
    pub(super) fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        info!("NEW SequenceChunkStore!");
        let root_dir = config.root_dir()?;
        let max_capacity = config.max_capacity();
        let crdt_chunks = SequenceChunkStore::new(
            &root_dir,
            max_capacity,
            Rc::clone(total_used_space),
            init_mode,
        )?;

        Ok(Self { id, crdt_chunks })
    }

    pub(super) fn handle_put_adata_req(
        &mut self,
        requester: PublicId,
        data: &AData,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("PUT Sequence!!!!!!!!");
        let seq_data = Sequence::new(*data.name(), data.tag());
        let result = if self.crdt_chunks.has(data.address()) {
            Err(NdError::DataExists)
        } else {
            self.crdt_chunks
                .put(&seq_data)
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
        info!("DEL Sequence!!!!!!!!");
        let requester_pk = *utils::own_key(&requester)?;
        let result = self
            .crdt_chunks
            .get(&address)
            .map_err(|error| match error {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                error => error.to_string().into(),
            })
            .and_then(|seq_data| {
                // TODO - Sequence::check_permission() doesn't support Delete yet in safe-nd
                if seq_data.address().is_pub() {
                    Err(NdError::InvalidOperation)
                } else {
                    seq_data.check_is_last_owner(requester_pk)
                }
            })
            .and_then(|_| {
                self.crdt_chunks
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
        info!("GET Sequence!!!!!!!!");
        let result = self.get_seq_data(&requester, address, ADataAction::Read);

        /*Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetAData(result),
                message_id,
                refund: None,
            },
        })*/
        None
    }

    pub(super) fn handle_get_adata_shell_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        data_index: ADataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("GET Sequence Shell!!!!!!!!");
        let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| seq_data.shell(data_index));

        /*Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataShell(result),
                message_id,
                refund: None,
            },
        })*/
        None
    }

    pub(super) fn handle_get_adata_range_req(
        &mut self,
        requester: PublicId,
        address: ADataAddress,
        range: (ADataIndex, ADataIndex),
        message_id: MessageId,
    ) -> Option<Action> {
        info!("GET Sequence Range!!!!!!!!");
        let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| {
                seq_data
                    .in_range(range.0, range.1)
                    .ok_or(NdError::NoSuchEntry)
            });

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
        info!("GET Sequence Indices!!!!!!!!");
        let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| seq_data.indices());

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
        info!("GET Sequence Last entry!!!");
        let seq_result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| seq_data.last_entry().ok_or(NdError::NoSuchEntry));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetADataLastEntry(seq_result),
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
        info!("GET Sequence owner!!!");
        let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| {
                seq_data
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
        info!("GET pub Sequence user perms!!!");
        let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|adata| adata.user_permissions(user, permissions_index));

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
        info!("GET unpub AData user perms!!!");
        /*let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| seq_data.user_permissions(public_key, permissions_index));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetUnpubADataUserPermissions(result),
                message_id,
                refund: None,
            },
        })*/
        None
    }

    pub(super) fn handle_get_adata_permissions_req(
        &self,
        requester: PublicId,
        address: ADataAddress,
        permissions_index: ADataIndex,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("GET Sequence Permissions!!!");
        let response = {
            let result = self
                .get_seq_data(&requester, address, ADataAction::Read)
                .and_then(|seq_data| {
                    let res =
                        ADataPermissions::from(seq_data.permissions(permissions_index)?.clone());
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
        key: &[u8],
        message_id: MessageId,
    ) -> Option<Action> {
        info!("GET Sequence value!!!!");
        let result = self
            .get_seq_data(&requester, address, ADataAction::Read)
            .and_then(|seq_data| seq_data.get(&key).ok_or(NdError::NoSuchEntry));

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

    fn get_seq_data(
        &self,
        requester: &PublicId,
        address: ADataAddress,
        action: ADataAction,
    ) -> Result<Sequence, NdError> {
        info!("GET Sequence (private helper)!!!!!");
        let requester_key = utils::own_key(requester).ok_or(NdError::AccessDenied)?;
        let data = self
            .crdt_chunks
            .get(&address)
            .map_err(|error| match error {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                _ => error.to_string().into(),
            })?;

        data.check_permission(action, *requester_key)?;
        Ok(data)
    }

    pub(super) fn handle_add_pub_adata_permissions_req(
        &mut self,
        requester: &PublicId,
        address: ADataAddress,
        permissions: ADataPubPermissions,
        permissions_idx: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("Add PublicSequence permissions!!!!!!!!");
        let own_id = format!("{}", self);
        self.mutate_seq_data_chunk(
            &requester,
            address,
            ADataAction::ManagePermissions,
            message_id,
            move |mut seq_data| {
                seq_data.append_permissions(permissions, permissions_idx)?;
                Ok(seq_data)
            },
        )
    }

    pub(super) fn handle_add_unpub_adata_permissions_req(
        &mut self,
        requester: &PublicId,
        address: ADataAddress,
        permissions: ADataUnpubPermissions,
        permissions_idx: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("Add PrivateSequence permissions!!!!!!!!");
        None
        // TODO: we need the pub/priv sequence first
        /*let own_id = format!("{}", self);
        self.mutate_seq_data_chunk(
            &requester,
            address,
            ADataAction::ManagePermissions,
            message_id,
            move |mut seq_data| {
                seq_data.append_permissions(permissions, permissions_idx)?;
                Ok(seq_data)
            },
        )*/
    }

    pub(super) fn handle_set_adata_owner_req(
        &mut self,
        requester: &PublicId,
        address: ADataAddress,
        owner: ADataOwner,
        owners_idx: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("Append Sequence Owner!!!!!!!!");
        self.mutate_seq_data_chunk(
            &requester,
            address,
            ADataAction::ManagePermissions,
            message_id,
            move |mut seq_data| {
                seq_data.append_owner(owner, owners_idx)?;
                Ok(seq_data)
            },
        )
    }

    pub(super) fn handle_append_seq_req(
        &mut self,
        requester: &PublicId,
        operation: ADataAppendOperation,
        current_index: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("Append Sequence (guarded)!!!!!!!!");
        let actor = self.id.name().clone();

        self.mutate_seq_data_chunk(
            &requester,
            operation.address,
            ADataAction::Append,
            message_id,
            move |mut seq_data| {
                seq_data.append(operation.values, Some(current_index), actor);
                Ok(seq_data)
            },
        )
    }

    pub(super) fn handle_append_unseq_req(
        &mut self,
        requester: &PublicId,
        operation: ADataAppendOperation,
        message_id: MessageId,
    ) -> Option<Action> {
        info!("Append Sequence (not guarded)!!!!!!!!");
        let actor = self.id.name().clone();

        self.mutate_seq_data_chunk(
            &requester,
            operation.address,
            ADataAction::Append,
            message_id,
            move |mut seq_data| {
                seq_data.append(operation.values, None, actor);
                Ok(seq_data)
            },
        )
    }

    fn mutate_seq_data_chunk<F>(
        &mut self,
        requester: &PublicId,
        address: ADataAddress,
        action: ADataAction,
        message_id: MessageId,
        mutation_fn: F,
    ) -> Option<Action>
    where
        F: FnOnce(Sequence) -> NdResult<Sequence>,
    {
        info!("Mutate Sequence (private helper)!!!!");
        let result = self
            .get_seq_data(requester, address, action)
            .and_then(mutation_fn)
            .and_then(move |seq_data| {
                self.crdt_chunks
                    .put(&seq_data)
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
