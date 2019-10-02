// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    chunk_store::{error::Error as ChunkStoreError, MutableChunkStore},
    rpc::Rpc,
    utils,
    vault::Init,
    Config, Result,
};
use log::error;

use safe_nd::{
    Error as NdError, MData, MDataAction, MDataAddress, MDataEntryActions, MDataPermissionSet,
    MDataValue, MessageId, NodePublicId, PublicId, PublicKey, Response, Result as NdResult,
};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(super) struct MDataHandler {
    id: NodePublicId,
    chunks: MutableChunkStore,
}

impl MDataHandler {
    pub(super) fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        let root_dir = config.root_dir()?;
        let max_capacity = config.max_capacity();
        let chunks = MutableChunkStore::new(
            &root_dir,
            max_capacity,
            Rc::clone(total_used_space),
            init_mode,
        )?;
        Ok(Self { id, chunks })
    }

    /// Get `MData` from the chunk store and check permissions.
    /// Returns `Some(Result<..>)` if the flow should be continued, returns
    /// `None` if there was a logic error encountered and the flow should be
    /// terminated.
    fn get_mdata_chunk(
        &mut self,
        address: &MDataAddress,
        requester: &PublicId,
        action: MDataAction,
    ) -> Option<NdResult<MData>> {
        let requester_pk = if let Some(pk) = utils::own_key(&requester) {
            pk
        } else {
            error!("Logic error: requester {:?} must not be Node", requester);
            return None;
        };

        Some(
            self.chunks
                .get(&address)
                .map_err(|e| match e {
                    ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                    error => error.to_string().into(),
                })
                .and_then(move |mdata| {
                    mdata
                        .check_permissions(action, *requester_pk)
                        .map(move |_| mdata)
                }),
        )
    }

    /// Get MData from the chunk store, update it, and overwrite the stored chunk.
    fn mutate_mdata_chunk<F>(
        &mut self,
        address: &MDataAddress,
        requester: PublicId,
        message_id: MessageId,
        mutation_fn: F,
    ) -> Option<Action>
    where
        F: FnOnce(MData) -> NdResult<MData>,
    {
        let result = self
            .chunks
            .get(address)
            .map_err(|e| match e {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                error => error.to_string().into(),
            })
            .and_then(mutation_fn)
            .and_then(move |mdata| {
                self.chunks
                    .put(&mdata)
                    .map_err(|error| error.to_string().into())
            });

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::Mutation(result),
                message_id,
            },
        })
    }

    /// Put MData.
    pub(super) fn handle_put_mdata_req(
        &mut self,
        requester: PublicId,
        data: MData,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = if self.chunks.has(data.address()) {
            Err(NdError::DataExists)
        } else {
            self.chunks
                .put(&data)
                .map_err(|error| error.to_string().into())
        };
        Some(Action::RespondToClientHandlers {
            sender: *data.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::Mutation(result),
                message_id,
            },
        })
    }

    pub(super) fn handle_delete_mdata_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let requester_pk = *utils::own_key(&requester)?;

        let result = self
            .chunks
            .get(&address)
            .map_err(|e| match e {
                ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                error => error.to_string().into(),
            })
            .and_then(move |mdata| {
                mdata.check_is_owner(requester_pk)?;

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
            },
        })
    }

    /// Set MData user permissions.
    pub(super) fn handle_set_mdata_user_permissions_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        user: PublicKey,
        permissions: &MDataPermissionSet,
        version: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let requester_pk = *utils::own_key(&requester)?;

        self.mutate_mdata_chunk(&address, requester, message_id, move |mut data| {
            data.check_permissions(MDataAction::ManagePermissions, requester_pk)?;
            data.set_user_permissions(user, permissions.clone(), version)?;
            Ok(data)
        })
    }

    /// Delete MData user permissions.
    pub(super) fn handle_del_mdata_user_permissions_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        user: PublicKey,
        version: u64,
        message_id: MessageId,
    ) -> Option<Action> {
        let requester_pk = *utils::own_key(&requester)?;

        self.mutate_mdata_chunk(&address, requester, message_id, move |mut data| {
            data.check_permissions(MDataAction::ManagePermissions, requester_pk)?;
            data.del_user_permissions(user, version)?;
            Ok(data)
        })
    }

    /// Mutate Sequenced MData.
    pub(super) fn handle_mutate_mdata_entries_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        actions: MDataEntryActions,
        message_id: MessageId,
    ) -> Option<Action> {
        let requester_pk = *utils::own_key(&requester)?;

        self.mutate_mdata_chunk(&address, requester, message_id, move |mut data| {
            data.mutate_entries(actions, requester_pk)?;
            Ok(data)
        })
    }

    /// Get entire MData.
    pub(super) fn handle_get_mdata_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self.get_mdata_chunk(&address, &requester, MDataAction::Read)?;

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetMData(result),
                message_id,
            },
        })
    }

    /// Get MData shell.
    pub(super) fn handle_get_mdata_shell_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_mdata_chunk(&address, &requester, MDataAction::Read)?
            .map(|data| data.shell());

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetMDataShell(result),
                message_id,
            },
        })
    }

    /// Get MData version.
    pub(super) fn handle_get_mdata_version_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_mdata_chunk(&address, &requester, MDataAction::Read)?
            .map(|data| data.version());

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::GetMDataVersion(result),
                message_id,
            },
        })
    }

    /// Get MData value.
    pub(super) fn handle_get_mdata_value_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        key: &[u8],
        message_id: MessageId,
    ) -> Option<Action> {
        let res = self.get_mdata_chunk(&address, &requester, MDataAction::Read)?;

        let response = Response::GetMDataValue(res.and_then(|data| {
            match data {
                MData::Seq(md) => md
                    .get(key)
                    .cloned()
                    .map(MDataValue::from)
                    .ok_or_else(|| NdError::NoSuchEntry),
                MData::Unseq(md) => md
                    .get(key)
                    .cloned()
                    .map(MDataValue::from)
                    .ok_or_else(|| NdError::NoSuchEntry),
            }
        }));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response,
                message_id,
            },
        })
    }

    /// Get MData keys.
    pub(super) fn handle_list_mdata_keys_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_mdata_chunk(&address, &requester, MDataAction::Read)?
            .map(|data| data.keys());

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::ListMDataKeys(result),
                message_id,
            },
        })
    }

    /// Get MData values.
    pub(super) fn handle_list_mdata_values_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let res = self.get_mdata_chunk(&address, &requester, MDataAction::Read)?;

        let response = Response::ListMDataValues(res.and_then(|data| match data {
            MData::Seq(md) => Ok(md.values().into()),
            MData::Unseq(md) => Ok(md.values().into()),
        }));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response,
                message_id,
            },
        })
    }

    /// Get MData entries.
    pub(super) fn handle_list_mdata_entries_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let res = self.get_mdata_chunk(&address, &requester, MDataAction::Read)?;

        let response = Response::ListMDataEntries(res.and_then(|data| match data {
            MData::Seq(md) => Ok(md.entries().clone().into()),
            MData::Unseq(md) => Ok(md.entries().clone().into()),
        }));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response,
                message_id,
            },
        })
    }

    /// Get MData permissions.
    pub(super) fn handle_list_mdata_permissions_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_mdata_chunk(&address, &requester, MDataAction::Read)?
            .map(|data| data.permissions());

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::ListMDataPermissions(result),
                message_id,
            },
        })
    }

    /// Get MData user permissions.
    pub(super) fn handle_list_mdata_user_permissions_req(
        &mut self,
        requester: PublicId,
        address: MDataAddress,
        user: PublicKey,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = self
            .get_mdata_chunk(&address, &requester, MDataAction::Read)?
            .and_then(|data| data.user_permissions(user).map(MDataPermissionSet::clone));

        Some(Action::RespondToClientHandlers {
            sender: *address.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::ListMDataUserPermissions(result),
                message_id,
            },
        })
    }
}

impl Display for MDataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
