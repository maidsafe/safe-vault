// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{error::Error as ChunkStoreError, MapChunkStore, UsedSpace},
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::NodeMessagingDuty,
    node::state_db::NodeInfo,
    Result,
};
use sn_data_types::{
    CmdError, Error as NdError, Map, MapAction, MapAddress, MapEntryActions, MapPermissionSet,
    MapRead, MapValue, MapWrite, Message, MessageId, MsgSender, PublicKey, QueryResponse,
    Result as NdResult,
};
use std::fmt::{self, Display, Formatter};

/// Operations over the data type Map.
pub(super) struct MapStorage {
    chunks: MapChunkStore,
    wrapping: ElderMsgWrapping,
}

impl MapStorage {
    pub(super) async fn new(
        node_info: &NodeInfo,
        used_space: UsedSpace,
        wrapping: ElderMsgWrapping,
    ) -> Result<Self> {
        let chunks = MapChunkStore::new(node_info.path(), used_space, node_info.init_mode).await?;
        Ok(Self { chunks, wrapping })
    }

    pub(super) async fn read(
        &self,
        read: &MapRead,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        use MapRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, origin).await,
            GetValue { address, ref key } => self.get_value(*address, key, msg_id, origin).await,
            GetShell(address) => self.get_shell(*address, msg_id, origin).await,
            GetVersion(address) => self.get_version(*address, msg_id, origin).await,
            ListEntries(address) => self.list_entries(*address, msg_id, origin).await,
            ListKeys(address) => self.list_keys(*address, msg_id, origin).await,
            ListValues(address) => self.list_values(*address, msg_id, origin).await,
            ListPermissions(address) => self.list_permissions(*address, msg_id, origin).await,
            ListUserPermissions { address, user } => {
                self.list_user_permissions(*address, *user, msg_id, origin)
                    .await
            }
        }
    }

    pub(super) async fn write(
        &mut self,
        write: MapWrite,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        use MapWrite::*;
        match write {
            New(data) => self.create(&data, msg_id, origin).await,
            Delete(address) => self.delete(address, msg_id, origin).await,
            SetUserPermissions {
                address,
                user,
                ref permissions,
                version,
            } => {
                self.set_user_permissions(address, user, permissions, version, msg_id, origin)
                    .await
            }
            DelUserPermissions {
                address,
                user,
                version,
            } => {
                self.delete_user_permissions(address, user, version, msg_id, origin)
                    .await
            }
            Edit { address, changes } => self.edit_entries(address, changes, msg_id, origin).await,
        }
    }

    /// Get `Map` from the chunk store and check permissions.
    /// Returns `Some(Result<..>)` if the flow should be continued, returns
    /// `None` if there was a logic error encountered and the flow should be
    /// terminated.
    fn get_chunk(
        &self,
        address: &MapAddress,
        origin: &MsgSender,
        action: MapAction,
    ) -> Option<NdResult<Map>> {
        Some(
            self.chunks
                .get(&address)
                .map_err(|e| match e {
                    ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
                    error => error.to_string().into(),
                })
                .and_then(move |map| map.check_permissions(action, origin.id()).map(move |_| map)),
        )
    }

    /// Get Map from the chunk store, update it, and overwrite the stored chunk.
    async fn edit_chunk<F>(
        &mut self,
        address: &MapAddress,
        origin: &MsgSender,
        msg_id: MessageId,
        mutation_fn: F,
    ) -> Option<NodeMessagingDuty>
    where
        F: FnOnce(Map) -> NdResult<Map>,
    {
        let result = match self.chunks.get(address).map_err(|e| match e {
            ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
            error => error.to_string().into(),
        }) {
            Ok(data) => match mutation_fn(data) {
                Ok(map) => self
                    .chunks
                    .put(&map)
                    .await
                    .map_err(|error| error.to_string().into()),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, &origin).await
    }

    /// Put Map.
    async fn create(
        &mut self,
        data: &Map,
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
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn delete(
        &mut self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = match self.chunks.get(&address).map_err(|e| match e {
            ChunkStoreError::NoSuchChunk => NdError::NoSuchData,
            error => error.to_string().into(),
        }) {
            Ok(map) => {
                map.check_is_owner(origin.id()).ok()?;
                self.chunks
                    .delete(&address)
                    .await
                    .map_err(|error| error.to_string().into())
            }
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, origin).await
    }

    /// Set Map user permissions.
    async fn set_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        permissions: &MapPermissionSet,
        version: u64,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        self.edit_chunk(&address, origin, msg_id, move |mut data| {
            data.check_permissions(MapAction::ManagePermissions, origin.id())?;
            data.set_user_permissions(user, permissions.clone(), version)?;
            Ok(data)
        })
        .await
    }

    /// Delete Map user permissions.
    async fn delete_user_permissions(
        &mut self,
        address: MapAddress,
        user: PublicKey,
        version: u64,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        self.edit_chunk(&address, origin, msg_id, move |mut data| {
            data.check_permissions(MapAction::ManagePermissions, origin.id())?;
            data.del_user_permissions(user, version)?;
            Ok(data)
        })
        .await
    }

    /// Edit Map.
    async fn edit_entries(
        &mut self,
        address: MapAddress,
        actions: MapEntryActions,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        self.edit_chunk(&address, origin, msg_id, move |mut data| {
            data.mutate_entries(actions, origin.id())?;
            Ok(data)
        })
        .await
    }

    /// Get entire Map.
    async fn get(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self.get_chunk(&address, origin, MapAction::Read)?;
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetMap(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map shell.
    async fn get_shell(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(&address, origin, MapAction::Read)?
            .map(|data| data.shell());
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetMapShell(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map version.
    async fn get_version(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(&address, origin, MapAction::Read)?
            .map(|data| data.version());
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetMapVersion(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map value.
    async fn get_value(
        &self,
        address: MapAddress,
        key: &[u8],
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let res = self.get_chunk(&address, origin, MapAction::Read)?;
        let result = res.and_then(|data| match data {
            Map::Seq(map) => map
                .get(key)
                .cloned()
                .map(MapValue::from)
                .ok_or_else(|| NdError::NoSuchEntry),
            Map::Unseq(map) => map
                .get(key)
                .cloned()
                .map(MapValue::from)
                .ok_or_else(|| NdError::NoSuchEntry),
        });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::GetMapValue(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map keys.
    async fn list_keys(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(&address, origin, MapAction::Read)?
            .map(|data| data.keys());
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::ListMapKeys(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map values.
    async fn list_values(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let res = self.get_chunk(&address, origin, MapAction::Read)?;
        let result = res.map(|data| match data {
            Map::Seq(map) => map.values().into(),
            Map::Unseq(map) => map.values().into(),
        });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::ListMapValues(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map entries.
    async fn list_entries(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let res = self.get_chunk(&address, origin, MapAction::Read)?;
        let result = res.map(|data| match data {
            Map::Seq(map) => map.entries().clone().into(),
            Map::Unseq(map) => map.entries().clone().into(),
        });
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::ListMapEntries(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map permissions.
    async fn list_permissions(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(&address, origin, MapAction::Read)?
            .map(|data| data.permissions());
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::ListMapPermissions(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    /// Get Map user permissions.
    async fn list_user_permissions(
        &self,
        address: MapAddress,
        user: PublicKey,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        let result = self
            .get_chunk(&address, origin, MapAction::Read)?
            .and_then(|data| data.user_permissions(user).map(MapPermissionSet::clone));
        self.wrapping
            .send_to_section(Message::QueryResponse {
                response: QueryResponse::ListMapUserPermissions(result),
                id: MessageId::new(),
                correlation_id: msg_id,
                query_origin: origin.address(),
            })
            .await
    }

    async fn ok_or_error(
        &self,
        result: NdResult<()>,
        msg_id: MessageId,
        origin: &MsgSender,
    ) -> Option<NodeMessagingDuty> {
        if let Err(error) = result {
            self.wrapping
                .error(CmdError::Data(error), msg_id, &origin.address())
                .await
        } else {
            None
        }
    }
}

impl Display for MapStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "MapStorage")
    }
}
