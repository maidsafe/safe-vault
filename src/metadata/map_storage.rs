// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::{MapChunkStore, UsedSpace},
    error::convert_to_error_message,
    node_ops::{NodeDuty, OutgoingMsg},
    Error, Network, Result,
};
use log::info;
use sn_data_types::{
    Error as DtError, Map, MapAction, MapAddress, MapEntryActions, MapPermissionSet, MapValue,
    PublicKey, Result as NdResult,
};
use sn_messaging::{
    client::{CmdError, MapRead, MapWrite, ProcessMsg, QueryResponse},
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};

use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};

/// Operations over the data type Map.
pub(super) struct MapStorage {
    chunks: MapChunkStore,
}

impl MapStorage {
    pub(super) async fn new(path: &Path, used_space: UsedSpace) -> Result<Self> {
        let chunks = MapChunkStore::new(path, used_space).await?;
        Ok(Self { chunks })
    }

    pub(super) async fn read(
        &self,
        read: &MapRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
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
        origin: EndUser,
    ) -> Result<NodeDuty> {
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
    fn get_chunk(&self, address: &MapAddress, origin: EndUser, action: MapAction) -> Result<Map> {
        self.chunks.get(&address).and_then(move |map| {
            map.check_permissions(action, origin.id())
                .map(move |_| map)
                .map_err(|error| error.into())
        })
    }

    /// Get Map from the chunk store, update it, and overwrite the stored chunk.
    async fn edit_chunk<F>(
        &mut self,
        address: &MapAddress,
        origin: EndUser,
        msg_id: MessageId,
        mutation_fn: F,
    ) -> Result<NodeDuty>
    where
        F: FnOnce(Map) -> NdResult<Map>,
    {
        let result = match self.chunks.get(address) {
            Ok(data) => match mutation_fn(data) {
                Ok(map) => self.chunks.put(&map).await,
                Err(error) => Err(error.into()),
            },
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, origin).await
    }

    /// Put Map.
    async fn create(&mut self, data: &Map, msg_id: MessageId, origin: EndUser) -> Result<NodeDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(Error::DataExists)
        } else {
            self.chunks.put(&data).await
        };
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn delete(
        &mut self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.chunks.get(&address) {
            Ok(map) => match map.check_is_owner(origin.id()) {
                Ok(()) => {
                    info!("Deleting Map");
                    self.chunks.delete(&address).await
                }
                Err(_e) => {
                    info!("Error: Delete Map called by non-owner");
                    Err(Error::NetworkData(DtError::AccessDenied(*origin.id())))
                }
            },
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
        origin: EndUser,
    ) -> Result<NodeDuty> {
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
        origin: EndUser,
    ) -> Result<NodeDuty> {
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
        origin: EndUser,
    ) -> Result<NodeDuty> {
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
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.get_chunk(&address, origin, MapAction::Read) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetMap(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map shell.
    async fn get_shell(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(&address, origin, MapAction::Read)
            .map(|data| data.shell())
        {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetMapShell(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map version.
    async fn get_version(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(&address, origin, MapAction::Read)
            .map(|data| data.version())
        {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetMapVersion(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map value.
    async fn get_value(
        &self,
        address: MapAddress,
        key: &[u8],
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let res = self.get_chunk(&address, origin, MapAction::Read);
        let result = match res.and_then(|data| match data {
            Map::Seq(map) => map
                .get(key)
                .cloned()
                .map(MapValue::from)
                .ok_or(Error::NetworkData(DtError::NoSuchEntry)),
            Map::Unseq(map) => map
                .get(key)
                .cloned()
                .map(MapValue::from)
                .ok_or(Error::NetworkData(DtError::NoSuchEntry)),
        }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::GetMapValue(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map keys.
    async fn list_keys(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(&address, origin, MapAction::Read)
            .map(|data| data.keys())
        {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::ListMapKeys(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map values.
    async fn list_values(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let res = self.get_chunk(&address, origin, MapAction::Read);
        let result = match res.map(|data| match data {
            Map::Seq(map) => map.values().into(),
            Map::Unseq(map) => map.values().into(),
        }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::ListMapValues(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map entries.
    async fn list_entries(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let res = self.get_chunk(&address, origin, MapAction::Read);
        let result = match res.map(|data| match data {
            Map::Seq(map) => map.entries().clone().into(),
            Map::Unseq(map) => map.entries().clone().into(),
        }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::ListMapEntries(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map permissions.
    async fn list_permissions(
        &self,
        address: MapAddress,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(&address, origin, MapAction::Read)
            .map(|data| data.permissions())
        {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::ListMapPermissions(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    /// Get Map user permissions.
    async fn list_user_permissions(
        &self,
        address: MapAddress,
        user: PublicKey,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(&address, origin, MapAction::Read)
            .and_then(|data| {
                data.user_permissions(&user)
                    .map_err(|e| e.into())
                    .map(MapPermissionSet::clone)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)?),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::QueryResponse {
                response: QueryResponse::ListMapUserPermissions(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn ok_or_error(
        &self,
        result: Result<()>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        if let Err(error) = result {
            let messaging_error = convert_to_error_message(error)?;
            info!("MapStorage: Writing chunk FAILED!");

            Ok(NodeDuty::Send(OutgoingMsg {
                msg: ProcessMsg::CmdError {
                    error: CmdError::Data(messaging_error),
                    id: MessageId::in_response_to(&msg_id),
                    correlation_id: msg_id,
                },
                section_source: false, // strictly this is not correct, but we don't expect responses to a response..
                dst: DstLocation::EndUser(origin),
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            }))
        } else {
            info!("MapStorage: Writing chunk PASSED!");
            Ok(NodeDuty::NoOp)
        }
    }
}

impl Display for MapStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "MapStorage")
    }
}
