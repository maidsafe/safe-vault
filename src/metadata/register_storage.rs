// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunk_store::RegisterChunkStore,
    error::convert_to_error_message,
    node_ops::{NodeDuty, OutgoingMsg},
    Error, Result,
};
use log::info;
use sn_data_types::register::{Action, Address, Entry, Register, RegisterOp, User};
use sn_messaging::{
    client::{CmdError, Message, QueryResponse, RegisterRead, RegisterWrite},
    Aggregation, DstLocation, EndUser, MessageId,
};

use std::{
    fmt::{self, Display, Formatter},
    path::Path,
};

/// Operations over the data type Register.
pub(super) struct RegisterStorage {
    chunks: RegisterChunkStore,
}

impl RegisterStorage {
    pub(super) async fn new(path: &Path, max_capacity: u64) -> Result<Self> {
        let chunks = RegisterChunkStore::new(path, max_capacity).await?;

        Ok(Self { chunks })
    }

    pub(super) async fn read(
        &self,
        read: &RegisterRead,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use RegisterRead::*;
        match read {
            Get(address) => self.get(*address, msg_id, origin).await,
            Read(address) => self.read_register(*address, msg_id, origin).await,
            GetOwner(address) => self.get_owner(*address, msg_id, origin).await,
            GetUserPermissions { address, user } => {
                self.get_user_permissions(*address, *user, msg_id, origin)
                    .await
            }
            GetPolicy(address) => self.get_policy(*address, msg_id, origin).await,
        }
    }

    pub(super) async fn write(
        &mut self,
        write: RegisterWrite,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        use RegisterWrite::*;
        info!("Matching Register Write");
        match write {
            New(data) => self.store(&data, msg_id, origin).await,
            Edit(operation) => {
                info!("Editing Register");
                self.edit(operation, msg_id, origin).await
            }
            Delete(address) => self.delete(address, msg_id, origin).await,
        }
    }

    async fn store(
        &mut self,
        data: &Register,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = if self.chunks.has(data.address()) {
            Err(Error::DataExists)
        } else {
            self.chunks.put(&data).await
        };
        self.ok_or_error(result, msg_id, origin).await
    }

    async fn get(&self, address: Address, msg_id: MessageId, origin: EndUser) -> Result<NodeDuty> {
        let result = match self.get_chunk(address, Action::Read, origin) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetRegister(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    fn get_chunk(&self, address: Address, action: Action, origin: EndUser) -> Result<Register> {
        let data = self.chunks.get(&address)?;
        data.check_permission(action, Some(*origin.id()))?;
        Ok(data)
    }

    async fn delete(
        &mut self,
        address: Address,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.chunks.get(&address).and_then(|register| {
            // TODO - Register::check_permission() doesn't support Delete yet in safe-nd
            if register.address().is_public() {
                return Err(Error::InvalidMessage(
                    msg_id,
                    "Cannot delete public Register".to_string(),
                ));
            }

            let public_key = *origin.id();
            if public_key != register.owner() {
                Err(Error::InvalidOwners(public_key))
            } else {
                Ok(())
            }
        }) {
            Ok(()) => self.chunks.delete(&address).await,
            Err(error) => Err(error),
        };

        self.ok_or_error(result, msg_id, origin).await
    }

    async fn read_register(
        &self,
        address: Address,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, Action::Read, origin)
            .and_then(|register| register.read(Some(*origin.id())).map_err(Error::from))
        {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::ReadRegister(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_owner(
        &self,
        address: Address,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self.get_chunk(address, Action::Read, origin) {
            Ok(res) => Ok(res.owner()),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetRegisterOwner(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_user_permissions(
        &self,
        address: Address,
        user: User,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, Action::Read, origin)
            .and_then(|register| {
                register
                    .permissions(user, Some(*origin.id()))
                    .map_err(Error::from)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetRegisterUserPermissions(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn get_policy(
        &self,
        address: Address,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let result = match self
            .get_chunk(address, Action::Read, origin)
            .and_then(|register| {
                register
                    .policy(Some(*origin.id()))
                    .map(|p| p.clone())
                    .map_err(Error::from)
            }) {
            Ok(res) => Ok(res),
            Err(error) => Err(convert_to_error_message(error)),
        };

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::QueryResponse {
                response: QueryResponse::GetRegisterPolicy(result),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: DstLocation::EndUser(origin),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }

    async fn edit(
        &mut self,
        write_op: RegisterOp<Entry>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let address = write_op.address;
        info!("Editing Register chunk");
        let result = self
            .edit_chunk(address, Action::Write, origin, move |mut register| {
                register.apply_op(write_op)?;
                Ok(register)
            })
            .await;

        if result.is_ok() {
            info!("Editing Register chunk SUCCESSFUL!");
        } else {
            info!("Editing Register chunk FAILED!");
        }

        self.ok_or_error(result, msg_id, origin).await
    }

    async fn edit_chunk<F>(
        &mut self,
        address: Address,
        action: Action,
        origin: EndUser,
        write_fn: F,
    ) -> Result<()>
    where
        F: FnOnce(Register) -> Result<Register>,
    {
        info!("Getting Register chunk for Edit");
        let result = self.get_chunk(address, action, origin)?;
        let sequence = write_fn(result)?;
        info!("Edited Register chunk successfully");
        self.chunks.put(&sequence).await
    }

    async fn ok_or_error<T>(
        &self,
        result: Result<T>,
        msg_id: MessageId,
        origin: EndUser,
    ) -> Result<NodeDuty> {
        let error = match result {
            Ok(_) => return Ok(NodeDuty::NoOp),
            Err(error) => {
                info!("Error on writing Register! {:?}", error);
                convert_to_error_message(error)
            }
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::CmdError {
                id: MessageId::in_response_to(&msg_id),
                error: CmdError::Data(error),
                correlation_id: msg_id,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an error..
            dst: DstLocation::Section(origin.name()),
            aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
        }))
    }
}

impl Display for RegisterStorage {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "RegisterStorage")
    }
}
