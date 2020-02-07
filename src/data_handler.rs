// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod idata_handler;
mod idata_holder;
mod idata_op;
mod mdata_handler;
mod sequence_handler;

use crate::{action::Action, rpc::Rpc, vault::Init, Config, Result};
use idata_handler::IDataHandler;
use idata_holder::IDataHolder;
use idata_op::{IDataOp, IDataRequest, OpType};
use log::{error, trace};
use mdata_handler::MDataHandler;
use sequence_handler::SequenceHandler;

use safe_nd::{IData, IDataAddress, MessageId, NodePublicId, PublicId, Request, Response, XorName};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(crate) struct DataHandler {
    id: NodePublicId,
    idata_handler: IDataHandler,
    idata_holder: IDataHolder,
    mdata_handler: MDataHandler,
    sequence_handler: SequenceHandler,
}

impl DataHandler {
    pub fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        let idata_handler = IDataHandler::new(id.clone(), config, init_mode)?;
        let idata_holder = IDataHolder::new(id.clone(), config, total_used_space, init_mode)?;
        let mdata_handler = MDataHandler::new(id.clone(), config, total_used_space, init_mode)?;
        let sequence_handler =
            SequenceHandler::new(id.clone(), config, total_used_space, init_mode)?;
        Ok(Self {
            id,
            idata_handler,
            idata_holder,
            mdata_handler,
            sequence_handler,
        })
    }

    pub fn handle_vault_rpc(&mut self, src: XorName, rpc: Rpc) -> Option<Action> {
        match rpc {
            Rpc::Request {
                request,
                requester,
                message_id,
            } => self.handle_request(src, requester, request, message_id),
            Rpc::Response {
                response,
                message_id,
                ..
            } => self.handle_response(src, response, message_id),
        }
    }

    fn handle_request(
        &mut self,
        src: XorName,
        requester: PublicId,
        request: Request,
        message_id: MessageId,
    ) -> Option<Action> {
        use Request::*;
        trace!(
            "{}: Received ({:?} {:?}) from src {} (client {:?})",
            self,
            request,
            message_id,
            src,
            requester
        );
        match request {
            //
            // ===== Immutable Data =====
            //
            PutIData(data) => self.handle_put_idata_req(src, requester, data, message_id),
            GetIData(address) => self.handle_get_idata_req(src, requester, address, message_id),
            DeleteUnpubIData(address) => {
                self.handle_delete_unpub_idata_req(src, requester, address, message_id)
            }
            //
            // ===== Mutable Data =====
            //
            PutMData(data) => self
                .mdata_handler
                .handle_put_mdata_req(requester, &data, message_id),
            GetMData(address) => self
                .mdata_handler
                .handle_get_mdata_req(requester, address, message_id),
            GetMDataValue { address, ref key } => self
                .mdata_handler
                .handle_get_mdata_value_req(requester, address, key, message_id),
            DeleteMData(address) => self
                .mdata_handler
                .handle_delete_mdata_req(requester, address, message_id),
            GetMDataShell(address) => self
                .mdata_handler
                .handle_get_mdata_shell_req(requester, address, message_id),
            GetMDataVersion(address) => self
                .mdata_handler
                .handle_get_mdata_version_req(requester, address, message_id),
            ListMDataEntries(address) => self
                .mdata_handler
                .handle_list_mdata_entries_req(requester, address, message_id),
            ListMDataKeys(address) => self
                .mdata_handler
                .handle_list_mdata_keys_req(requester, address, message_id),
            ListMDataValues(address) => self
                .mdata_handler
                .handle_list_mdata_values_req(requester, address, message_id),
            ListMDataPermissions(address) => self
                .mdata_handler
                .handle_list_mdata_permissions_req(requester, address, message_id),
            ListMDataUserPermissions { address, user } => self
                .mdata_handler
                .handle_list_mdata_user_permissions_req(requester, address, user, message_id),
            SetMDataUserPermissions {
                address,
                user,
                ref permissions,
                version,
            } => self.mdata_handler.handle_set_mdata_user_permissions_req(
                requester,
                address,
                user,
                permissions,
                version,
                message_id,
            ),
            DelMDataUserPermissions {
                address,
                user,
                version,
            } => self.mdata_handler.handle_del_mdata_user_permissions_req(
                requester, address, user, version, message_id,
            ),
            MutateMDataEntries { address, actions } => self
                .mdata_handler
                .handle_mutate_mdata_entries_req(requester, address, actions, message_id),
            //
            // ===== Sequence =====
            //
            PutSequence(data) => self.sequence_handler.put(requester, data, message_id),
            GetSequence(address) => self.sequence_handler.get(requester, address, message_id),
            GetSequenceValue { address, version } => self
                .sequence_handler
                .get_value(requester, address, version, message_id),
            GetSequenceShell {
                address,
                data_version,
            } => self.sequence_handler.get_shell(
                requester,
                address,
                data_version,
                message_id,
            ),
            GetSequenceRange { address, range } => self
                .sequence_handler
                .get_range(requester, address, range, message_id),
            GetSequenceExpectedVersions(address) => self
                .sequence_handler
                .get_versions(requester, address, message_id),
            GetSequenceCurrentEntry(address) => self
                .sequence_handler
                .get_current_entry(requester, address, message_id),
            GetSequenceOwner(address) => self
                .sequence_handler
                .get_owner(requester, address, message_id),
            GetSequenceOwnerAt { address, version } => self
                .sequence_handler
                .get_owner_at(requester, address, version, message_id),
            GetSequenceOwnerHistory(address) => self
                .sequence_handler
                .get_owner_history(requester, address, message_id),
            GetSequenceOwnerHistoryRange {
                address,
                start,
                end,
            } => self
                .sequence_handler
                .get_owner_history_range(requester, address, start, end, message_id),
            GetSequenceAccessList(address) => self
                .sequence_handler
                .get_access_list(requester, address, message_id),
            GetSequenceAccessListAt { address, version } => self
                .sequence_handler
                .get_access_list_at(requester, address, version, message_id),
            GetPublicSequenceAccessListHistory(address) => self
                .sequence_handler
                .get_public_access_list_history(requester, address, message_id),
            GetPublicSequenceAccessListHistoryRange {
                address,
                start,
                end,
            } => self
                .sequence_handler
                .get_public_access_list_history_range(requester, address, start, end, message_id),
            GetPrivateSequenceAccessListHistory(address) => self
                .sequence_handler
                .get_private_access_list_history(requester, address, message_id),
            GetPrivateSequenceAccessListHistoryRange {
                address,
                start,
                end,
            } => self
                .sequence_handler
                .get_private_access_list_history_range(requester, address, start, end, message_id),
            GetPublicSequenceUserPermissions { address, user } => self
                .sequence_handler
                .get_public_user_access(requester, address, user, message_id),
            GetPrivateSequenceUserPermissions { address, user } => self
                .sequence_handler
                .get_private_user_access(requester, address, &user, message_id),
            GetPublicSequenceUserPermissionsAt {
                address,
                version,
                user,
            } => self
                .sequence_handler
                .get_public_user_access_at(requester, address, version, user, message_id),
            GetPrivateSequenceUserPermissionsAt {
                address,
                version,
                public_key,
            } => self
                .sequence_handler
                .get_private_user_access_at(requester, address, version, &public_key, message_id),
            DeletePrivateSequence(address) => {
                self.sequence_handler.delete(requester, address, message_id)
            }
            SetPublicSequenceAccessList {
                address,
                access_list,
                expected_version,
            } => self.sequence_handler.set_public_access_list(
                requester,
                address,
                access_list,
                expected_version,
                message_id,
            ),
            SetPrivateSequenceAccessList {
                address,
                access_list,
                expected_version,
            } => self.sequence_handler.set_private_access_list(
                requester,
                address,
                access_list,
                expected_version,
                message_id,
            ),
            SetSequenceOwner {
                address,
                owner,
                expected_version,
            } => self.sequence_handler.set_owner(
                requester,
                address,
                owner,
                expected_version,
                message_id,
            ),
            Append(operation) => self
                .sequence_handler
                .append(requester, &operation, message_id),
            //
            // ===== Invalid =====
            //
            GetBalance
            | CreateBalance { .. }
            | CreateLoginPacket(_)
            | CreateLoginPacketFor { .. }
            | UpdateLoginPacket(_)
            | GetLoginPacket(_)
            | ListAuthKeysAndVersion
            | InsAuthKey { .. }
            | TransferCoins { .. }
            | DelAuthKey { .. } => {
                error!(
                    "{}: Should not receive {:?} as a data handler.",
                    self, request
                );
                None
            }
        }
    }

    fn handle_response(
        &mut self,
        src: XorName,
        response: Response,
        message_id: MessageId,
    ) -> Option<Action> {
        use Response::*;
        trace!(
            "{}: Received ({:?} {:?}) from {}",
            self,
            response,
            message_id,
            src
        );
        match response {
            Mutation(result) => self
                .idata_handler
                .handle_mutation_resp(src, result, message_id),
            GetIData(result) => self
                .idata_handler
                .handle_get_idata_resp(src, result, message_id),
            //
            // ===== Invalid =====
            //
            GetMData(_)
            | GetMDataShell(_)
            | GetMDataVersion(_)
            | ListMDataEntries(_)
            | ListMDataKeys(_)
            | ListMDataValues(_)
            | ListMDataUserPermissions(_)
            | ListMDataPermissions(_)
            | GetMDataValue(_)
            | GetSequence(_)
            | GetSequenceShell(_)
            | GetSequenceOwner(_)
            | GetSequenceOwnerAt(_)
            | GetSequenceOwnerHistory(_)
            | GetSequenceOwnerHistoryRange(_)
            | GetSequenceRange(_)
            | GetSequenceValue(_)
            | GetSequenceExpectedVersions(_)
            | GetSequenceCurrentEntry(_)
            | GetSequenceAccessList(_)
            | GetSequenceAccessListAt(_)
            | GetPublicSequenceAccessListHistory(_)
            | GetPublicSequenceAccessListHistoryRange(_)
            | GetPrivateSequenceAccessListHistory(_)
            | GetPrivateSequenceAccessListHistoryRange(_)
            | GetPublicSequenceUserPermissions(_)
            | GetPrivateSequenceUserPermissions(_)
            | GetPublicSequenceUserPermissionsAt(_)
            | GetPrivateSequenceUserPermissionsAt(_)
            | Transaction(_)
            | GetBalance(_)
            | ListAuthKeysAndVersion(_)
            | GetLoginPacket(_) => {
                error!(
                    "{}: Should not receive {:?} as a data handler.",
                    self, response
                );
                None
            }
        }
    }

    fn handle_put_idata_req(
        &mut self,
        src: XorName,
        requester: PublicId,
        data: IData,
        message_id: MessageId,
    ) -> Option<Action> {
        if &src == data.name() {
            // Since the src is the chunk's name, this message was sent by the data handlers to us
            // as a single data handler, implying that we're a data handler chosen to store the
            // chunk.
            self.idata_holder.store_idata(&data, requester, message_id)
        } else {
            self.idata_handler
                .handle_put_idata_req(requester, data, message_id)
        }
    }

    fn handle_delete_unpub_idata_req(
        &mut self,
        src: XorName,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        if &src == address.name() {
            // Since the src is the chunk's name, this message was sent by the data handlers to us
            // as a single data handler, implying that we're a data handler where the chunk is
            // stored.
            let client = self.client_id(&message_id)?.clone();
            self.idata_holder
                .delete_unpub_idata(address, &client, message_id)
        } else {
            // We're acting as data handler, received request from client handlers
            self.idata_handler
                .handle_delete_unpub_idata_req(requester, address, message_id)
        }
    }

    fn handle_get_idata_req(
        &mut self,
        src: XorName,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        if &src == address.name() {
            // The message was sent by the data handlers to us as the one who is supposed to store
            // the chunk. See the sent Get request below.
            let client = self.client_id(&message_id)?.clone();
            self.idata_holder.get_idata(address, &client, message_id)
        } else {
            self.idata_handler
                .handle_get_idata_req(requester, address, message_id)
        }
    }

    fn client_id(&self, message_id: &MessageId) -> Option<&PublicId> {
        self.idata_handler.idata_op(message_id).map(IDataOp::client)
    }
}

impl Display for DataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
