// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adata_handler;
mod idata_handler;
mod idata_holder;
mod idata_op;
mod mdata_handler;

use crate::{action::Action, rpc::Rpc, vault::Init, Config, Result};
use adata_handler::ADataHandler;
use idata_handler::IDataHandler;
use idata_holder::IDataHolder;
use idata_op::{IDataOp, IDataRequest, OpType};
use log::{error, trace};
use mdata_handler::MDataHandler;

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
    adata_handler: ADataHandler,
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
        let adata_handler = ADataHandler::new(id.clone(), config, total_used_space, init_mode)?;
        Ok(Self {
            id,
            idata_handler,
            idata_holder,
            mdata_handler,
            adata_handler,
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
            _ => {
                error!("{}: Received invalid vault RPC: {:?}", self, rpc);
                None
            }
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
                .handle_put_mdata_req(requester, data, message_id),
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
            // ===== Append Only Data =====
            //
            PutAData(data) => self
                .adata_handler
                .handle_put_adata_req(requester, data, message_id),
            GetAData(address) => self
                .adata_handler
                .handle_get_adata_req(requester, address, message_id),
            GetADataValue { address, key } => self
                .adata_handler
                .handle_get_adata_value_req(requester, address, key, message_id),
            GetADataShell {
                address,
                data_index,
            } => self
                .adata_handler
                .handle_get_adata_shell_req(requester, address, data_index, message_id),
            GetADataRange { address, range } => self
                .adata_handler
                .handle_get_adata_range_req(requester, address, range, message_id),
            GetADataIndices(address) => self
                .adata_handler
                .handle_get_adata_indices_req(requester, address, message_id),
            GetADataLastEntry(address) => self
                .adata_handler
                .handle_get_adata_last_entry_req(requester, address, message_id),
            GetADataOwners {
                address,
                owners_index,
            } => self.adata_handler.handle_get_adata_owners_req(
                requester,
                address,
                owners_index,
                message_id,
            ),
            GetPubADataUserPermissions {
                address,
                permissions_index,
                user,
            } => self
                .adata_handler
                .handle_get_pub_adata_user_permissions_req(
                    requester,
                    address,
                    permissions_index,
                    user,
                    message_id,
                ),
            GetUnpubADataUserPermissions {
                address,
                permissions_index,
                public_key,
            } => self
                .adata_handler
                .handle_get_unpub_adata_user_permissions_req(
                    requester,
                    address,
                    permissions_index,
                    public_key,
                    message_id,
                ),
            GetADataPermissions {
                address,
                permissions_index,
            } => self.adata_handler.handle_get_adata_permissions_req(
                requester,
                address,
                permissions_index,
                message_id,
            ),
            DeleteAData(address) => self
                .adata_handler
                .handle_delete_adata_req(requester, address, message_id),
            AddPubADataPermissions {
                address,
                permissions,
                permissions_index,
            } => self.adata_handler.handle_add_pub_adata_permissions_req(
                requester,
                address,
                permissions,
                permissions_index,
                message_id,
            ),
            AddUnpubADataPermissions {
                address,
                permissions,
                permissions_index,
            } => self.adata_handler.handle_add_unpub_adata_permissions_req(
                requester,
                address,
                permissions,
                permissions_index,
                message_id,
            ),
            SetADataOwner {
                address,
                owner,
                owners_index,
            } => self.adata_handler.handle_set_adata_owner_req(
                requester,
                address,
                owner,
                owners_index,
                message_id,
            ),
            AppendSeq { append, index } => self
                .adata_handler
                .handle_append_seq_req(requester, append, index, message_id),
            AppendUnseq(operation) => self
                .adata_handler
                .handle_append_unseq_req(requester, operation, message_id),
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
            | GetAData(_)
            | GetADataValue(_)
            | GetADataShell(_)
            | GetADataOwners(_)
            | GetADataRange(_)
            | GetADataIndices(_)
            | GetADataLastEntry(_)
            | GetADataPermissions(_)
            | GetPubADataUserPermissions(_)
            | GetUnpubADataUserPermissions(_)
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
            self.idata_holder.store_idata(data, requester, message_id)
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
                .delete_unpub_idata(address, client, message_id)
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
            self.idata_holder.get_idata(address, client, message_id)
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
