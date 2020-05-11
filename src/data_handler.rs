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

use crate::{action::Action, routing::Node, rpc::Rpc, vault::Init, Config, Result};
use adata_handler::ADataHandler;
use idata_handler::IDataHandler;
use idata_holder::IDataHolder;
use idata_op::{IDataOp, OpType};
use log::{error, trace};
use mdata_handler::MDataHandler;

use safe_nd::{IDataRequest, MessageId, NodePublicId, PublicId, Request, Response, XorName};

use std::{
    cell::{Cell, RefCell},
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(crate) struct DataHandler {
    id: NodePublicId,
    idata_holder: IDataHolder,
    idata_handler: Option<IDataHandler>,
    mdata_handler: Option<MDataHandler>,
    adata_handler: Option<ADataHandler>,
}

impl DataHandler {
    pub fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
        is_elder: bool,
        routing_node: Rc<RefCell<Node>>,
    ) -> Result<Self> {
        let idata_holder = IDataHolder::new(id.clone(), config, total_used_space, init_mode)?;
        let (idata_handler, mdata_handler, adata_handler) = if is_elder {
            let idata_handler = IDataHandler::new(id.clone(), config, init_mode, routing_node)?;
            let mdata_handler = MDataHandler::new(id.clone(), config, total_used_space, init_mode)?;
            let adata_handler = ADataHandler::new(id.clone(), config, total_used_space, init_mode)?;
            (
                Some(idata_handler),
                Some(mdata_handler),
                Some(adata_handler),
            )
        } else {
            (None, None, None)
        };
        Ok(Self {
            id,
            idata_holder,
            idata_handler,
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
            IData(idata_req) => {
                match idata_req {
                    IDataRequest::Put(data) => {
                        if matches!(requester, PublicId::Node(_)) {
                            // Since the requester is a node, this message was sent by the data handlers to us
                            // as a single data handler, implying that we're a data handler chosen to store the
                            // chunk.
                            self.idata_holder
                                .store_idata(&data, requester, src, message_id)
                        } else {
                            self.handle_idata_request(|idata_handler| {
                                idata_handler.handle_put_idata_req(requester, data, message_id)
                            })
                        }
                    }
                    IDataRequest::Get(address) => {
                        if matches!(requester, PublicId::Node(_)) {
                            // The message was sent by the data handlers to us as the one who is supposed to store
                            // the chunk. See the sent Get request below.
                            self.idata_holder
                                .get_idata(address, requester, src, message_id)
                        } else {
                            self.handle_idata_request(|idata_handler| {
                                idata_handler.handle_get_idata_req(requester, address, message_id)
                            })
                        }
                    }
                    IDataRequest::DeleteUnpub(address) => {
                        if &src == address.name() {
                            // Since the src is the chunk's name, this message was sent by the data handlers to us
                            // as a single data handler, implying that we're a data handler where the chunk is
                            // stored.
                            let client = self.client_id(&message_id)?.clone();
                            self.idata_holder
                                .delete_unpub_idata(address, &client, message_id)
                        } else {
                            // We're acting as data handler, received request from client handlers
                            self.handle_idata_request(|idata_handler| {
                                idata_handler
                                    .handle_delete_unpub_idata_req(requester, address, message_id)
                            })
                        }
                    }
                }
            }
            MData(mdata_req) => self.mdata_handler.as_mut().map_or_else(
                || {
                    trace!("Not applicable to Adults");
                    None
                },
                |mdata_handler| mdata_handler.handle_request(requester, mdata_req, message_id),
            ),
            AData(adata_req) => self.adata_handler.as_mut().map_or_else(
                || {
                    trace!("Not applicable to Adults");
                    None
                },
                |adata_handler| adata_handler.handle_request(requester, adata_req, message_id),
            ),
            Coins(_) | LoginPacket(_) | Client(_) => {
                error!(
                    "{}: Should not receive {:?} as a data handler.",
                    self, request
                );
                None
            }
        }
    }

    fn handle_idata_request<F>(&mut self, operation: F) -> Option<Action>
    where
        F: FnOnce(&mut IDataHandler) -> Option<Action>,
    {
        self.idata_handler.as_mut().map_or_else(
            || {
                trace!("Not applicable to Adults");
                None
            },
            |idata_handler| operation(idata_handler),
        )
    }

    fn client_id(&self, message_id: &MessageId) -> Option<&PublicId> {
        self.idata_handler.as_ref().map_or_else(
            || {
                trace!("Not applicable for adults");
                None
            },
            |idata_handler| idata_handler.idata_op(message_id).map(IDataOp::client),
        )
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
            Mutation(result) => self.handle_idata_request(|idata_handler| {
                idata_handler.handle_mutation_resp(src, result, message_id)
            }),
            GetIData(result) => self.handle_idata_request(|idata_handler| {
                idata_handler.handle_get_idata_resp(src, result, message_id)
            }),
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
}

impl Display for DataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
