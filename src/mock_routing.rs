// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use GROUP_SIZE;
use routing::{AccountInfo, Authority, Cache, ClientError, EntryAction, Event, EventStream, FullId,
              ImmutableData, InterfaceError, MessageId, MutableData, PermissionSet, PublicId,
              Request, Response, RoutingError, RoutingTable, User, Value, XorName};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::mpsc::{RecvError, TryRecvError};

/// Mock routing node for unit testing.
pub struct Node {
    id: PublicId,
    routing_table: RoutingTable<XorName>,
    pub sent_requests: HashMap<MessageId, RequestWrapper>,
    pub sent_responses: HashMap<MessageId, ResponseWrapper>,
}

macro_rules! impl_request {
    ($method:ident, $message:ident { $($pname:ident : $ptype:ty),* }) => {
        #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
        pub fn $method(&mut self,
                       src: Authority<XorName>,
                       dst: Authority<XorName>,
                       $($pname : $ptype),*)
                       -> Result<(), InterfaceError> {
            self.send_request(src,
                              dst,
                              Request::$message {
                                $($pname : $pname),*,
                              })
        }
    };

    ($method:ident, $message:ident { $($pname:ident : $ptype:ty),*, }) => {
        impl_request!($method, $message { $($pname : $ptype),* });
    };
}

macro_rules! impl_response {
    ($method:ident, $message:ident, $payload:ty) => {
        pub fn $method(&mut self,
                       src: Authority<XorName>,
                       dst: Authority<XorName>,
                       res: Result<$payload, ClientError>,
                       msg_id: MessageId)
                       -> Result<(), InterfaceError> {
            self.send_response(src,
                               dst,
                               Response::$message {
                                 res: res,
                                 msg_id: msg_id,
                               })
        }
    };

    ($method:ident, $message:ident) => {
        impl_response!($method, $message, ());
    }
}

impl Node {
    pub fn builder() -> NodeBuilder {
        NodeBuilder
    }

    pub fn new() -> Self {
        unwrap!(Self::builder().create())
    }

    pub fn id(&self) -> Result<PublicId, InterfaceError> {
        Ok(self.id)
    }

    pub fn close_group(&self, name: XorName, count: usize) -> Option<Vec<XorName>> {
        self.routing_table.closest_names(&name, count).map(
            |names| {
                names.into_iter().cloned().collect()
            },
        )
    }

    pub fn routing_table(&self) -> Result<&RoutingTable<XorName>, RoutingError> {
        Ok(&self.routing_table)
    }

    // mock-only method.
    pub fn add_to_routing_table(&mut self, name: XorName) {
        unwrap!(self.routing_table.add(name));
    }

    impl_request!(
        send_get_idata_request,
        GetIData {
            name: XorName,
            msg_id: MessageId,
        }
    );

    impl_request!(
        send_put_idata_request,
        PutIData {
            data: ImmutableData,
            msg_id: MessageId,
        }
    );

    impl_request!(
        send_get_mdata_request,
        GetMData {
            name: XorName,
            tag: u64,
            msg_id: MessageId,
        }
    );

    impl_request!(
        send_put_mdata_request,
        PutMData {
            data: MutableData,
            msg_id: MessageId,
            requester: sign::PublicKey,
        }
    );

    impl_request!(send_mutate_mdata_entries_request,
                  MutateMDataEntries {
                      name: XorName,
                      tag: u64,
                      actions: BTreeMap<Vec<u8>, EntryAction>,
                      msg_id: MessageId,
                      requester: sign::PublicKey,
                  });

    impl_request!(send_get_mdata_shell_request,
                  GetMDataShell {
                      name: XorName,
                      tag: u64,
                      msg_id: MessageId,
                  });

    impl_request!(send_get_mdata_value_request,
                  GetMDataValue {
                      name: XorName,
                      tag: u64,
                      key: Vec<u8>,
                      msg_id: MessageId
                  });

    impl_request!(send_set_mdata_user_permissions_request,
                  SetMDataUserPermissions {
                      name: XorName,
                      tag: u64,
                      user: User,
                      permissions: PermissionSet,
                      version: u64,
                      msg_id: MessageId,
                      requester: sign::PublicKey,
                  });

    impl_request!(send_del_mdata_user_permissions_request,
                  DelMDataUserPermissions {
                      name: XorName,
                      tag: u64,
                      user: User,
                      version: u64,
                      msg_id: MessageId,
                      requester: sign::PublicKey,
                  });

    impl_request!(send_change_mdata_owner_request,
                  ChangeMDataOwner {
                      name: XorName,
                      tag: u64,
                      new_owners: BTreeSet<sign::PublicKey>,
                      version: u64,
                      msg_id: MessageId,
                  });

    pub fn send_refresh_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        content: Vec<u8>,
        msg_id: MessageId,
    ) -> Result<(), InterfaceError> {
        self.send_request(src, dst, Request::Refresh(content, msg_id))
    }

    impl_response!(send_get_account_info_response, GetAccountInfo, AccountInfo);
    impl_response!(send_get_idata_response, GetIData, ImmutableData);
    impl_response!(send_put_idata_response, PutIData);
    impl_response!(send_put_mdata_response, PutMData);
    impl_response!(send_get_mdata_response, GetMData, MutableData);
    impl_response!(send_get_mdata_shell_response, GetMDataShell, MutableData);
    impl_response!(send_get_mdata_version_response, GetMDataVersion, u64);
    impl_response!(send_list_mdata_entries_response,
                   ListMDataEntries, BTreeMap<Vec<u8>, Value>);
    impl_response!(send_list_mdata_keys_response,
                   ListMDataKeys, BTreeSet<Vec<u8>>);
    impl_response!(send_list_mdata_values_response,
                   ListMDataValues, Vec<Value>);
    impl_response!(send_get_mdata_value_response,
                   GetMDataValue, Value);
    impl_response!(send_mutate_mdata_entries_response, MutateMDataEntries);
    impl_response!(send_list_mdata_permissions_response,
                   ListMDataPermissions, BTreeMap<User, PermissionSet>);
    impl_response!(send_list_mdata_user_permissions_response,
                   ListMDataUserPermissions, PermissionSet);
    impl_response!(send_set_mdata_user_permissions_response,
                   SetMDataUserPermissions);
    impl_response!(send_del_mdata_user_permissions_response,
                   DelMDataUserPermissions);
    impl_response!(send_change_mdata_owner_response, ChangeMDataOwner);
    impl_response!(send_list_auth_keys_and_version_response,
                   ListAuthKeysAndVersion, (BTreeSet<sign::PublicKey>, u64));
    impl_response!(send_ins_auth_key_response, InsAuthKey);
    impl_response!(send_del_auth_key_response, DelAuthKey);

    fn send_request(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        request: Request,
    ) -> Result<(), InterfaceError> {
        let prev = self.sent_requests.insert(
            request_id(&request),
            RequestWrapper {
                src: src,
                dst: dst,
                request: request,
            },
        );
        assert!(prev.is_none());
        Ok(())
    }

    fn send_response(
        &mut self,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        response: Response,
    ) -> Result<(), InterfaceError> {
        let prev = self.sent_responses.insert(
            response_id(&response),
            ResponseWrapper {
                src: src,
                dst: dst,
                response: response,
            },
        );
        assert!(prev.is_none());
        Ok(())
    }
}

impl EventStream for Node {
    type Item = Event;

    fn next_ev(&mut self) -> Result<Self::Item, RecvError> {
        Err(RecvError)
    }

    fn try_next_ev(&mut self) -> Result<Self::Item, TryRecvError> {
        Err(TryRecvError::Empty)
    }

    fn poll(&mut self) -> bool {
        false
    }
}

pub struct NodeBuilder;

impl NodeBuilder {
    pub fn first(self, _first: bool) -> Self {
        self
    }

    pub fn deny_other_local_nodes(self) -> Self {
        self
    }

    pub fn cache(self, _cache: Box<Cache>) -> Self {
        self
    }

    pub fn create(self) -> Result<Node, RoutingError> {
        let id = *FullId::new().public_id();

        Ok(Node {
            id: id,
            routing_table: RoutingTable::new(*id.name(), GROUP_SIZE),
            sent_requests: Default::default(),
            sent_responses: Default::default(),
        })
    }
}

#[derive(Debug)]
pub struct ResponseWrapper {
    pub src: Authority<XorName>,
    pub dst: Authority<XorName>,
    pub response: Response,
}

#[derive(Debug)]
pub struct RequestWrapper {
    pub src: Authority<XorName>,
    pub dst: Authority<XorName>,
    pub request: Request,
}

// TODO: consider adding these to impl Request / impl Response in routing.

fn request_id(request: &Request) -> MessageId {
    match *request {
        Request::Refresh(_, msg_id) |
        Request::GetAccountInfo(msg_id) |
        Request::PutIData { msg_id, .. } |
        Request::GetIData { msg_id, .. } |
        Request::PutMData { msg_id, .. } |
        Request::GetMData { msg_id, .. } |
        Request::GetMDataShell { msg_id, .. } |
        Request::GetMDataVersion { msg_id, .. } |
        Request::ListMDataEntries { msg_id, .. } |
        Request::ListMDataKeys { msg_id, .. } |
        Request::ListMDataValues { msg_id, .. } |
        Request::GetMDataValue { msg_id, .. } |
        Request::MutateMDataEntries { msg_id, .. } |
        Request::ListMDataPermissions { msg_id, .. } |
        Request::ListMDataUserPermissions { msg_id, .. } |
        Request::SetMDataUserPermissions { msg_id, .. } |
        Request::DelMDataUserPermissions { msg_id, .. } |
        Request::ChangeMDataOwner { msg_id, .. } |
        Request::ListAuthKeysAndVersion(msg_id) |
        Request::InsAuthKey { msg_id, .. } |
        Request::DelAuthKey { msg_id, .. } => msg_id,
    }
}

fn response_id(response: &Response) -> MessageId {
    match *response {
        Response::GetAccountInfo { msg_id, .. } |
        Response::PutIData { msg_id, .. } |
        Response::GetIData { msg_id, .. } |
        Response::PutMData { msg_id, .. } |
        Response::GetMData { msg_id, .. } |
        Response::GetMDataShell { msg_id, .. } |
        Response::GetMDataVersion { msg_id, .. } |
        Response::ListMDataEntries { msg_id, .. } |
        Response::ListMDataKeys { msg_id, .. } |
        Response::ListMDataValues { msg_id, .. } |
        Response::GetMDataValue { msg_id, .. } |
        Response::MutateMDataEntries { msg_id, .. } |
        Response::ListMDataPermissions { msg_id, .. } |
        Response::ListMDataUserPermissions { msg_id, .. } |
        Response::SetMDataUserPermissions { msg_id, .. } |
        Response::DelMDataUserPermissions { msg_id, .. } |
        Response::ChangeMDataOwner { msg_id, .. } |
        Response::ListAuthKeysAndVersion { msg_id, .. } |
        Response::InsAuthKey { msg_id, .. } |
        Response::DelAuthKey { msg_id, .. } => msg_id,
    }
}
