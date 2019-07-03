// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{action::Action, Error, Result};
use log::{error, warn};
use safe_nd::{MessageId, Request, Response, XorName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub(super) enum RpcState {
    // Request sent to chunk holder.
    Sent,
    // Response received from chunk holder.
    Actioned,
    // Holder has left the section without responding.
    HolderGone,
    // Holder hasn't responded within the required time.
    TimedOut,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub(super) struct IDataOp {
    client: XorName,
    request: Request,
    rpc_states: BTreeMap<XorName, RpcState>,
}

#[allow(unused)]
impl IDataOp {
    pub(super) fn new(client: XorName, request: Request, holders: Vec<XorName>) -> Result<Self> {
        use Request::*;
        match request {
            PutIData(_) | GetIData(_) | DeleteUnpubIData(_) => (),
            _ => {
                error!("Logic error. Only add Immutable Data requests here.");
                return Err(Error::Logic);
            }
        }

        Ok(Self {
            client,
            request,
            rpc_states: holders
                .into_iter()
                .map(|holder| (holder, RpcState::Sent))
                .collect(),
        })
    }

    pub(super) fn client(&self) -> &XorName {
        &self.client
    }

    pub(super) fn request(&self) -> &Request {
        &self.request
    }

    pub(super) fn rpc_states(&self) -> &BTreeMap<XorName, RpcState> {
        &self.rpc_states
    }

    pub(super) fn is_any_actioned(&self) -> bool {
        self.rpc_states
            .values()
            .any(|rpc_state| rpc_state == &RpcState::Actioned)
    }

    pub(super) fn handle_response(
        &mut self,
        sender: XorName,
        response: Response,
        own_id: String,
        message_id: MessageId,
    ) -> Option<Action> {
        let is_already_actioned = self.is_any_actioned();
        match response {
            Response::GetIData(ref result) => {
                let address = if let Request::GetIData(address) = self.request {
                    address
                } else {
                    warn!(
                        "{}: Expected Response::GetIData to correspond to \
                         Request::GetIData from {}:",
                        own_id, sender,
                    );
                    // TODO - Instead of returning None here, take action by treating the vault as
                    //        failing.
                    return None;
                };

                self.rpc_states
                    .get_mut(&sender)
                    .or_else(|| {
                        warn!(
                            "{}: Received response from sender {} that we didn't expect.",
                            own_id, sender
                        );
                        None
                    })
                    .map(|rpc_state| *rpc_state = RpcState::Actioned)
                    .and_then(|()| {
                        if is_already_actioned {
                            None
                        } else {
                            Some(Action::RespondToSrcElders {
                                sender: *address.name(),
                                client_name: *self.client(),
                                response,
                                message_id,
                            })
                        }
                    })
            }
            _ => {
                error!("{}: Logic error", own_id);
                None
            }
        }
    }
}
