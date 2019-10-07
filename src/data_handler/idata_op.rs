// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{action::Action, rpc::Rpc, Error, Result};
use log::{error, warn};
use safe_nd::{
    Error as NdError, IData, IDataAddress, MessageId, PublicId, Request, Response,
    Result as NdResult, XorName,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub(crate) enum RpcState {
    // Request sent to chunk holder.
    Sent,
    // Response received from chunk holder. Don't store the whole response due to space concerns,
    // instead only store if there are any errors.
    Actioned(Option<NdError>),
    // Holder has left the section without responding.
    HolderGone,
    // Holder hasn't responded within the required time.
    TimedOut,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub(crate) enum OpType {
    Put,
    Get,
    Delete,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Debug)]
pub(crate) struct IDataOp {
    client: PublicId,
    request: Request,
    pub rpc_states: BTreeMap<XorName, RpcState>,
}

impl IDataOp {
    pub fn new(client: PublicId, request: Request, holders: BTreeSet<XorName>) -> Result<Self> {
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

    pub fn client(&self) -> &PublicId {
        &self.client
    }

    pub fn request(&self) -> &Request {
        &self.request
    }

    pub fn is_any_actioned(&self) -> bool {
        self.rpc_states.values().any(|rpc_state| match rpc_state {
            RpcState::Actioned(_) => true,
            _ => false,
        })
    }

    pub fn op_type(&self) -> OpType {
        match self.request {
            Request::PutIData(_) => OpType::Put,
            Request::GetIData(_) => OpType::Get,
            Request::DeleteUnpubIData(_) => OpType::Delete,
            _ => unreachable!(),
        }
    }

    /// Returns true if no `rpc_states` are still `RpcState::Sent`.
    pub fn concluded(&self) -> bool {
        !self
            .rpc_states
            .values()
            .any(|state| *state == RpcState::Sent)
    }

    pub fn get_any_errors(&self) -> BTreeMap<XorName, NdError> {
        self.rpc_states
            .iter()
            .filter_map(|(sender, state)| match state {
                RpcState::Actioned(Some(err)) => Some((*sender, err.clone())),
                _ => None,
            })
            .collect()
    }

    pub fn handle_mutation_resp(
        &mut self,
        sender: XorName,
        result: NdResult<()>,
        own_id: String,
        message_id: MessageId,
    ) -> Option<IDataAddress> {
        match &self.request {
            &Request::PutIData(_) | &Request::DeleteUnpubIData(_) => (),
            other => {
                warn!(
                    "{}: Expected PutIData or DeleteUnpubIData for {:?}, but found {:?}",
                    own_id, message_id, other
                );
                return None;
            }
        };
        self.set_to_actioned(&sender, result.err(), own_id)?;

        match self.request {
            Request::PutIData(ref data) => Some(*data.address()),
            Request::DeleteUnpubIData(address) => Some(address),
            _ => None, // unreachable - we checked above
        }
    }

    pub fn handle_get_idata_resp(
        &mut self,
        sender: XorName,
        result: NdResult<IData>,
        own_id: String,
        message_id: MessageId,
    ) -> Option<Action> {
        let is_already_actioned = self.is_any_actioned();
        let address = if let Request::GetIData(address) = self.request {
            address
        } else {
            warn!(
                "{}: Expected Response::GetIData to correspond to Request::GetIData from {}:",
                own_id, sender,
            );
            // TODO - Instead of returning None here, take action by treating the vault as
            //        failing.
            return None;
        };

        let response = Response::GetIData(result.clone());
        self.set_to_actioned(&sender, result.err(), own_id)?;
        if is_already_actioned {
            None
        } else {
            Some(Action::RespondToClientHandlers {
                sender: *address.name(),
                rpc: Rpc::Response {
                    requester: self.client().clone(),
                    response,
                    message_id,
                },
            })
        }
    }

    fn set_to_actioned(
        &mut self,
        sender: &XorName,
        got_error_response: Option<NdError>,
        own_id: String,
    ) -> Option<()> {
        self.rpc_states
            .get_mut(sender)
            .or_else(|| {
                warn!(
                    "{}: Received response from {} that we didn't expect.",
                    own_id, sender
                );
                None
            })
            .map(|rpc_state| *rpc_state = RpcState::Actioned(got_error_response))
    }
}
