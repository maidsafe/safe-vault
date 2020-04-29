// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{auth::ClientInfo, COST_OF_PUT};
use crate::{
    action::{Action, ConsensusAction},
    rpc::Rpc,
    utils,
};
use log::trace;
use safe_nd::{
    AData, ADataAddress, Error as NdError, IData, IDataAddress, IDataKind, MData, MessageId,
    NodePublicId, Request, Response,
};
use std::fmt::{self, Display, Formatter};

#[derive(Clone)]
pub(crate) struct ElderData {
    pub idata: ElderIData,
    pub mdata: ElderMData,
    pub adata: ElderAData,
}

impl ElderData {
    pub fn new(id: NodePublicId) -> Self {
        Self {
            idata: ElderIData::new(id.clone()),
            mdata: ElderMData::new(id.clone()),
            adata: ElderAData::new(id),
        }
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ElderAData {
    id: NodePublicId,
}

impl ElderAData {
    pub fn new(id: NodePublicId) -> Self {
        Self { id }
    }

    // client query
    pub fn get_adata(
        &mut self,
        client: &ClientInfo,
        request: Request,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::ForwardClientRequest(Rpc::Request {
            requester: client.public_id.clone(),
            request,
            message_id,
        }))
    }

    // on client request
    pub fn initiate_adata_creation(
        &mut self,
        client: &ClientInfo,
        chunk: AData,
        message_id: MessageId,
    ) -> Option<Action> {
        let owner = utils::owner(&client.public_id)?;
        // TODO - Should we replace this with a adata.check_permission call in data_handler.
        // That would be more consistent, but on the other hand a check here stops spam earlier.
        if chunk.check_is_last_owner(*owner.public_key()).is_err() {
            trace!(
                "{}: {} attempted Put AppendOnlyData with invalid owners.",
                self,
                client.public_id
            );
            return Some(Action::RespondToClient {
                message_id,
                response: Response::Mutation(Err(NdError::InvalidOwners)),
            });
        }

        let request = Request::PutAData(chunk);
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }

    // on client request
    pub fn initiate_adata_deletion(
        &mut self,
        client: &ClientInfo,
        address: ADataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        if address.is_pub() {
            return Some(Action::RespondToClient {
                message_id,
                response: Response::Mutation(Err(NdError::InvalidOperation)),
            });
        }

        Some(Action::VoteFor(ConsensusAction::Forward {
            request: Request::DeleteAData(address),
            client_public_id: client.public_id.clone(),
            message_id,
        }))
    }

    // on client request
    pub fn initiate_adata_mutation(
        &mut self,
        client: &ClientInfo,
        request: Request,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }
}

impl Display for ElderAData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ElderIData {
    id: NodePublicId,
}

impl ElderIData {
    pub fn new(id: NodePublicId) -> Self {
        Self { id }
    }

    // client query
    pub fn get_idata(
        &mut self,
        client: &ClientInfo,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::ForwardClientRequest(Rpc::Request {
            requester: client.public_id.clone(),
            request: Request::GetIData(address),
            message_id,
        }))
    }

    // on client request
    pub fn initiate_idata_creation(
        &mut self,
        client: &ClientInfo,
        chunk: IData,
        message_id: MessageId,
    ) -> Option<Action> {
        let owner = utils::owner(&client.public_id)?;

        // Assert that if the request was for UnpubIData, that the owner's public key has
        // been added to the chunk, to avoid Apps putting chunks which can't be retrieved
        // by their Client owners.
        if let IData::Unpub(ref unpub_chunk) = &chunk {
            if unpub_chunk.owner() != owner.public_key() {
                trace!(
                    "{}: {} attempted Put UnpubIData with invalid owners field.",
                    self,
                    client.public_id
                );
                return Some(Action::RespondToClient {
                    message_id,
                    response: Response::Mutation(Err(NdError::InvalidOwners)),
                });
            }
        }

        let request = Request::PutIData(chunk);
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }

    // on client request
    pub fn initiate_unpub_idata_deletion(
        &mut self,
        client: &ClientInfo,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        if address.kind() == IDataKind::Pub {
            return Some(Action::RespondToClient {
                message_id,
                response: Response::Mutation(Err(NdError::InvalidOperation)),
            });
        }
        Some(Action::VoteFor(ConsensusAction::Forward {
            request: Request::DeleteUnpubIData(address),
            client_public_id: client.public_id.clone(),
            message_id,
        }))
    }
}

impl Display for ElderIData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ElderMData {
    id: NodePublicId,
}

impl ElderMData {
    pub fn new(id: NodePublicId) -> Self {
        Self { id }
    }

    // client query
    pub fn get_mdata(
        &mut self,
        request: Request,
        client: &ClientInfo,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::ForwardClientRequest(Rpc::Request {
            requester: client.public_id.clone(),
            request,
            message_id,
        }))
    }

    // on client request
    pub fn initiate_mdata_mutation(
        &mut self,
        request: Request,
        client: &ClientInfo,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }

    // on client request
    pub fn initiate_mdata_deletion(
        &mut self,
        request: Request,
        client: &ClientInfo,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::Forward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
        }))
    }

    // on client request
    pub fn initiate_mdata_creation(
        &mut self,
        client: &ClientInfo,
        chunk: MData,
        message_id: MessageId,
    ) -> Option<Action> {
        let owner = utils::owner(&client.public_id)?;

        // Assert that the owner's public key has been added to the chunk, to avoid Apps
        // putting chunks which can't be retrieved by their Client owners.
        if chunk.owner() != *owner.public_key() {
            trace!(
                "{}: {} attempted PutMData with invalid owners field.",
                self,
                client.public_id
            );
            return Some(Action::RespondToClient {
                message_id,
                response: Response::Mutation(Err(NdError::InvalidOwners)),
            });
        }

        let request = Request::PutMData(chunk);

        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }
}

impl Display for ElderMData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
