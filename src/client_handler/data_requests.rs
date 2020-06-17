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
    Error as NdError, IData, IDataAddress, IDataKind, IDataRequest, MData, MDataRequest, MessageId,
    NodePublicId, Request, Response, SData, SDataAddress, SDataRequest,
};
use std::fmt::{self, Display, Formatter};

#[derive(Clone)]
pub(crate) struct Evaluation {
    pub immutable: Immutable,
    pub mutable: Mutable,
    pub sequence: Sequence,
}

impl Evaluation {
    pub fn new(id: NodePublicId) -> Self {
        Self {
            immutable: Immutable::new(id.clone()),
            mutable: Mutable::new(id.clone()),
            sequence: Sequence::new(id),
        }
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct Sequence {
    id: NodePublicId,
}

impl Sequence {
    pub fn new(id: NodePublicId) -> Self {
        Self { id }
    }

    // on client request
    pub fn process_client_request(
        &mut self,
        client: &ClientInfo,
        request: SDataRequest,
        message_id: MessageId,
    ) -> Option<Action> {
        use SDataRequest::*;
        match request {
            Store(chunk) => self.initiate_creation(client, chunk, message_id),
            Get(_)
            | GetRange { .. }
            | GetLastEntry(_)
            | GetOwner { .. }
            | GetPermissions { .. }
            | GetUserPermissions { .. } => self.get(client, request, message_id),
            Delete(address) => self.initiate_deletion(client, address, message_id),
            MutatePubPermissions { .. }
            | MutatePrivPermissions { .. }
            | MutateOwner { .. }
            | Mutate(..) => self.initiate_mutation(client, request, message_id),
        }
    }

    // client query
    fn get(
        &mut self,
        client: &ClientInfo,
        request: SDataRequest,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::ForwardClientRequest(Rpc::Request {
            requester: client.public_id.clone(),
            request: Request::SData(request),
            message_id,
        }))
    }

    // on client request
    fn initiate_creation(
        &mut self,
        client: &ClientInfo,
        chunk: SData,
        message_id: MessageId,
    ) -> Option<Action> {
        let owner = utils::owner(&client.public_id)?;
        // TODO - Should we replace this with a sequence.check_permission call in data_handler.
        // That would be more consistent, but on the other hand a check here stops spam earlier.
        if chunk.check_is_last_owner(*owner.public_key()).is_err() {
            trace!(
                "{}: {} attempted to store Sequence with invalid owners.",
                self,
                client.public_id
            );
            return Some(Action::RespondToClient {
                message_id,
                response: Response::Mutation(Err(NdError::InvalidOwners)),
            });
        }

        let request = Request::SData(SDataRequest::Store(chunk));
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }

    // on client request
    fn initiate_deletion(
        &mut self,
        client: &ClientInfo,
        address: SDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        if address.is_pub() {
            return Some(Action::RespondToClient {
                message_id,
                response: Response::Mutation(Err(NdError::InvalidOperation)),
            });
        }

        Some(Action::VoteFor(ConsensusAction::Forward {
            request: Request::SData(SDataRequest::Delete(address)),
            client_public_id: client.public_id.clone(),
            message_id,
        }))
    }

    // on client request
    fn initiate_mutation(
        &mut self,
        client: &ClientInfo,
        request: SDataRequest,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request: Request::SData(request),
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }
}

impl Display for Sequence {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct Immutable {
    id: NodePublicId,
}

impl Immutable {
    pub fn new(id: NodePublicId) -> Self {
        Self { id }
    }

    // on client request
    pub fn process_client_request(
        &mut self,
        client: &ClientInfo,
        request: IDataRequest,
        message_id: MessageId,
    ) -> Option<Action> {
        use IDataRequest::*;
        match request {
            Put(chunk) => self.initiate_creation(client, chunk, message_id),
            Get(address) => {
                // TODO: We don't check for the existence of a valid signature for published data,
                // since it's free for anyone to get.  However, as a means of spam prevention, we
                // could change this so that signatures are required, and the signatures would need
                // to match a pattern which becomes increasingly difficult as the client's
                // behaviour is deemed to become more "spammy". (e.g. the get requests include a
                // `seed: [u8; 32]`, and the client needs to form a sig matching a required pattern
                // by brute-force attempts with varying seeds)
                self.get(client, address, message_id)
            }
            DeleteUnpub(address) => self.initiate_deletion(client, address, message_id),
        }
    }

    // client query
    fn get(
        &mut self,
        client: &ClientInfo,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::ForwardClientRequest(Rpc::Request {
            requester: client.public_id.clone(),
            request: Request::IData(IDataRequest::Get(address)),
            message_id,
        }))
    }

    // on client request
    fn initiate_creation(
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

        let request = Request::IData(IDataRequest::Put(chunk));
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }

    // on client request
    fn initiate_deletion(
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
            request: Request::IData(IDataRequest::DeleteUnpub(address)),
            client_public_id: client.public_id.clone(),
            message_id,
        }))
    }
}

impl Display for Immutable {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct Mutable {
    id: NodePublicId,
}

impl Mutable {
    pub fn new(id: NodePublicId) -> Self {
        Self { id }
    }

    // on client request
    pub fn process_client_request(
        &mut self,
        client: &ClientInfo,
        request: MDataRequest,
        message_id: MessageId,
    ) -> Option<Action> {
        use MDataRequest::*;
        match request {
            Put(chunk) => self.initiate_creation(client, chunk, message_id),
            MutateEntries { .. } | SetUserPermissions { .. } | DelUserPermissions { .. } => {
                self.initiate_mutation(request, client, message_id)
            }
            Delete(..) => self.initiate_deletion(request, client, message_id),
            Get(..)
            | GetVersion(..)
            | GetShell(..)
            | GetValue { .. }
            | ListPermissions(..)
            | ListUserPermissions { .. }
            | ListEntries(..)
            | ListKeys(..)
            | ListValues(..) => self.get(request, client, message_id),
        }
    }

    // client query
    fn get(
        &mut self,
        request: MDataRequest,
        client: &ClientInfo,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::ForwardClientRequest(Rpc::Request {
            requester: client.public_id.clone(),
            request: Request::MData(request),
            message_id,
        }))
    }

    // on client request
    fn initiate_mutation(
        &mut self,
        request: MDataRequest,
        client: &ClientInfo,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request: Request::MData(request),
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }

    // on client request
    fn initiate_deletion(
        &mut self,
        request: MDataRequest,
        client: &ClientInfo,
        message_id: MessageId,
    ) -> Option<Action> {
        Some(Action::VoteFor(ConsensusAction::Forward {
            request: Request::MData(request),
            client_public_id: client.public_id.clone(),
            message_id,
        }))
    }

    // on client request
    fn initiate_creation(
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

        let request = Request::MData(MDataRequest::Put(chunk));

        Some(Action::VoteFor(ConsensusAction::PayAndForward {
            request,
            client_public_id: client.public_id.clone(),
            message_id,
            cost: COST_OF_PUT,
        }))
    }
}

impl Display for Mutable {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
