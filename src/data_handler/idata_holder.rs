// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action, chunk_store::ImmutableChunkStore, rpc::Rpc, utils, vault::Init, Config, Result,
};
use log::{error, info};

use safe_nd::{Error as NdError, IData, IDataAddress, MessageId, NodePublicId, PublicId, Response};

use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub(super) struct IDataHolder {
    id: NodePublicId,
    chunks: ImmutableChunkStore,
}

impl IDataHolder {
    pub(super) fn new(
        id: NodePublicId,
        config: &Config,
        total_used_space: &Rc<Cell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        let root_dir = config.root_dir()?;
        let max_capacity = config.max_capacity();
        let chunks = ImmutableChunkStore::new(
            &root_dir,
            max_capacity,
            Rc::clone(total_used_space),
            init_mode,
        )?;
        Ok(Self { id, chunks })
    }

    pub(super) fn store_idata(
        &mut self,
        data: IData,
        requester: PublicId,
        message_id: MessageId,
    ) -> Option<Action> {
        let result = if self.chunks.has(data.address()) {
            info!(
                "{}: Immutable chunk already exists, not storing: {:?}",
                self,
                data.address()
            );
            Ok(())
        } else {
            self.chunks
                .put(&data)
                .map_err(|error| error.to_string().into())
        };
        Some(Action::RespondToOurDataHandlers {
            sender: *self.id.name(),
            rpc: Rpc::Response {
                requester,
                response: Response::Mutation(result),
                message_id,
            },
        })
    }

    pub(super) fn get_idata(
        &self,
        address: IDataAddress,
        client: PublicId,
        message_id: MessageId,
    ) -> Option<Action> {
        let client_pk = utils::own_key(&client)?;
        let result = self
            .chunks
            .get(&address)
            .map_err(|error| error.to_string().into())
            .and_then(|idata| match idata {
                IData::Unpub(ref data) => {
                    if data.owner() != client_pk {
                        Err(NdError::AccessDenied)
                    } else {
                        Ok(idata)
                    }
                }
                _ => Ok(idata),
            });
        Some(Action::RespondToOurDataHandlers {
            sender: *self.id.name(),
            rpc: Rpc::Response {
                requester: client.clone(),
                response: Response::GetIData(result),
                message_id,
            },
        })
    }

    pub(super) fn delete_unpub_idata(
        &mut self,
        address: IDataAddress,
        client: PublicId,
        message_id: MessageId,
    ) -> Option<Action> {
        let client_pk = utils::own_key(&client)?;

        // First we need to read the chunk to verify the permissions
        let result = self
            .chunks
            .get(&address)
            .map_err(|error| error.to_string().into())
            .and_then(|data| match data {
                IData::Unpub(ref data) => {
                    if data.owner() != client_pk {
                        Err(NdError::AccessDenied)
                    } else {
                        Ok(())
                    }
                }
                _ => {
                    error!(
                        "{}: Invalid DeleteUnpub(IData::Pub) encountered: {:?}",
                        self, message_id
                    );
                    Err(NdError::InvalidOperation)
                }
            })
            .and_then(|_| {
                self.chunks
                    .delete(&address)
                    .map_err(|error| error.to_string().into())
            });

        Some(Action::RespondToOurDataHandlers {
            sender: *self.id.name(),
            rpc: Rpc::Response {
                requester: client.clone(),
                response: Response::Mutation(result),
                message_id,
            },
        })
    }
}

impl Display for IDataHolder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
