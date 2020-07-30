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

use routing::SrcLocation;
use safe_nd::{
    Error as NdError, IData, IDataAddress, MessageId, NodePublicId, PublicId, Request, Response,
};
use std::{
    cell::Cell,
    collections::BTreeSet,
    fmt::{self, Display, Formatter},
    rc::Rc,
};
use threshold_crypto::Signature;
use xor_name::XorName;

pub(crate) struct IDataHolder {
    id: NodePublicId,
    chunks: ImmutableChunkStore,
}

impl IDataHolder {
    pub(crate) fn new(
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

    pub(crate) fn store_idata(
        &mut self,
        sender: SrcLocation,
        data: &IData,
        requester: PublicId,
        message_id: MessageId,
        accumulated_signature: Option<Signature>,
        request: Request,
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
        let refund = utils::get_refund_for_put(&result);
        info!(
            "{}: Sender {:?} asked us to store Immutable data at: {:?}. Result: {:?}",
            self,
            &sender,
            data.address(),
            &result
        );
        match sender {
            SrcLocation::Node(_) => Some(Action::RespondToOurDataHandlers {
                rpc: Rpc::DuplicationComplete {
                    response: Response::Mutation(result),
                    message_id,
                    proof: Some((*data.address(), accumulated_signature?)),
                },
            }),
            SrcLocation::Section(_) => Some(Action::RespondToOurDataHandlers {
                rpc: Rpc::Response {
                    requester,
                    response: Response::Mutation(result),
                    message_id,
                    refund,
                    proof: Some((request, accumulated_signature?)),
                },
            }),
        }
    }

    pub(crate) fn get_idata(
        &self,
        sender: SrcLocation,
        address: IDataAddress,
        requester: PublicId,
        message_id: MessageId,
        request: Request,
        accumulated_signature: Option<Signature>,
    ) -> Option<Action> {
        let result = self
            .chunks
            .get(&address)
            .map_err(|error| error.to_string().into());

        match sender {
            SrcLocation::Node(xorname) => {
                let mut targets: BTreeSet<XorName> = Default::default();
                let _ = targets.insert(XorName(xorname.0));
                Some(Action::SendToPeers {
                    targets,
                    rpc: Rpc::Response {
                        requester,
                        response: Response::GetIData(result),
                        message_id,
                        refund: None,
                        proof: Some((request, accumulated_signature?)),
                    },
                })
            }
            SrcLocation::Section(_) => Some(Action::RespondToOurDataHandlers {
                rpc: Rpc::Response {
                    requester,
                    response: Response::GetIData(result),
                    message_id,
                    refund: None,
                    proof: Some((request, accumulated_signature?)),
                },
            }),
        }
    }

    pub(crate) fn delete_unpub_idata(
        &mut self,
        address: IDataAddress,
        requester: PublicId,
        message_id: MessageId,
        request: Request,
        accumulated_signature: Option<Signature>,
    ) -> Option<Action> {
        let result = if self.chunks.has(&address) {
            self.chunks
                .get(&address)
                .map_err(|error| error.to_string().into())
                .and_then(|data| match data {
                    IData::Unpub(ref _data) => Ok(()),
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
                })
        } else {
            info!("{}: Immutable chunk doesn't exist: {:?}", self, address);
            Ok(())
        };

        Some(Action::RespondToOurDataHandlers {
            rpc: Rpc::Response {
                requester,
                response: Response::Mutation(result),
                message_id,
                refund: None,
                proof: Some((request, accumulated_signature?)),
            },
        })
    }
}

impl Display for IDataHolder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
