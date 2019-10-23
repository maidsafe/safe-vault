// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{IDataOp, IDataRequest, OpType};
use crate::{action::Action, rpc::Rpc, utils, vault::Init, Config, Result, ToDbKey};
use log::{trace, warn};
use pickledb::PickleDb;
use safe_nd::{
    Error as NdError, IData, IDataAddress, MessageId, NodePublicId, PublicId, Response,
    Result as NdResult, XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    iter,
};

const IMMUTABLE_META_DB_NAME: &str = "immutable_data.db";
const FULL_ADULTS_DB_NAME: &str = "full_adults.db";
// The number of separate copies of an ImmutableData chunk which should be maintained.
const IMMUTABLE_DATA_COPY_COUNT: usize = 3;

#[derive(Default, Serialize, Deserialize)]
struct ChunkMetadata {
    holders: BTreeSet<XorName>,
}

pub(super) struct IDataHandler {
    id: NodePublicId,
    idata_ops: BTreeMap<MessageId, IDataOp>,
    metadata: PickleDb,
    #[allow(unused)]
    full_adults: PickleDb,
}

impl IDataHandler {
    pub(super) fn new(id: NodePublicId, config: &Config, init_mode: Init) -> Result<Self> {
        let root_dir = config.root_dir()?;
        let metadata = utils::new_db(&root_dir, IMMUTABLE_META_DB_NAME, init_mode)?;
        let full_adults = utils::new_db(&root_dir, FULL_ADULTS_DB_NAME, init_mode)?;

        Ok(Self {
            id,
            idata_ops: Default::default(),
            metadata,
            full_adults,
        })
    }

    pub(super) fn handle_put_idata_req(
        &mut self,
        requester: PublicId,
        data: IData,
        message_id: MessageId,
    ) -> Option<Action> {
        // We're acting as data handler, received request from client handlers
        let data_name = *data.name();

        let client_id = requester.clone();
        let respond = |result: NdResult<()>| {
            let refund = utils::get_refund_for_put(&result);
            Some(Action::RespondToClientHandlers {
                sender: data_name,
                rpc: Rpc::Response {
                    requester: client_id,
                    response: Response::Mutation(result),
                    message_id,
                    refund,
                },
            })
        };

        // Does the data already exist?
        if self.metadata.exists(&(*data.address()).to_db_key()) {
            return if data.is_pub() {
                trace!(
                    "{}: Replying success for Put {:?}, it already exists.",
                    self,
                    data
                );
                respond(Ok(()))
            } else {
                // Only for unpublished immutable data do we return `DataExists` when attempting to
                // put data that already exists.
                respond(Err(NdError::DataExists))
            };
        }

        let target_holders = self
            .non_full_adults_sorted(data.name())
            .chain(self.elders_sorted(data.name()))
            .take(IMMUTABLE_DATA_COPY_COUNT)
            .cloned()
            .collect::<BTreeSet<_>>();
        let data_name = *data.name();
        let idata_op = IDataOp::new(
            requester.clone(),
            IDataRequest::PutIData(data),
            target_holders.clone(),
        );

        match self.idata_ops.entry(message_id) {
            Entry::Occupied(_) => respond(Err(NdError::DuplicateMessageId)),
            Entry::Vacant(vacant_entry) => {
                let idata_op = vacant_entry.insert(idata_op);
                Some(Action::SendToPeers {
                    sender: data_name,
                    targets: target_holders,
                    rpc: Rpc::Request {
                        request: idata_op.request(),
                        requester,
                        message_id,
                    },
                })
            }
        }
    }

    pub(super) fn handle_delete_unpub_idata_req(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let client_id = requester.clone();
        let respond = |result: NdResult<()>| {
            Some(Action::RespondToClientHandlers {
                sender: *address.name(),
                rpc: Rpc::Response {
                    requester: client_id,
                    response: Response::Mutation(result),
                    message_id,
                    refund: None,
                },
            })
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return respond(Err(error)),
        };

        let idata_op = IDataOp::new(
            requester.clone(),
            IDataRequest::DeleteUnpubIData(address),
            metadata.holders.clone(),
        );
        match self.idata_ops.entry(message_id) {
            Entry::Occupied(_) => respond(Err(NdError::DuplicateMessageId)),
            Entry::Vacant(vacant_entry) => {
                let idata_op = vacant_entry.insert(idata_op);
                Some(Action::SendToPeers {
                    sender: *address.name(),
                    targets: metadata.holders,
                    rpc: Rpc::Request {
                        request: idata_op.request(),
                        requester,
                        message_id,
                    },
                })
            }
        }
    }

    pub(super) fn handle_get_idata_req(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let client_id = requester.clone();
        let respond = |result: NdResult<IData>| {
            Some(Action::RespondToClientHandlers {
                sender: *address.name(),
                rpc: Rpc::Response {
                    requester: client_id,
                    response: Response::GetIData(result),
                    message_id,
                    refund: None,
                },
            })
        };

        // We're acting as data handler, received request from client handlers
        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return respond(Err(error)),
        };

        let idata_op = IDataOp::new(
            requester.clone(),
            IDataRequest::GetIData(address),
            metadata.holders.clone(),
        );
        match self.idata_ops.entry(message_id) {
            Entry::Occupied(_) => respond(Err(NdError::DuplicateMessageId)),
            Entry::Vacant(vacant_entry) => {
                let idata_op = vacant_entry.insert(idata_op);
                Some(Action::SendToPeers {
                    sender: *address.name(),
                    targets: metadata.holders,
                    rpc: Rpc::Request {
                        request: idata_op.request(),
                        requester,
                        message_id,
                    },
                })
            }
        }
    }

    pub(super) fn handle_mutation_resp(
        &mut self,
        sender: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        let (idata_address, op_type) = self.idata_op_mut(&message_id).and_then(|idata_op| {
            let op_type = idata_op.op_type();
            idata_op
                .handle_mutation_resp(sender, result.clone(), own_id, message_id)
                .map(|address| (address, op_type))
        })?;

        if op_type == OpType::Put {
            self.handle_put_idata_resp(idata_address, sender, result, message_id)
        } else {
            self.handle_delete_unpub_idata_resp(idata_address, sender, result, message_id)
        }
    }

    pub(super) fn handle_put_idata_resp(
        &mut self,
        idata_address: IDataAddress,
        sender: XorName,
        _result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<Action> {
        // TODO -
        // - if Ok, and this is the final of the three responses send success back to client handlers and
        //   then on to the client.  Note: there's no functionality in place yet to know whether
        //   this is the last response or not.
        // - if Ok, and this is not the last response, just return `None` here.
        // - if Err, we need to flag this sender as "full" (i.e. add to self.full_adults, try on
        //   next closest non-full adult, or elder if none.  Also update the metadata for this
        //   chunk.  Not known yet where we'll get the chunk from to do that.
        //
        // For phase 1, we can leave many of these unanswered.

        // TODO - we'll assume `result` is success for phase 1.
        let db_key = idata_address.to_db_key();
        let mut metadata = self
            .metadata
            .get::<ChunkMetadata>(&db_key)
            .unwrap_or_default();
        if !metadata.holders.insert(sender) {
            warn!(
                "{}: {} already registered as a holder for {:?}",
                self,
                sender,
                self.idata_op(&message_id)?
            );
        }
        if let Err(error) = self.metadata.set(&db_key, &metadata) {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
            // TODO - send failure back to client handlers (hopefully won't accumulate), or
            //        maybe self-terminate if we can't fix this error?
        }

        self.remove_idata_op_if_concluded(&message_id)
            .map(|idata_op| Action::RespondToClientHandlers {
                sender: *idata_address.name(),
                rpc: Rpc::Response {
                    requester: idata_op.client().clone(),
                    response: Response::Mutation(Ok(())),
                    message_id,
                    refund: None,
                },
            })
    }

    pub(super) fn handle_delete_unpub_idata_resp(
        &mut self,
        idata_address: IDataAddress,
        sender: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<Action> {
        // TODO - Only rudimentary checks for if requests to Adult nodes were successful. These
        // mostly assume we're in practice only delegating to a single Adult (ourself in phase 1).
        if let Err(err) = result {
            warn!("{}: Node reports error deleting: {}", self, err);
        } else {
            let db_key = idata_address.to_db_key();
            let metadata = self.metadata.get::<ChunkMetadata>(&db_key).or_else(|| {
                warn!(
                    "{}: Failed to get metadata from DB: {:?}",
                    self, idata_address
                );
                None
            });

            if let Some(mut metadata) = metadata {
                if !metadata.holders.remove(&sender) {
                    warn!(
                        "{}: {} is not registered as a holder for {:?}",
                        self,
                        sender,
                        self.idata_op(&message_id)?
                    );
                }
                if metadata.holders.is_empty() {
                    if let Err(error) = self.metadata.rem(&db_key) {
                        warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
                        // TODO - Send failure back to client handlers?
                    }
                } else if let Err(error) = self.metadata.set(&db_key, &metadata) {
                    warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                    // TODO - Send failure back to client handlers?
                }
            };
        }

        self.remove_idata_op_if_concluded(&message_id)
            .map(|idata_op| {
                let response = {
                    let errors_for_req = idata_op.get_any_errors();
                    assert!(
                        errors_for_req.len() <= 1,
                        "Handling more than one response is not implemented."
                    );
                    if let Some(response) = errors_for_req.values().next() {
                        Err(response.clone())
                    } else {
                        Ok(())
                    }
                };
                Action::RespondToClientHandlers {
                    sender: *idata_address.name(),
                    rpc: Rpc::Response {
                        requester: idata_op.client().clone(),
                        response: Response::Mutation(response),
                        message_id,
                        // Deleting data is free so, no refund
                        // This field can be put to use when deletion is incentivised
                        refund: None,
                    },
                }
            })
    }

    pub(super) fn handle_get_idata_resp(
        &mut self,
        sender: XorName,
        result: NdResult<IData>,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        let action = self.idata_op_mut(&message_id).and_then(|idata_op| {
            idata_op.handle_get_idata_resp(sender, result, own_id, message_id)
        });
        let _ = self.remove_idata_op_if_concluded(&message_id);
        action
    }

    fn get_metadata_for(&self, address: IDataAddress) -> NdResult<ChunkMetadata> {
        match self.metadata.get::<ChunkMetadata>(&address.to_db_key()) {
            Some(metadata) => {
                if metadata.holders.is_empty() {
                    warn!("{}: Metadata holders is empty for: {:?}", self, address);
                    Err(NdError::NoSuchData)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                warn!("{}: Failed to get metadata from DB: {:?}", self, address);
                Err(NdError::NoSuchData)
            }
        }
    }

    pub(super) fn idata_op(&self, message_id: &MessageId) -> Option<&IDataOp> {
        self.idata_ops.get(message_id).or_else(|| {
            warn!(
                "{}: No current ImmutableData operation for {:?}",
                self, message_id
            );
            None
        })
    }

    pub(super) fn idata_op_mut(&mut self, message_id: &MessageId) -> Option<&mut IDataOp> {
        let own_id = format!("{}", self);
        self.idata_ops.get_mut(message_id).or_else(|| {
            warn!(
                "{}: No current ImmutableData operation for {:?}",
                own_id, message_id
            );
            None
        })
    }

    /// Removes and returns the op if it has concluded.
    fn remove_idata_op_if_concluded(&mut self, message_id: &MessageId) -> Option<IDataOp> {
        let is_concluded = self
            .idata_op(message_id)
            .map(IDataOp::concluded)
            .unwrap_or(false);
        if is_concluded {
            return self.idata_ops.remove(message_id);
        }
        None
    }

    // Returns an iterator over all of our section's non-full adults' names, sorted by closest to
    // `target`.
    fn non_full_adults_sorted(&self, _target: &XorName) -> impl Iterator<Item = &XorName> {
        None.iter()
    }

    // Returns an iterator over all of our section's elders' names, sorted by closest to `target`.
    fn elders_sorted(&self, _target: &XorName) -> impl Iterator<Item = &XorName> {
        iter::once(self.id.name())
    }
}

impl Display for IDataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
