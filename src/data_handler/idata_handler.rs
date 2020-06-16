// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{IDataOp, OpType};
use crate::{action::Action, rpc::Rpc, utils, vault::Init, Config, Result, ToDbKey};
use log::{debug, error, info, trace, warn};
use pickledb::PickleDb;
use rand::SeedableRng;
use routing::Node;
use safe_nd::{
    Error as NdError, IData, IDataAddress, IDataRequest, MessageId, NodeFullId, NodePublicId,
    PublicId, PublicKey, Request, Response, Result as NdResult, XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    rc::Rc,
};
use tiny_keccak::sha3_256;

const IMMUTABLE_META_DB_NAME: &str = "immutable_data.db";
const HOLDER_META_DB_NAME: &str = "holder_data.db";
const FULL_ADULTS_DB_NAME: &str = "full_adults.db";
// The number of separate copies of an ImmutableData chunk which should be maintained.
const IMMUTABLE_DATA_COPY_COUNT: usize = 4;
const IMMUTABLE_DATA_ADULT_COPY_COUNT: usize = 3;

#[derive(Default, Debug, Serialize, Deserialize)]
struct ChunkMetadata {
    holders: BTreeSet<XorName>,
    owner: Option<PublicKey>,
}

#[derive(Debug)]
enum IDataResult {
    Mutation(NdResult<()>),
    Get(NdResult<IData>),
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct HolderMetadata {
    chunks: BTreeSet<IDataAddress>,
}

pub(super) struct IDataHandler {
    id: NodePublicId,
    idata_elder_ops: BTreeSet<MessageId>,
    idata_client_ops: BTreeMap<MessageId, IDataOp>,
    // Responses from IDataHolders might arrive before we send a request.
    // This will hold the responses that are processed once the request arrives.
    early_responses: BTreeMap<MessageId, Vec<(XorName, IDataResult)>>,
    metadata: PickleDb,
    holders: PickleDb,
    #[allow(unused)]
    full_adults: PickleDb,
    #[allow(unused)]
    routing_node: Rc<RefCell<Node>>,
}

impl IDataHandler {
    pub(super) fn new(
        id: NodePublicId,
        config: &Config,
        init_mode: Init,
        routing_node: Rc<RefCell<Node>>,
    ) -> Result<Self> {
        let root_dir = config.root_dir()?;
        let metadata = utils::new_db(&root_dir, IMMUTABLE_META_DB_NAME, init_mode)?;
        let holders = utils::new_db(&root_dir, HOLDER_META_DB_NAME, init_mode)?;
        let full_adults = utils::new_db(&root_dir, FULL_ADULTS_DB_NAME, init_mode)?;

        Ok(Self {
            id,
            idata_elder_ops: Default::default(),
            idata_client_ops: Default::default(),
            early_responses: Default::default(),
            metadata,
            holders,
            full_adults,
            routing_node,
        })
    }

    pub(super) fn handle_put_idata_req(
        &mut self,
        requester: PublicId,
        data: IData,
        message_id: MessageId,
    ) -> Option<Action> {
        // We're acting as data handler, received request from client handlers
        let our_name = *self.id.name();

        let client_id = requester.clone();
        let respond = |result: NdResult<()>| {
            let refund = utils::get_refund_for_put(&result);
            Some(Action::RespondToClientHandlers {
                sender: our_name,
                rpc: Rpc::Response {
                    requester: client_id,
                    response: Response::Mutation(result),
                    message_id,
                    refund,
                },
            })
        };

        let mut target_holders = Default::default();

        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        if self.metadata.exists(&(*data.address()).to_db_key()) {
            let idata_metadata = self
                .metadata
                .get::<ChunkMetadata>(&*data.address().to_db_key());
            if let Some(metadata) = idata_metadata {
                if metadata.holders.len() == IMMUTABLE_DATA_COPY_COUNT {
                    if data.is_pub() {
                        trace!(
                            "{}: Replying success for Put {:?}, it already exists.",
                            self,
                            data
                        );
                        return respond(Ok(()));
                    } else {
                        return respond(Err(NdError::DataExists));
                    }
                } else {
                    let mut existing_holders = metadata.holders;
                    let closest_holders = self
                        .get_holders_for_chunk(data.name())
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>();

                    for holder_xorname in closest_holders {
                        if !existing_holders.contains(&holder_xorname)
                            && existing_holders.len() < IMMUTABLE_DATA_COPY_COUNT
                        {
                            let _ = existing_holders.insert(holder_xorname);
                        }
                    }
                    target_holders = existing_holders;
                }
            }
        } else {
            target_holders = self
                .get_holders_for_chunk(data.name())
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
        };

        info!("Storing {} copies of the data", target_holders.len());

        let idata_op = IDataOp::new(
            requester.clone(),
            IDataRequest::Put(data),
            target_holders.clone(),
        );
        let process_request_action = match self.idata_client_ops.entry(message_id) {
            Entry::Occupied(_) => respond(Err(NdError::DuplicateMessageId)),
            Entry::Vacant(vacant_entry) => {
                let idata_op = vacant_entry.insert(idata_op);
                Some(Action::SendToPeers {
                    sender: our_name,
                    targets: target_holders,
                    rpc: Rpc::Request {
                        request: Request::IData(idata_op.request().clone()),
                        requester,
                        message_id,
                    },
                })
            }
        };

        // Check if we really need to send the request
        self.apply_early_responses(message_id)
            .or(process_request_action)
    }

    // IData holders will process requests if quorum number of elders have sent the request.
    // If were not a part of that quorum, we might've received the response before sending the request.
    // This functions checks if a holder has already responded to a request, if so, it is applied and marked as actioned.
    // If all the nodes holding the chunk have responded to the request this will return an `Action::RespondToClientHandlers`
    // which can be directly sent back to the client handlers.
    fn apply_early_responses(&mut self, message_id: MessageId) -> Option<Action> {
        let own_id = format!("{}", &self);
        if let Some(responses) = self.early_responses.remove(&message_id) {
            debug!(
                "Applying {}, early resposes on operation with MessageID: {:?}",
                responses.len(),
                &message_id
            );
            let op_type = self.idata_op(&message_id)?.op_type();
            let mut actions = responses
                .into_iter()
                .filter_map(|(sender, idata_result)| match (op_type, idata_result) {
                    (OpType::Get, IDataResult::Get(result)) => {
                        self.handle_get_idata_resp(sender, result, message_id)
                    }
                    (_, IDataResult::Mutation(result)) => self
                        .idata_op_mut(&message_id)?
                        .handle_mutation_resp(sender, result.clone(), &own_id, message_id)
                        .map(|address| (address, op_type))
                        .and_then(|(idata_address, op_type)| {
                            if op_type == OpType::Put {
                                self.handle_put_idata_resp(
                                    idata_address,
                                    sender,
                                    &result,
                                    message_id,
                                )
                            } else {
                                self.handle_delete_unpub_idata_resp(
                                    idata_address,
                                    sender,
                                    result,
                                    message_id,
                                )
                            }
                        }),
                    (op, result) => {
                        error!("{:?} and {:?} are incompatible", &op, &result);
                        None
                    }
                })
                .collect::<Vec<Action>>();
            debug!("Resultant actions: {:?}", &actions);
            // There will be only one action. Others will be None.
            actions.pop()
        } else {
            None
        }
    }

    pub(super) fn handle_delete_unpub_idata_req(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let our_name = *self.id.name();
        let client_id = requester.clone();
        let respond = |result: NdResult<()>| {
            Some(Action::RespondToClientHandlers {
                sender: our_name,
                rpc: Rpc::Response {
                    requester: client_id.clone(),
                    response: Response::Mutation(result),
                    message_id,
                    // Deletion is free so no refund
                    refund: None,
                },
            })
        };

        let metadata = match self.get_metadata_for(address) {
            Ok(metadata) => metadata,
            Err(error) => return respond(Err(error)),
        };

        if let Some(data_owner) = metadata.owner {
            let request_key = utils::own_key(&requester)?;
            if data_owner != *request_key {
                return respond(Err(NdError::AccessDenied));
            }
        };

        let idata_op = IDataOp::new(
            requester,
            IDataRequest::DeleteUnpub(address),
            metadata.holders.clone(),
        );

        let process_request_action = match self.idata_client_ops.entry(message_id) {
            Entry::Occupied(_) => respond(Err(NdError::DuplicateMessageId)),
            Entry::Vacant(vacant_entry) => {
                let idata_op = vacant_entry.insert(idata_op);
                Some(Action::SendToPeers {
                    sender: our_name,
                    targets: metadata.holders,
                    rpc: Rpc::Request {
                        request: Request::IData(idata_op.request().clone()),
                        requester: client_id,
                        message_id,
                    },
                })
            }
        };

        self.apply_early_responses(message_id)
            .or(process_request_action)
    }

    pub(super) fn request_chunk_from_holders(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        holders: BTreeSet<XorName>,
        message_id: MessageId,
    ) -> Option<Action> {
        let our_name = *self.id.name();
        let idata_op = IDataOp::new(
            requester.clone(),
            IDataRequest::Get(address),
            holders.clone(),
        );
        if !self.idata_elder_ops.contains(&message_id) {
            let _ = self.idata_elder_ops.insert(message_id);
            let request_chunks_action = match self.idata_client_ops.entry(message_id) {
                Entry::Occupied(_) => None,
                Entry::Vacant(vacant_entry) => {
                    let idata_op = vacant_entry.insert(idata_op);
                    Some(Action::SendToPeers {
                        sender: our_name,
                        targets: holders,
                        rpc: Rpc::Request {
                            request: Request::IData(idata_op.request().clone()),
                            requester,
                            message_id,
                        },
                    })
                }
            };
            self.apply_early_responses(message_id)
                .or(request_chunks_action)
        } else {
            None
        }
    }

    pub(super) fn handle_get_idata_req(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
    ) -> Option<Action> {
        let our_name = *self.id.name();

        let client_id = requester.clone();
        let respond = |result: NdResult<IData>| {
            Some(Action::RespondToClientHandlers {
                sender: our_name,
                rpc: Rpc::Response {
                    requester: client_id.clone(),
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

        if let Some(data_owner) = metadata.owner {
            let request_key = utils::own_key(&requester)?;
            if data_owner != *request_key {
                return respond(Err(NdError::AccessDenied));
            }
        };

        let idata_op = IDataOp::new(
            requester,
            IDataRequest::Get(address),
            metadata.holders.clone(),
        );

        let process_request_action = match self.idata_client_ops.entry(message_id) {
            Entry::Occupied(_) => respond(Err(NdError::DuplicateMessageId)),
            Entry::Vacant(vacant_entry) => {
                let idata_op = vacant_entry.insert(idata_op);
                Some(Action::SendToPeers {
                    sender: our_name,
                    targets: metadata.holders,
                    rpc: Rpc::Request {
                        request: Request::IData(idata_op.request().clone()),
                        requester: client_id,
                        message_id,
                    },
                })
            }
        };

        self.apply_early_responses(message_id)
            .or(process_request_action)
    }

    pub(super) fn handle_mutation_resp(
        &mut self,
        sender: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<Action> {
        let own_id = format!("{}", self);
        let (idata_address, op_type) = self
            .idata_op_mut(&message_id)
            .and_then(|idata_op| {
                let op_type = idata_op.op_type();
                idata_op
                    .handle_mutation_resp(sender, result.clone(), &own_id, message_id)
                    .map(|address| (address, op_type))
            })
            .or_else(|| {
                // The response arrived before this particular vault processed the request
                match self.early_responses.entry(message_id) {
                    Entry::Vacant(vacant_entry) => {
                        let _ = vacant_entry
                            .insert(vec![(sender, IDataResult::Mutation(result.clone()))]);
                    }
                    Entry::Occupied(mut entry) => {
                        entry
                            .get_mut()
                            .push((sender, IDataResult::Mutation(result.clone())));
                    }
                }
                trace!("Added early response for message ID: {:?}", message_id);
                trace!("Current: {:?}", self.early_responses.get(&message_id));
                None
            })?;

        if op_type == OpType::Put {
            self.handle_put_idata_resp(idata_address, sender, &result, message_id)
        } else {
            self.handle_delete_unpub_idata_resp(idata_address, sender, result, message_id)
        }
    }

    pub(super) fn handle_put_idata_resp(
        &mut self,
        idata_address: IDataAddress,
        sender: XorName,
        _result: &NdResult<()>,
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
        let is_idata_copy_op = self.idata_elder_ops.contains(&message_id);
        let db_key = idata_address.to_db_key();
        let mut metadata = self.get_metadata_for(idata_address).unwrap_or_default();
        let idata_op = self.idata_op(&message_id);

        if !is_idata_copy_op {
            if let Some(idata_put_op) = idata_op {
                let request = idata_put_op.request();
                metadata.owner = match request {
                    IDataRequest::Put(IData::Unpub(_)) => {
                        Some(*utils::own_key(idata_put_op.client())?)
                    }
                    _ => None,
                }
            }
        }

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
        debug!(
            "{:?}, Entry {:?} has {:?} holders",
            self.id,
            idata_address,
            metadata.holders.len()
        );

        // We're acting as data handler, received request from client handlers
        let mut holders_metadata = self.get_holder(sender).unwrap_or_default();

        if !holders_metadata.chunks.insert(idata_address) {
            warn!(
                "{}: {} already registered as a holder for {:?}",
                self,
                sender,
                self.idata_op(&message_id)?
            );
        }

        if let Err(error) = self.holders.set(&sender.to_db_key(), &holders_metadata) {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
        }

        if is_idata_copy_op {
            trace!("Duplication operation completed for : {:?}", idata_address);
            let _ = self.idata_elder_ops.remove(&message_id);
            let _ = self.remove_idata_op_if_concluded(&message_id);
            None
        } else {
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
            let metadata = self.get_metadata_for(idata_address);

            if let Ok(mut metadata) = metadata {
                let holder = self.get_holder(sender);

                // Remove the chunk from the holder metadata
                if let Ok(mut holder) = holder {
                    let _ = holder.chunks.remove(&idata_address);

                    if holder.chunks.is_empty() {
                        if let Err(error) = self.holders.rem(&sender.to_db_key()) {
                            warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
                        }
                    } else if let Err(error) = self.holders.set(&sender.to_db_key(), &holder) {
                        warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                    }
                }

                // Remove the holder from the chunk metadata
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
        let is_idata_copy_op = self.idata_elder_ops.contains(&message_id);

        let action = if is_idata_copy_op {
            info!("Holder {:?} responded with chunk for duplication", sender);

            match result {
                Ok(idata) => {
                    let _ = self.idata_elder_ops.remove(&message_id);
                    let _ = self.idata_client_ops.remove(&message_id);

                    // Send PUT requests to holders to store a new copy of the chunk.
                    // Use the address of the data as a seed to generate a unique ID on all data handlers.
                    // This is only used for the requester field and it should not be used for encryption / signing.
                    let mut rng = rand::rngs::StdRng::from_seed(idata.address().name().0);
                    let node_id = NodeFullId::new(&mut rng);
                    let requester = PublicId::Node(node_id.public_id().clone());

                    // Hash the old message ID with the IData address for a unique MessageID
                    let mut hash_bytes = Vec::new();
                    hash_bytes.extend_from_slice(&(message_id.0).0);
                    hash_bytes.extend_from_slice(&idata.address().name().0);
                    let new_msg_id = MessageId(XorName(sha3_256(&hash_bytes)));
                    trace!(
                        "Generated MsgID {:?} & NodeID {:?} to store additional chunk copy",
                        &message_id,
                        &requester
                    );
                    let new_holders = self.get_new_holders_for_chunk(idata.address());

                    let idata_op = IDataOp::new(
                        requester.clone(),
                        IDataRequest::Put(idata),
                        new_holders.clone(),
                    );

                    match self.idata_client_ops.entry(new_msg_id) {
                        Entry::Occupied(_) => None,
                        Entry::Vacant(vacant_entry) => {
                            let _ = self.idata_elder_ops.insert(new_msg_id);
                            let idata_op = vacant_entry.insert(idata_op);
                            Some(Action::SendToPeers {
                                sender: *self.id.name(),
                                targets: new_holders,
                                rpc: Rpc::Request {
                                    request: Request::IData(idata_op.request().clone()),
                                    requester,
                                    message_id: new_msg_id,
                                },
                            })
                        }
                    }
                }
                Err(_) => None,
            }
        } else {
            self.idata_op_mut(&message_id)
                .and_then(|idata_op| {
                    idata_op.handle_get_idata_resp(sender, result.clone(), &own_id, message_id)
                })
                .or_else(|| {
                    // The response arrived before this particular vault processed the request
                    // Note that for get responses we hold only one early response
                    if let Entry::Vacant(vacant_entry) = self.early_responses.entry(message_id) {
                        let _ =
                            vacant_entry.insert(vec![(sender, IDataResult::Get(result.clone()))]);
                    }
                    trace!("Added early response for message ID: {:?}", message_id);
                    trace!("Current: {:?}", self.early_responses.get(&message_id));
                    None
                })
        };

        let _ = self.remove_idata_op_if_concluded(&message_id);
        action
    }

    // Updates the metadata of the chunks help by a node that left.
    // Returns the list of chunks that were held along with the remaining holders.
    pub fn update_chunk_metadata_on_node_left(
        &mut self,
        node: XorName,
    ) -> NdResult<BTreeMap<IDataAddress, BTreeSet<XorName>>> {
        let mut idata_addresses: BTreeMap<IDataAddress, BTreeSet<XorName>> = BTreeMap::new();
        let chunk_holder = self.get_holder(node);

        if let Ok(holder) = chunk_holder {
            for chunk_address in holder.chunks {
                let db_key = chunk_address.to_db_key();
                let chunk_metadata = self.get_metadata_for(chunk_address);

                if let Ok(mut metadata) = chunk_metadata {
                    if !metadata.holders.remove(&node) {
                        warn!("doesn't contain the holder",);
                    }

                    let _ = idata_addresses.insert(chunk_address, metadata.holders.clone());

                    if metadata.holders.is_empty() {
                        if let Err(error) = self.metadata.rem(&db_key) {
                            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                        }
                    } else if let Err(error) = self.metadata.set(&db_key, &metadata) {
                        warn!("{}: Failed to write metadata to DB: {:?}", self, error);
                    }
                }
            }
        }

        // Since the node has left the section, remove it from the holders DB
        if let Err(error) = self.holders.rem(&node.to_db_key()) {
            warn!("{}: Failed to delete metadata from DB: {:?}", self, error);
        };

        Ok(idata_addresses)
    }

    fn get_holder(&self, holder: XorName) -> NdResult<HolderMetadata> {
        match self.holders.get::<HolderMetadata>(&holder.to_db_key()) {
            Some(metadata) => {
                if metadata.chunks.is_empty() {
                    warn!("{}: is not responsible for any chunk", holder);
                    Err(NdError::NoSuchData)
                } else {
                    Ok(metadata)
                }
            }
            None => {
                info!("{}: is not responsible for any chunk", holder);
                Err(NdError::NoSuchData)
            }
        }
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
        self.idata_client_ops.get(message_id).or_else(|| {
            warn!(
                "{}: No current ImmutableData operation for {:?}",
                self, message_id
            );
            None
        })
    }

    pub(super) fn idata_op_mut(&mut self, message_id: &MessageId) -> Option<&mut IDataOp> {
        let own_id = format!("{}", self);
        self.idata_client_ops.get_mut(message_id).or_else(|| {
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
            return self.idata_client_ops.remove(message_id);
        }
        None
    }

    // Returns `XorName`s of the target holders for an idata chunk.
    // Used to fetch the list of holders for a new chunk.
    fn get_holders_for_chunk(&self, target: &XorName) -> Vec<XorName> {
        let routing_node = self.routing_node.borrow_mut();
        let mut closest_adults = routing_node
            .our_adults_sorted_by_distance_to(&routing::XorName(target.0))
            .iter()
            .take(IMMUTABLE_DATA_ADULT_COPY_COUNT)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>();

        if closest_adults.len() < IMMUTABLE_DATA_COPY_COUNT {
            let mut closest_elders = routing_node
                .our_elders_sorted_by_distance_to(&routing::XorName(target.0))
                .into_iter()
                .take(IMMUTABLE_DATA_COPY_COUNT - closest_adults.len())
                .map(|p2p_node| XorName(p2p_node.name().0))
                .collect::<Vec<_>>();

            closest_adults.append(&mut closest_elders);
            closest_adults
        } else {
            closest_adults
        }
    }

    // Returns `XorName`s of the new target holders for an idata chunk.
    // Used to fetch the additional list of holders for existing chunks.
    fn get_new_holders_for_chunk(&self, target: &IDataAddress) -> BTreeSet<XorName> {
        let closest_holders = self
            .get_holders_for_chunk(target.name())
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Ok(metadata) = self.get_metadata_for(*target) {
            return closest_holders
                .difference(&metadata.holders)
                .cloned()
                .collect();
        }
        closest_holders
    }
}

impl Display for IDataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
