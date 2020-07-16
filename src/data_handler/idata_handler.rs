// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{action::Action, rpc::Rpc, utils, vault::Init, Config, Result, ToDbKey};
use log::{debug, info, trace, warn};
use pickledb::PickleDb;
use rand::SeedableRng;
use routing::{Node, ProofShare};
use safe_nd::{
    Error as NdError, IData, IDataAddress, IDataRequest, MessageId, NodeFullId, NodePublicId,
    PublicId, PublicKey, Request, Response, Result as NdResult, XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    rc::Rc,
};
use threshold_crypto::Signature;
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

#[derive(Default, Debug, Serialize, Deserialize)]
struct HolderMetadata {
    chunks: BTreeSet<IDataAddress>,
}

pub(super) struct IDataHandler {
    id: NodePublicId,
    // idata_elder_ops: BTreeMap<MessageId, IDataAddress>,
    // idata_client_ops: BTreeMap<MessageId, IDataOp>,
    // Responses from IDataHolders might arrive before we send a request.
    // This will hold the responses that are processed once the request arrives.
    // early_responses: BTreeMap<MessageId, Vec<(XorName, IDataResult)>>,
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
            // idata_elder_ops: Default::default(),
            // idata_client_ops: Default::default(),
            // early_responses: Default::default(),
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
        request: Request,
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
                    proof: None,
                },
            })
        };

        // If the data already exist, check the existing no of copies.
        // If no of copies are less then required, then continue with the put request.
        let metadata = self.get_metadata_for(*data.address());
        let target_holders = if let Ok(metadata) = metadata {
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
                existing_holders
            }
        } else {
            self.get_holders_for_chunk(data.name())
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        };

        info!("Storing {} copies of the data", target_holders.len());
        let proof =
            self.sign_with_signature_share(&utils::serialise(&(request.clone(), message_id)));
        Some(Action::SendToPeers {
            targets: target_holders,
            rpc: Rpc::Request {
                request,
                requester,
                message_id,
                proof,
            },
        })
    }

    pub(super) fn handle_delete_unpub_idata_req(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
        request: Request,
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
                    proof: None,
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
        let proof =
            self.sign_with_signature_share(&utils::serialise(&(request.clone(), message_id)));
        Some(Action::SendToPeers {
            targets: metadata.holders,
            rpc: Rpc::Request {
                request,
                requester,
                message_id,
                proof,
            },
        })
    }

    pub(super) fn trigger_data_copy_process(&mut self, node_left: XorName) -> Option<Vec<Action>> {
        trace!(
            "Get the list of IData holder {:?} was resposible for",
            node_left
        );
        // Use the address of the lost node as a seed to generate a unique ID on all data handlers.
        // This is only used for the requester field and it should not be used for encryption / signing.
        let mut rng = rand::rngs::StdRng::from_seed(node_left.0);
        let node_id = NodeFullId::new(&mut rng);
        let requester = PublicId::Node(node_id.public_id().clone());
        trace!("Generated NodeID {:?} to get chunk copy", &requester);

        let chunks_stored = self.update_chunk_metadata_on_node_left(node_left);

        if let Ok(chunks_stored) = chunks_stored {
            let mut actions = Vec::new();

            for (address, holders) in chunks_stored {
                trace!("{:?} was resposible for : {:?}", node_left, address);

                let mut hash_bytes = Vec::new();
                hash_bytes.extend_from_slice(&address.name().0);
                hash_bytes.extend_from_slice(&node_left.0);

                let message_id = MessageId(XorName(sha3_256(&hash_bytes)));
                trace!("Generated MsgID {:?} to duplicate chunks", &message_id);

                // Wrap the address in a get request and sign it along with the message id
                let request = Request::IData(IDataRequest::Get(address));

                let new_holders = self.get_new_holders_for_chunk(&address);
                let proof =
                    self.sign_with_signature_share(&utils::serialise(&(request, message_id)));
                let duplicate_chunk_action = Action::SendToPeers {
                    targets: new_holders,
                    rpc: Rpc::Duplicate {
                        address,
                        holders,
                        message_id,
                        proof,
                    },
                };
                actions.push(duplicate_chunk_action);
            }
            Some(actions)
        } else {
            None
        }
    }

    pub(super) fn handle_get_idata_req(
        &mut self,
        requester: PublicId,
        address: IDataAddress,
        message_id: MessageId,
        request: Request,
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
                    proof: None,
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
        let proof =
            self.sign_with_signature_share(&utils::serialise(&(request.clone(), message_id)));
        Some(Action::SendToPeers {
            targets: metadata.holders,
            rpc: Rpc::Request {
                request,
                requester: client_id,
                message_id,
                proof,
            },
        })
    }

    pub(super) fn update_idata_holders(
        &mut self,
        address: IDataAddress,
        sender: XorName,
        result: NdResult<()>,
        message_id: MessageId,
    ) -> Option<Action> {
        if result.is_ok() {
            let mut chunk_metadata = self.get_metadata_for(address).unwrap_or_default();
            if !chunk_metadata.holders.insert(sender) {
                warn!(
                    "{}: {} already registered as a holder for {:?}",
                    self, sender, address
                );
            }

            if let Err(error) = self.metadata.set(&address.to_db_key(), &chunk_metadata) {
                warn!("{}: Failed to write metadata to DB: {:?}", self, error);
            }

            let mut holders_metadata = self.get_holder(sender).unwrap_or_default();
            if !holders_metadata.chunks.insert(address) {
                warn!(
                    "{}: {} already registered as a holder for {:?}",
                    self, sender, &address
                );
            }

            if let Err(error) = self.holders.set(&sender.to_db_key(), &holders_metadata) {
                warn!(
                    "{}: Failed to write holder metadata to DB: {:?}",
                    self, error
                );
            }
            info!("Duplication process completed for: {:?}", message_id);
        } else {
            // Todo: take care of the mutation failure case
        }
        None
    }

    pub(super) fn handle_mutation_resp(
        &mut self,
        sender: XorName,
        requester: PublicId,
        result: NdResult<()>,
        message_id: MessageId,
        request: Request,
    ) -> Option<Action> {
        match &request {
            Request::IData(IDataRequest::Put(data)) => {
                self.handle_put_idata_resp(*data.address(), sender, &result, message_id, requester)
            }
            Request::IData(IDataRequest::DeleteUnpub(address)) => {
                self.handle_delete_unpub_idata_resp(*address, sender, result, message_id, requester)
            }
            _ => None,
        }
    }

    pub(super) fn handle_put_idata_resp(
        &mut self,
        idata_address: IDataAddress,
        sender: XorName,
        _result: &NdResult<()>,
        message_id: MessageId,
        requester: PublicId,
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
        let mut metadata = self.get_metadata_for(idata_address).unwrap_or_default();
        if idata_address.is_unpub() {
            metadata.owner = Some(*utils::own_key(&requester)?);
        }

        if !metadata.holders.insert(sender) {
            warn!(
                "{}: {} already registered as a holder for {:?}",
                self, sender, &idata_address
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
                self, sender, &idata_address
            );
        }

        if let Err(error) = self.holders.set(&sender.to_db_key(), &holders_metadata) {
            warn!("{}: Failed to write metadata to DB: {:?}", self, error);
        }

        // if metadata.holders.len() == IMMUTABLE_DATA_COPY_COUNT {

        // Return Ok once we get a single response.
        // This is sufficient to respond back to the client
        if true {
            Some(Action::RespondToClientHandlers {
                sender: *idata_address.name(),
                rpc: Rpc::Response {
                    requester,
                    response: Response::Mutation(Ok(())),
                    message_id,
                    refund: None,
                    proof: None,
                },
            })
        } else {
            None
        }
    }

    pub(super) fn handle_delete_unpub_idata_resp(
        &mut self,
        idata_address: IDataAddress,
        sender: XorName,
        result: NdResult<()>,
        message_id: MessageId,
        requester: PublicId,
    ) -> Option<Action> {
        if let Err(err) = &result {
            warn!("{}: Node reports error deleting: {}", self, err);
            None
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
                            warn!(
                                "{}: Failed to delete holder metadata from DB: {:?}",
                                self, error
                            );
                        }
                    } else if let Err(error) = self.holders.set(&sender.to_db_key(), &holder) {
                        warn!(
                            "{}: Failed to write holder metadata to DB: {:?}",
                            self, error
                        );
                    }
                }

                // Remove the holder from the chunk metadata
                if !metadata.holders.remove(&sender) {
                    warn!(
                        "{}: {} is not registered as a holder for {:?}",
                        self, sender, &idata_address
                    );
                }
                if metadata.holders.is_empty() {
                    if let Err(error) = self.metadata.rem(&db_key) {
                        warn!(
                            "{}: Failed to delete chunk metadata from DB: {:?}",
                            self, error
                        );
                        // TODO - Send failure back to client handlers?
                    }
                    Some(Action::RespondToClientHandlers {
                        sender: *idata_address.name(),
                        rpc: Rpc::Response {
                            requester,
                            response: Response::Mutation(result),
                            message_id,
                            // Deleting data is free so, no refund
                            // This field can be put to use when deletion is incentivised
                            refund: None,
                            proof: None,
                        },
                    })
                } else if let Err(error) = self.metadata.set(&db_key, &metadata) {
                    warn!(
                        "{}: Failed to write chunk metadata to DB: {:?}",
                        self, error
                    );
                    None
                // TODO - Send failure back to client handlers?
                } else {
                    None
                }
            } else {
                None
            }
        }
    }

    pub(super) fn handle_get_idata_resp(
        &mut self,
        result: NdResult<IData>,
        message_id: MessageId,
        requester: PublicId,
        proof: (Request, Signature),
    ) -> Option<Action> {
        let response = Response::GetIData(result);
        Some(Action::RespondToClientHandlers {
            sender: *self.id.name(),
            rpc: Rpc::Response {
                requester,
                response,
                message_id,
                refund: None,
                proof: Some(proof),
            },
        })
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

    // Returns `XorName`s of the target holders for an idata chunk.
    // Used to fetch the list of holders for a new chunk.
    fn get_holders_for_chunk(&self, target: &XorName) -> Vec<XorName> {
        let routing_node = self.routing_node.borrow_mut();
        let mut closest_adults = routing_node
            .our_adults_sorted_by_distance_to(&xor_name::XorName(target.0))
            .iter()
            .take(IMMUTABLE_DATA_ADULT_COPY_COUNT)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>();

        if closest_adults.len() < IMMUTABLE_DATA_COPY_COUNT {
            let mut closest_elders = routing_node
                .our_elders_sorted_by_distance_to(&xor_name::XorName(target.0))
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

    fn sign_with_signature_share(&self, data: &[u8]) -> Option<ProofShare> {
        let routing_node = self.routing_node.borrow();
        let pk_set = routing_node.public_key_set().ok()?.clone();
        let index = routing_node.our_index().ok()?;
        let secret_key_share = routing_node.secret_key_share().ok()?;
        let proof = ProofShare::new(pk_set, index, secret_key_share, data);
        Some(proof)
    }
}

impl Display for IDataHandler {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
