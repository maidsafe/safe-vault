use crate::{rpc::Rpc, utils};
use log::{error, info};
use routing::Node;
use safe_nd::{IDataAddress, IDataRequest, MessageId, PublicId, Request, XorName};
use std::cell::RefCell;
use std::collections::{hash_map::Entry, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use threshold_crypto::{Signature, SignatureShare};

type RequestInfo = (Request, PublicId, Vec<(usize, SignatureShare)>);
type DuplicationInfo = (
    IDataAddress,
    BTreeSet<XorName>,
    Vec<(usize, SignatureShare)>,
);

pub struct Accumulator {
    routing_node: Rc<RefCell<Node>>,
    messages: HashMap<MessageId, RequestInfo>,
    duplications: HashMap<MessageId, DuplicationInfo>,
    completed: HashSet<MessageId>,
}

impl Accumulator {
    pub fn new(routing_node: Rc<RefCell<Node>>) -> Self {
        Self {
            routing_node,
            messages: Default::default(),
            duplications: Default::default(),
            completed: Default::default(),
        }
    }

    pub(crate) fn accumulate_request(&mut self, rpc: Rpc) -> Option<(Rpc, Signature)> {
        if self.completed.contains(rpc.message_id()) {
            info!("RPC already processed.");
            return None;
        }
        match rpc {
            Rpc::Request {
                request,
                requester,
                message_id,
                signature,
            } => {
                if let Some(signature) = signature {
                    // If the request comes from a node, the signatures have already
                    // been accumulated at the Adult before the data is requested for duplication.
                    if let (Request::IData(IDataRequest::Get(_)), PublicId::Node(_)) =
                        (&request, &requester)
                    {
                        Some((
                            Rpc::Request {
                                request,
                                requester,
                                message_id,
                                signature: None,
                            },
                            (signature.1).0,
                        ))
                    } else {
                        match self.messages.entry(message_id) {
                            Entry::Vacant(entry) => {
                                let _ = entry.insert((request, requester, vec![signature]));
                            }
                            Entry::Occupied(mut entry) => {
                                let (_, _, signatures) = entry.get_mut();
                                signatures.push(signature);
                            }
                        }

                        let (_, _, signatures) = self.messages.get(&message_id)?;
                        let public_key_set =
                            self.routing_node.borrow().public_key_set().ok()?.clone();
                        info!(
                            "Got {} signatures. We need {}",
                            signatures.len(),
                            public_key_set.threshold() + 1
                        );
                        if signatures.len() > public_key_set.threshold() {
                            let (request, requester, signatures) =
                                self.messages.remove(&message_id)?;
                            let signed_data = utils::serialise(&request);
                            for (idx, sig) in &signatures {
                                if !public_key_set
                                    .public_key_share(idx)
                                    .verify(sig, &signed_data)
                                {
                                    error!("Invalid signature share");
                                    return None;
                                }
                            }
                            let signature = public_key_set
                                .combine_signatures(signatures.iter().map(|(i, sig)| (*i, sig)))
                                .ok()?;
                            if public_key_set.public_key().verify(&signature, &signed_data) {
                                let _ = self.completed.insert(message_id);
                                return Some((
                                    Rpc::Request {
                                        request,
                                        requester,
                                        message_id,
                                        signature: None,
                                    },
                                    signature,
                                ));
                            } else {
                                error!("Accumulated signature is invalid");
                            }
                        }
                        None
                    }
                } else {
                    None
                }
            }
            Rpc::Duplicate {
                address,
                holders,
                message_id,
                signature,
            } => {
                if let Some(signature) = signature {
                    match self.duplications.entry(message_id) {
                        Entry::Vacant(entry) => {
                            let _ = entry.insert((address, holders, vec![signature]));
                        }
                        Entry::Occupied(mut entry) => {
                            let (_, _, signatures) = entry.get_mut();
                            signatures.push(signature);
                        }
                    }
                }

                let (_, _, signatures) = self.duplications.get(&message_id)?;
                let public_key_set = self.routing_node.borrow().public_key_set().ok()?.clone();
                info!(
                    "Got {} signatures. We need {}",
                    signatures.len(),
                    public_key_set.threshold() + 1
                );
                if signatures.len() > public_key_set.threshold() {
                    let (address, holders, signatures) = self.duplications.remove(&message_id)?;
                    log::debug!("{:?}", public_key_set);
                    let signed_data = utils::serialise(&address);
                    for (idx, sig) in &signatures {
                        if !public_key_set
                            .public_key_share(idx)
                            .verify(sig, &signed_data)
                        {
                            error!("Invalid signature share");
                            return None;
                        }
                    }
                    let signature = public_key_set
                        .combine_signatures(signatures.iter().map(|(i, sig)| (*i, sig)))
                        .ok()?;
                    if public_key_set.public_key().verify(&signature, &signed_data) {
                        let _ = self.completed.insert(message_id);
                        return Some((
                            Rpc::Duplicate {
                                address,
                                holders,
                                message_id,
                                signature: None,
                            },
                            signature,
                        ));
                    } else {
                        error!("Accumulated signature is invalid");
                    }
                }
                None
            }
            _ => {
                error!("Should not accumulate");
                None
            }
        }
    }
}
