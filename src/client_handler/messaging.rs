// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::auth::ClientInfo;
use crate::{action::Action, routing::Node, utils};
use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use rand::{CryptoRng, Rng};
use safe_nd::{
    HandshakeRequest, HandshakeResponse, Message, MessageId, NodePublicId, Notification, PublicId,
    Request, Response, Signature, Transaction, XorName,
};
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    rc::Rc,
};

pub(super) struct Messaging {
    id: NodePublicId,
    routing_node: Rc<RefCell<Node>>,
    clients: HashMap<SocketAddr, ClientInfo>,
    pending_msg_ids: HashMap<MessageId, SocketAddr>,
    pending_actions: HashMap<MessageId, Response>,
    // Map of new client connections to the challenge value we sent them.
    client_candidates: HashMap<SocketAddr, (Vec<u8>, PublicId)>,
}

pub(crate) struct ClientRequest {
    pub client: ClientInfo,
    pub request: Request,
    pub message_id: MessageId,
    pub signature: Option<Signature>,
}

impl Messaging {
    pub fn new(id: NodePublicId, routing_node: Rc<RefCell<Node>>) -> Self {
        Self {
            id,
            routing_node,
            clients: Default::default(),
            pending_msg_ids: Default::default(),
            pending_actions: Default::default(),
            client_candidates: Default::default(),
        }
    }

    pub fn try_parse_client_request<R: CryptoRng + Rng>(
        &mut self,
        peer_addr: SocketAddr,
        bytes: &Bytes,
        rng: &mut R,
    ) -> Option<ClientRequest> {
        if let Some(client) = self.clients.get(&peer_addr).cloned() {
            match bincode::deserialize(&bytes) {
                Ok(Message::Request {
                    request,
                    message_id,
                    signature,
                }) => {
                    if self.shall_handle_request(message_id, peer_addr) {
                        return Some(ClientRequest {
                            client,
                            request,
                            message_id,
                            signature,
                        });
                    }
                }
                Ok(Message::Response { response, .. }) => {
                    info!(
                        "{}: {} invalidly sent {:?}",
                        self, client.public_id, response
                    );
                }
                Ok(Message::Notification { notification, .. }) => {
                    info!(
                        "{}: {} invalidly sent {:?}",
                        self, client.public_id, notification
                    );
                }
                Err(err) => {
                    info!(
                        "{}: Unable to deserialise message from {}: {}",
                        self, client.public_id, err
                    );
                }
            }
        } else {
            match bincode::deserialize(&bytes) {
                Ok(HandshakeRequest::Bootstrap(client_id)) => {
                    self.try_bootstrap(peer_addr, &client_id);
                }
                Ok(HandshakeRequest::Join(client_id)) => {
                    self.try_join(peer_addr, client_id, rng);
                }
                Ok(HandshakeRequest::ChallengeResult(signature)) => {
                    self.handle_challenge(peer_addr, &signature);
                }
                Err(err) => {
                    info!(
                        "{}: Unable to deserialise handshake request from {}: {}",
                        self, peer_addr, err
                    );
                }
            }
        }
        None
    }

    pub fn shall_handle_request(&mut self, message_id: MessageId, peer_addr: SocketAddr) -> bool {
        // We could receive a consensused vault rpc contains a client request,
        // before receiving the request from that client directly.
        if let Some(response) = self.pending_actions.remove(&message_id) {
            self.send(
                peer_addr,
                &Message::Response {
                    response,
                    message_id,
                },
            );
            return false;
        }

        if let Entry::Vacant(ve) = self.pending_msg_ids.entry(message_id) {
            let _ = ve.insert(peer_addr);
            true
        } else {
            info!(
                "Pending MessageId {:?} reused - ignoring client message.",
                message_id
            );
            false
        }
    }

    pub fn handle_new_connection(&mut self, peer_addr: SocketAddr) {
        // If we already know the peer, drop the connection attempt.
        if self.clients.contains_key(&peer_addr) || self.client_candidates.contains_key(&peer_addr)
        {
            return;
        }

        info!("{}: Connected to new client on {}", self, peer_addr);
    }

    pub fn handle_connection_failure(&mut self, peer_addr: SocketAddr) {
        if let Some(client) = self.clients.remove(&peer_addr) {
            info!(
                "{}: Disconnected from {:?} on {}",
                self, client.public_id, peer_addr
            );
        } else {
            let _ = self.client_candidates.remove(&peer_addr);
            info!(
                "{}: Disconnected from client candidate on {}",
                self, peer_addr
            );
        }
    }

    #[allow(unused)]
    pub fn notify_client(&mut self, client: &XorName, receipt: Transaction) {
        for client_id in self.lookup_client_and_its_apps(client) {
            self.send_notification_to_client(&client_id, &Notification(receipt));
        }
    }

    pub fn respond_to_client(&mut self, message_id: MessageId, response: Response) {
        let peer_addr = match self.pending_msg_ids.remove(&message_id) {
            Some(peer_addr) => peer_addr,
            None => {
                info!(
                    "{} for message-id {:?}, Unable to find the client to respond to.",
                    self, message_id
                );
                let _ = self.pending_actions.insert(message_id, response);
                return;
            }
        };

        self.send(
            peer_addr,
            &Message::Response {
                response,
                message_id,
            },
        )
    }

    /// Relay response from other node to the client.
    pub fn relay_reponse_to_client(
        &mut self,
        data_handlers: XorName,
        requester: &PublicId,
        response: Response,
        message_id: MessageId,
    ) -> Option<Action> {
        use Response::*;
        trace!(
            "{}: Received ({:?} {:?}) to {} from {}",
            self,
            response,
            message_id,
            requester,
            data_handlers
        );

        match response {
            // Transfer the response from data handlers to clients
            GetIData(..)
            | GetAData(..)
            | GetADataShell(..)
            | GetADataRange(..)
            | GetADataIndices(..)
            | GetADataLastEntry(..)
            | GetADataOwners(..)
            | GetPubADataUserPermissions(..)
            | GetUnpubADataUserPermissions(..)
            | GetADataPermissions(..)
            | GetADataValue(..)
            | GetMData(..)
            | GetMDataShell(..)
            | GetMDataVersion(..)
            | ListMDataEntries(..)
            | ListMDataKeys(..)
            | ListMDataValues(..)
            | ListMDataUserPermissions(..)
            | ListMDataPermissions(..)
            | GetMDataValue(..)
            | Mutation(..)
            | Transaction(..) => {
                self.respond_to_client(message_id, response);
                None
            }
            //
            // ===== Invalid =====
            //
            GetLoginPacket(_) | GetBalance(_) | ListAuthKeysAndVersion(_) => {
                error!(
                    "{}: Should not receive {:?} as a client handler.",
                    self, response
                );
                None
            }
        }
    }

    /// Handles a received challenge response.
    ///
    /// Checks that the response contains a valid signature of the challenge we previously sent.
    /// If a client requests the section info, we also send it.
    fn handle_challenge(&mut self, peer_addr: SocketAddr, signature: &Signature) {
        if let Some((challenge, public_id)) = self.client_candidates.remove(&peer_addr) {
            let public_key = match utils::own_key(&public_id) {
                Some(pk) => pk,
                None => {
                    info!(
                        "{}: Client on {} identifies as a node: {}, hence disconnect from it.",
                        self, peer_addr, public_id
                    );
                    if let Err(err) = self
                        .routing_node
                        .borrow_mut()
                        .disconnect_from_client(peer_addr)
                    {
                        warn!("{}: Could not disconnect client: {:?}", self, err);
                    }
                    return;
                }
            };
            match public_key.verify(&signature, challenge) {
                Ok(()) => {
                    info!("{}: Accepted {} on {}.", self, public_id, peer_addr,);
                    let _ = self.clients.insert(peer_addr, ClientInfo { public_id });
                }
                Err(err) => {
                    info!(
                        "{}: Challenge failed for {} on {}: {}",
                        self, public_id, peer_addr, err
                    );
                    if let Err(err) = self
                        .routing_node
                        .borrow_mut()
                        .disconnect_from_client(peer_addr)
                    {
                        warn!("{}: Could not disconnect client: {:?}", self, err);
                    }
                }
            }
        } else {
            info!(
                "{}: {} supplied challenge response without us providing it.",
                self, peer_addr
            );
            if let Err(err) = self
                .routing_node
                .borrow_mut()
                .disconnect_from_client(peer_addr)
            {
                warn!("{}: Could not disconnect client: {:?}", self, err);
            }
        }
    }

    /// Handles a received join request from a client.
    fn try_join<R: CryptoRng + Rng>(
        &mut self,
        peer_addr: SocketAddr,
        client_id: PublicId,
        rng: &mut R,
    ) {
        if !self
            .routing_node
            .borrow()
            .matches_our_prefix(&routing::XorName(client_id.name().0))
            .unwrap_or(false)
        {
            debug!(
                "Client {} ({}) wants to join us but we are not its client handler",
                client_id, peer_addr
            );
            let _ = self
                .routing_node
                .borrow_mut()
                .disconnect_from_client(peer_addr);
        }
        let challenge = utils::random_vec(rng, 8);
        self.send(
            peer_addr,
            &HandshakeResponse::Challenge(PublicId::Node(self.id.clone()), challenge.clone()),
        );
        let _ = self
            .client_candidates
            .insert(peer_addr, (challenge, client_id));
    }

    fn send<T: Serialize>(&mut self, recipient: SocketAddr, msg: &T) {
        let msg = utils::serialise(msg);
        let msg = Bytes::from(msg);

        if let Err(e) = self
            .routing_node
            .borrow_mut()
            .send_message_to_client(recipient, msg, 0)
        {
            warn!(
                "{}: Could not send message to client {}: {:?}",
                self, recipient, e
            );
        }
    }

    pub(crate) fn send_notification_to_client(
        &mut self,
        client_id: &PublicId,
        notification: &Notification,
    ) {
        let peer_addrs = self.lookup_client_peer_addrs(&client_id);

        if peer_addrs.is_empty() {
            warn!(
                "{}: can't notify {} as none of the instances of the client is connected.",
                self, client_id
            );
            return;
        };

        for peer_addr in peer_addrs {
            self.send(
                peer_addr,
                &Message::Notification {
                    notification: notification.clone(),
                },
            )
        }
    }

    fn lookup_client_peer_addrs(&self, id: &PublicId) -> Vec<SocketAddr> {
        self.clients
            .iter()
            .filter_map(|(peer_addr, client)| {
                if &client.public_id == id {
                    Some(*peer_addr)
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn lookup_client_and_its_apps(&self, name: &XorName) -> Vec<PublicId> {
        self.clients
            .values()
            .filter_map(|client| {
                if client.public_id.name() == name {
                    Some(client.public_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    pub(crate) fn notify_destination_owners(
        &mut self,
        destination: &XorName,
        transaction: Transaction,
    ) {
        for client_id in self.lookup_client_and_its_apps(destination) {
            self.send_notification_to_client(&client_id, &Notification(transaction));
        }
    }

    fn try_bootstrap(&mut self, peer_addr: SocketAddr, client_id: &PublicId) {
        if !self
            .routing_node
            .borrow()
            .matches_our_prefix(&routing::XorName(client_id.name().0))
            .unwrap_or(false)
        {
            let closest_known_elders = match self
                .routing_node
                .borrow()
                .closest_known_elders_to(&routing::XorName(client_id.name().0))
            {
                Ok(elders_iter) => elders_iter
                    .map(|p2p_node| {
                        let peer_addr = *p2p_node.peer_addr();
                        (XorName(p2p_node.name().0), peer_addr)
                    })
                    .collect::<Vec<_>>(),
                Err(e) => {
                    info!("Could not handle bootstrap request: {:?}", e);
                    return;
                }
            };

            if closest_known_elders.is_empty() {
                warn!(
                    "{}: No closest known elders in any section we know of",
                    self
                );
            } else {
                self.send(peer_addr, &HandshakeResponse::Join(closest_known_elders));
            }
        } else {
            let elders = self
                .routing_node
                .borrow_mut()
                .our_elders_info()
                .map(|iter| {
                    iter.map(|p2p_node| {
                        let peer_addr = *p2p_node.peer_addr();
                        (XorName(p2p_node.name().0), peer_addr)
                    })
                    .collect::<Vec<_>>()
                });

            if let Some(elders) = elders {
                self.send(peer_addr, &HandshakeResponse::Join(elders));
            } else {
                warn!("{}: No other elders in our section found", self);
            }
        }
    }
}

impl Display for Messaging {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.name())
    }
}
