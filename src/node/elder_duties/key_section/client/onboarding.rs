// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::node_ops::MessagingDuty;
use crate::{utils, Network};
use log::{debug, info, trace};
use rand::{CryptoRng, Rng};
use safe_nd::{HandshakeRequest, HandshakeResponse, PublicKey, Signature};
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// A client is defined as a public key
/// used by a specific socket address.
/// Onboarding module deals with new and existing
/// client connections to the section closest to the
/// public key of that client.
/// Most notably, this is the handshake process
/// taking place between a connecting client and
/// the Elders of this section.
pub struct Onboarding {
    node_id: PublicKey,
    routing: Network,
    clients: HashMap<SocketAddr, PublicKey>,
    // Map of new client connections to the challenge value we sent them.
    client_candidates: HashMap<SocketAddr, (Vec<u8>, PublicKey)>,
}

impl Onboarding {
    pub fn new(node_id: PublicKey, routing: Network) -> Self {
        Self {
            node_id,
            routing,
            clients: HashMap::<SocketAddr, PublicKey>::new(),
            client_candidates: Default::default(),
        }
    }

    /// Query
    pub fn get_public_key(&mut self, peer_addr: SocketAddr) -> Option<&PublicKey> {
        self.clients.get(&peer_addr)
    }

    pub fn remove_client(&mut self, peer_addr: SocketAddr) {
        if let Some(public_key) = self.clients.remove(&peer_addr) {
            info!("{}: Removed client {:?} on {}", self, public_key, peer_addr);
        } else {
            let _ = self.client_candidates.remove(&peer_addr);
            info!("{}: Removed client candidate on {}", self, peer_addr);
        }
    }

    pub fn process<G: CryptoRng + Rng>(
        &mut self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
        rng: &mut G,
    ) -> Option<MessagingDuty> {
        match handshake {
            HandshakeRequest::Bootstrap(client_key) => self.try_bootstrap(peer_addr, &client_key),
            HandshakeRequest::Join(client_key) => self.try_join(peer_addr, client_key, rng),
            HandshakeRequest::ChallengeResult(signature) => {
                self.receive_challenge_response(peer_addr, &signature)
            }
        }
    }

    fn shall_bootstrap(&self, peer_addr: &SocketAddr) -> bool {
        let is_bootstrapping = self.client_candidates.contains_key(peer_addr);
        let is_bootstrapped = self.clients.contains_key(peer_addr);
        if is_bootstrapped || is_bootstrapping {
            return false;
        }
        true
    }

    fn try_bootstrap(
        &self,
        peer_addr: SocketAddr,
        client_key: &PublicKey,
    ) -> Option<MessagingDuty> {
        if !self.shall_bootstrap(&peer_addr) {
            info!(
                "{}: Redundant bootstrap..: {} on {}",
                self, client_key, peer_addr
            );
            return None;
        }

        info!(
            "{}: Trying to bootstrap..: {} on {}",
            self, client_key, peer_addr
        );

        let elders = if self.routing.matches_our_prefix((*client_key).into()) {
            self.routing.our_elder_addresses()
        } else {
            let closest_known_elders = self
                .routing
                .our_elder_addresses_sorted_by_distance_to(&(*client_key).into());
            if closest_known_elders.is_empty() {
                trace!(
                    "{}: No closest known elders in any section we know of",
                    self
                );
                return None;
            } else {
                closest_known_elders
            }
        };
        Some(MessagingDuty::SendHandshake {
            address: peer_addr,
            response: HandshakeResponse::Join(elders),
        })
    }

    /// Handles a received join request from a client.
    fn try_join<G: CryptoRng + Rng>(
        &mut self,
        peer_addr: SocketAddr,
        client_key: PublicKey,
        rng: &mut G,
    ) -> Option<MessagingDuty> {
        info!(
            "{}: Trying to join..: {} on {}",
            self, client_key, peer_addr
        );
        if self.routing.matches_our_prefix(client_key.into()) {
            let challenge = utils::random_vec(rng, 8);
            let _ = self
                .client_candidates
                .insert(peer_addr, (challenge.clone(), client_key));
            Some(MessagingDuty::SendHandshake {
                address: peer_addr,
                response: HandshakeResponse::Challenge(self.node_id, challenge),
            })
        } else {
            debug!(
                "Client {} ({}) wants to join us but we are not its client handler",
                client_key, peer_addr
            );
            Some(MessagingDuty::DisconnectClient(peer_addr))
        }
    }

    /// Handles a received challenge response.
    ///
    /// Checks that the response contains a valid signature of the challenge we previously sent.
    /// If a client requests the section info, we also send it.
    fn receive_challenge_response(
        &mut self,
        peer_addr: SocketAddr,
        signature: &Signature,
    ) -> Option<MessagingDuty> {
        trace!("Receive challenge response");
        if let Some((challenge, public_key)) = self.client_candidates.remove(&peer_addr) {
            match public_key.verify(&signature, challenge) {
                Ok(()) => {
                    info!("{}: Accepted {} on {}.", self, public_key, peer_addr,);
                    let _ = self.clients.insert(peer_addr, public_key);
                    None
                }
                Err(err) => {
                    info!(
                        "{}: Challenge failed for {} on {}: {}",
                        self, public_key, peer_addr, err
                    );
                    Some(MessagingDuty::DisconnectClient(peer_addr))
                }
            }
        } else {
            info!(
                "{}: {} supplied challenge response without us providing it.",
                self, peer_addr
            );
            Some(MessagingDuty::DisconnectClient(peer_addr))
        }
    }

    // pub fn notify_client(&mut self, client: &XorName, receipt: &DebitAgreementProof) {
    //     for client_key in self.lookup_client_and_its_apps(client) {
    //         self.send_notification_to_client(&client_key, &TransferNotification(receipt.clone()));
    //     }
    // }

    // pub(crate) fn send_notification_to_client(
    //     &mut self,
    //     client_key: &PublicId,
    //     notification: &TransferNotification,
    // ) {
    //     let peer_addrs = self.lookup_client_peer_addrs(&client_key);

    //     if peer_addrs.is_empty() {
    //         warn!(
    //             "{}: can't notify {} as none of the instances of the client is connected.",
    //             self, client_key
    //         );
    //         return;
    //     };

    //     for peer_addr in peer_addrs {
    //         self.send(
    //             peer_addr,
    //             &Message::TransferNotification {
    //                 payload: notification.clone(),
    //             },
    //         )
    //     }
    // }

    // fn lookup_client_peer_addrs(&self, id: &PublicId) -> Vec<SocketAddr> {
    //     self.clients
    //         .iter()
    //         .filter_map(|(peer_addr, client)| {
    //             if &client.public_key == id {
    //                 Some(*peer_addr)
    //             } else {
    //                 None
    //             }
    //         })
    //         .collect()
    // }

    // fn lookup_client_and_its_apps(&self, name: &XorName) -> Vec<PublicId> {
    //     self.clients
    //         .values()
    //         .filter_map(|client| {
    //             if client.public_key.name() == name {
    //                 Some(client.public_key.clone())
    //             } else {
    //                 None
    //             }
    //         })
    //         .collect::<Vec<_>>()
    // }
}

impl Display for Onboarding {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Onboarding")
    }
}
