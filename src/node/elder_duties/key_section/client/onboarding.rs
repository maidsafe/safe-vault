// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Network};
use crate::{Error, Result};
use dashmap::DashMap;
use log::{debug, error, info, trace};
use sn_data_types::{HandshakeRequest, HandshakeResponse, PublicKey};
use sn_routing::SendStream;
use std::{
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
    routing: Network,
    clients: DashMap<SocketAddr, PublicKey>,
    /// Map of new client connections to the challenge value we sent them.
    client_candidates: DashMap<SocketAddr, (Vec<u8>, PublicKey)>,
}

impl Onboarding {
    pub fn new(routing: Network) -> Self {
        Self {
            routing,
            clients: Default::default(),
            client_candidates: Default::default(),
        }
    }

    /// Query
    pub fn get_public_key(&self, peer_addr: SocketAddr) -> Option<PublicKey> {
        let value_ref = self.clients.get(&peer_addr)?;
        let value = value_ref.to_owned();
        Some(value)
    }

    // pub fn remove_client(&mut self, peer_addr: SocketAddr) {
    //     if let Some(public_key) = self.clients.remove(&peer_addr) {
    //         info!("{}: Removed client {:?} on {}", self, public_key, peer_addr);
    //     } else {
    //         let _ = self.client_candidates.remove(&peer_addr);
    //         info!("{}: Removed client candidate on {}", self, peer_addr);
    //     }
    // }

    pub async fn onboard_client(
        &self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
        stream: &mut SendStream,
    ) -> Result<()> {
        match handshake {
            HandshakeRequest::Bootstrap(client_key) => {
                self.try_bootstrap(peer_addr, &client_key, stream).await
            }
            HandshakeRequest::Join(client_key) => {
                self.try_join(peer_addr, client_key).await
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

    async fn try_bootstrap(
        &self,
        peer_addr: SocketAddr,
        client_key: &PublicKey,
        stream: &mut SendStream,
    ) -> Result<()> {
        if !self.shall_bootstrap(&peer_addr) {
            info!(
                "Redundant bootstrap..: {} on {}",
                client_key, peer_addr
            );
            return Ok(());
        }
        info!(
            "{}: Trying to bootstrap..: {} on {}",
            self, client_key, peer_addr
        );
        let elders = if self.routing.matches_our_prefix((*client_key).into()).await {
            self.routing.our_elder_addresses().await
        } else {
            let closest_known_elders = self
                .routing
                .our_elder_addresses_sorted_by_distance_to(&(*client_key).into())
                .await;
            if closest_known_elders.is_empty() {
                trace!(
                    "{}: No closest known elders in any section we know of",
                    self
                );
                return Ok(());
            } else {
                closest_known_elders
            }
        };
        let bytes = utils::serialise(&HandshakeResponse::Join(elders))?;
        // Hmmmm, what to do about this response.... we don't need a duty response here?
        let res = futures::executor::block_on(stream.send_user_msg(bytes));

        match res {
            Ok(()) => Ok(()),
            Err(error) => {
                error!("Error sending on stream {:?}", error);
                Err(Error::Onboarding)
            }
        }
    }

    /// Handles a received join request from a client.
    async fn try_join (
        &self,
        peer_addr: SocketAddr,
        client_key: PublicKey,
    ) -> Result<()> {
        info!(
            "{}: Trying to join..: {} on {}",
            self, client_key, peer_addr
        );
        if self.routing.matches_our_prefix(client_key.into()).await {
            match self.clients.insert(peer_addr, client_key) {
                None => info!(
                    "{}: Client is already accepted..: {} on {}",
                    self, client_key, peer_addr
                ),
                Some(_) => info!("{}: Client Joined..: {} on {}", self, client_key, peer_addr),
            };
        } else {
            debug!(
                "Client {} ({}) wants to join us but we are not its client handler",
                client_key, peer_addr
            ); // FIXME - send error back to client
            return Err(Error::Onboarding);
        };
        Ok(())
    }
}


impl Display for Onboarding {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Onboarding")
    }
}
