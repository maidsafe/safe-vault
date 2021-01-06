// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Network};
use crate::{Error, Result};
use bytes::Bytes;
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
}

impl Onboarding {
    pub fn new(routing: Network) -> Self {
        Self {
            routing,
            clients: Default::default(),
        }
    }
    pub async fn onboard_client(
        &self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
        stream: &mut SendStream,
    ) -> Result<()> {
        info!("Onboarding client w/ peer addr: {:?}", peer_addr);
        match handshake {
            HandshakeRequest::Bootstrap(client_key) => {
                self.try_bootstrap(peer_addr, &client_key, stream).await
            }
            HandshakeRequest::Join(client_key) => self.try_join(peer_addr, client_key).await,
        }
    }

    fn shall_bootstrap(&self, peer_addr: &SocketAddr) -> bool {
        let is_bootstrapped = self.clients.contains_key(peer_addr);
        if is_bootstrapped {
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
                "{}: Redundant bootstrap..: {} on {}",
                self, client_key, peer_addr
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

        info!("elders for client determined");
        let bytes = utils::serialise(&HandshakeResponse::Join(elders))?;

        info!("sending bytes back");

        // let res = self.send_bytes_to(peer_addr, bytes).await;

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
    async fn try_join(&self, peer_addr: SocketAddr, client_key: PublicKey) -> Result<()> {
        if self.clients.contains_key(&peer_addr) {
            info!(
                "{}: Client is already accepted..: {} on {}",
                self, client_key, peer_addr
            );
            return Ok(());
        }
        info!(
            "{}: Trying to join..: {} on {}",
            self, client_key, peer_addr
        );
        if self.routing.matches_our_prefix(client_key.into()).await {
            Ok(())
        } else {
            debug!(
                "Client {} ({}) wants to join us but we are not its client handler",
                client_key, peer_addr
            );
            Err(Error::Onboarding)
        }
    }

    /// Use routing to send a message to a client peer address
    pub async fn send_bytes_to(&self, peer_addr: SocketAddr, bytes: Bytes) -> Result<()> {
        self.routing
            .send_message_to_client(peer_addr, bytes)
            .await?;

        Ok(())
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
