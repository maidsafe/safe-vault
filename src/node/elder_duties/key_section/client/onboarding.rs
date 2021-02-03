// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, ElderState};
use crate::{Error, Result};
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, trace};
use sn_data_types::{HandshakeRequest, HandshakeResponse, PublicKey};
use sn_messaging::client::MsgEnvelope;
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
    elder_state: ElderState,
    clients: DashMap<SocketAddr, PublicKey>,
}

impl Onboarding {
    pub fn new(elder_state: ElderState) -> Self {
        Self {
            elder_state,
            clients: Default::default(),
        }
    }

    // /// Handles a received join request from a client.
    // async fn try_join(&self, peer_addr: SocketAddr, client_key: PublicKey) -> Result<()> {
    //     if self.clients.contains_key(&peer_addr) {
    //         info!(
    //             "{}: Client is already accepted..: {} on {}",
    //             self, client_key, peer_addr
    //         );
    //         return Ok(());
    //     }
    //     info!(
    //         "{}: Trying to join..: {} on {}",
    //         self, client_key, peer_addr
    //     );
    //     if self.elder_state.prefix().matches(&client_key.into()) {
    //         Ok(())
    //     } else {
    //         debug!(
    //             "Client {} ({}) wants to join us but we are not its client handler",
    //             client_key, peer_addr
    //         );
    //         Err(Error::Onboarding)
    //     }
    // }

    /// Use routing to send a message to a client peer address
    pub async fn send_message_to(
        &self,
        peer_addr: SocketAddr,
        envelope: MsgEnvelope,
    ) -> Result<()> {
        self.elder_state.send_to_client(peer_addr, envelope).await
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
