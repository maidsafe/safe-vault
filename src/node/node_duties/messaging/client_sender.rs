// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{network::Routing, node::node_ops::MessagingDuty, utils};
use bytes::Bytes;
use log::{info, warn};
use safe_nd::{Address, HandshakeResponse, MsgEnvelope};
use serde::Serialize;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Sending of messages to clients.
pub(super) struct ClientSender<R: Routing + Clone> {
    routing: R,
}

impl<R: Routing + Clone> ClientSender<R> {
    pub fn new(routing: R) -> Self {
        Self { routing }
    }

    pub fn send(&mut self, recipient: SocketAddr, msg: &MsgEnvelope) -> Option<MessagingDuty> {
        match msg.destination() {
            Address::Node(_) => Some(MessagingDuty::SendToNode(msg.clone())),
            Address::Section(_) => Some(MessagingDuty::SendToSection(msg.clone())),
            Address::Client(_) => self.send_any_to_client(recipient, msg),
        }
    }

    pub fn handshake(
        &mut self,
        recipient: SocketAddr,
        hs: &HandshakeResponse,
    ) -> Option<MessagingDuty> {
        self.send_any_to_client(recipient, hs)
    }

    pub fn disconnect(&mut self, peer_addr: SocketAddr) -> Option<MessagingDuty> {
        if let Err(err) = self.routing.disconnect_from_client(peer_addr) {
            warn!("{}: Could not disconnect client: {:?}", self, err);
        }

        info!("{}: Disconnected from {}", self, peer_addr);

        None
    }

    fn send_any_to_client<T: Serialize>(
        &mut self,
        recipient: SocketAddr,
        msg: &T,
    ) -> Option<MessagingDuty> {
        let msg = utils::serialise(msg);
        let bytes = Bytes::from(msg);

        if let Err(e) = self.routing.send_message_to_client(recipient, bytes) {
            warn!(
                "{}: Could not send message to client {}: {:?}",
                self, recipient, e
            );
        }
        None
    }
}

impl<R: Routing + Clone> Display for ClientSender<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientSender")
    }
}
