// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use super::client_input_parse::{try_deserialize_handshake, try_deserialize_msg};
pub use super::onboarding::Onboarding;
use crate::node::node_ops::MessagingDuty;
use log::{error, info, warn};
use rand::{CryptoRng, Rng};
use safe_nd::{Address, HandshakeRequest, Message, MessageId, MsgEnvelope, PublicKey};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};
use quic_p2p::SendStream;

/// Tracks incoming and outgoingg messages
/// between client and network.
pub struct ClientMsgTracking {
    onboarding: Onboarding,
    tracked_incoming: HashMap<MessageId, SocketAddr>,
    tracked_outgoing: HashMap<MessageId, MsgEnvelope>,
}

impl ClientMsgTracking {
    pub fn new(onboarding: Onboarding) -> Self {
        Self {
            onboarding,
            tracked_incoming: Default::default(),
            tracked_outgoing: Default::default(),
        }
    }

    pub fn get_public_key(&mut self, peer_addr: SocketAddr) -> Option<&PublicKey> {
        self.onboarding.get_public_key(peer_addr)
    }

    pub fn process_handshake<G: CryptoRng + Rng>(
        &mut self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
        stream: &mut SendStream,
        rng: &mut G,
    ) -> Option<MessagingDuty> {
        self.onboarding.process(handshake, peer_addr, stream, rng)
    }

    // pub fn remove_client(&mut self, peer_addr: SocketAddr) {
    //     self.onboarding.remove_client(peer_addr)
    // }

    ///
    pub fn track_incoming(
        &mut self,
        msg_id: MessageId,
        client_address: SocketAddr,
    ) -> Option<MessagingDuty> {
        // We could have received a group decision containing a client msg,
        // before receiving the msg from that client directly.
        if let Some(msg) = self.tracked_outgoing.remove(&msg_id) {
            warn!("Tracking incoming: Prior group decision on msg found.");
            return Some(MessagingDuty::SendToClient {
                address: client_address,
                msg,
            });
        }

        if let Entry::Vacant(ve) = self.tracked_incoming.entry(msg_id) {
            let _ = ve.insert(client_address);
            None
        } else {
            info!(
                "Pending MessageId {:?} reused - ignoring client message.",
                msg_id
            );
            None
        }
    }

    pub fn match_outgoing(&mut self, msg: &MsgEnvelope) -> Option<MessagingDuty> {
        match msg.destination() {
            Address::Client { .. } => (),
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid destination.",
                    self,
                    msg.id()
                );
                return None;
                //return Err(Error::InvalidOperation);
            }
        };
        let correlation_id = match msg.message {
            Message::Event { correlation_id, .. }
            | Message::CmdError { correlation_id, .. }
            | Message::QueryResponse { correlation_id, .. } => correlation_id,
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid message for client.",
                    self,
                    msg.id()
                );
                return None;
                //return Err(Error::InvalidOperation);
            }
        };
        let client_address = match self.tracked_incoming.remove(&correlation_id) {
            Some(address) => address,
            None => {
                info!(
                    "{} for message-id {:?}, Unable to find the client to respond to.",
                    self, correlation_id
                );
                let _ = self.tracked_outgoing.insert(correlation_id, msg.clone());
                return None;
                //return Err(Error::NoSuchKey);
            }
        };

        Some(MessagingDuty::SendToClient {
            address: client_address,
            msg: msg.clone(),
        })
    }
}

impl Display for ClientMsgTracking {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientMsgTracking")
    }
}
