// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use super::client_input_parse::{try_deserialize_handshake, try_deserialize_msg};
pub use super::onboarding::Onboarding;
use crate::node::node_ops::NodeMessagingDuty;
use crate::utils;
use crate::with_chaos;
use crate::{Error, Result};
use log::{error, info, trace, warn};
use rand::{CryptoRng, Rng};
use sn_data_types::{Address, HandshakeRequest, Message, MessageId, MsgEnvelope, PublicKey};
use sn_routing::event::SendStream;
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Tracks incoming and outgoingg messages
/// between client and network.
pub struct ClientMsgHandling {
    onboarding: Onboarding,
    notification_streams: HashMap<PublicKey, Vec<SendStream>>,
    tracked_incoming: HashMap<MessageId, (SocketAddr, SendStream)>,
    tracked_outgoing: HashMap<MessageId, MsgEnvelope>,
}

impl ClientMsgHandling {
    pub fn new(onboarding: Onboarding) -> Self {
        Self {
            onboarding,
            notification_streams: Default::default(),
            tracked_incoming: Default::default(),
            tracked_outgoing: Default::default(),
        }
    }

    pub fn get_public_key(&mut self, peer_addr: SocketAddr) -> Option<&PublicKey> {
        self.onboarding.get_public_key(peer_addr)
    }

    pub async fn process_handshake<G: CryptoRng + Rng>(
        &mut self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
        stream: SendStream,
        rng: &mut G,
    ) -> Result<()> {
        trace!("Processing client handshake");
        let mut the_stream = stream;

        with_chaos!({
            debug!("Chaos: Dropping handshake");
            return Ok(());
        });

        let result = self
            .onboarding
            .onboard_client(handshake, peer_addr, &mut the_stream, rng)
            .await;

        // client has been onboarded or already exists
        if result.is_ok() {
            trace!("Client has been onboarded.");
            if let Some(pk) = self.get_public_key(peer_addr) {
                let mut updated_streams = vec![];
                let pk = *pk;

                // let's append to any existing known streams for this PK
                if let Some(current_streams_for_pk) = self.notification_streams.remove(&pk) {
                    updated_streams = current_streams_for_pk;
                }

                updated_streams.push(the_stream);
                let _ = self.notification_streams.insert(pk, updated_streams);
            } else {
                warn!(
                    "No PK found for onboarded peer at address : {:?}",
                    peer_addr
                );
            }
        }

        result
    }

    // pub fn remove_client(&mut self, peer_addr: SocketAddr) {
    //     self.onboarding.remove_client(peer_addr)
    // }

    ///
    pub async fn track_incoming(
        &mut self,
        msg: &Message,
        client_address: SocketAddr,
        stream: SendStream,
    ) -> Option<NodeMessagingDuty> {
        trace!("Tracking incoming client message");

        let msg_id = msg.id();

        // We could have received a group decision containing a client msg,
        // before receiving the msg from that client directly.
        if let Some(msg) = self.tracked_outgoing.remove(&msg_id) {
            warn!("Tracking incoming: Prior group decision on msg found.");

            let _ = self.match_outgoing(&msg).await;
        }

        if let Entry::Vacant(ve) = self.tracked_incoming.entry(msg_id) {
            let _ = ve.insert((client_address, stream));
            None
        } else {
            info!(
                "Pending MessageId {:?} reused - ignoring client message.",
                msg_id
            );
            None
        }
    }

    pub async fn match_outgoing(&mut self, msg: &MsgEnvelope) -> Result<()> {
        trace!("Matching outgoing message");

        match msg.destination() {
            Address::Client { .. } => (),
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid destination.",
                    self,
                    msg.id()
                );
                return Err(Error::InvalidMessage);
            }
        };
        let (is_query_response, correlation_id) = match msg.message {
            Message::Event { correlation_id, .. } | Message::CmdError { correlation_id, .. } => {
                (false, correlation_id)
            }
            Message::QueryResponse { correlation_id, .. } => (true, correlation_id),
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid message for client.",
                    self,
                    msg.id()
                );
                return Err(Error::InvalidMessage);
            }
        };

        trace!("Message outgoing, correlates to {:?}", correlation_id);
        // Query responses are sent on the stream from the connection.
        // Events/CmdErrors are sent to the held stream from the bootstrap process.
        match self.tracked_incoming.remove(&correlation_id) {
            Some((peer_addr, mut stream)) => {
                if is_query_response {
                    trace!("Sending QueryResponse on request's stream");
                    send_message_on_stream(&msg, &mut stream).await
                } else {
                    trace!("Attempting to use bootstrap stream");
                    if let Some(pk) = self.get_public_key(peer_addr) {
                        let pk = *pk;
                        // get the streams and ownership
                        if let Some(streams) = self.notification_streams.remove(&pk) {
                            let mut used_streams = vec![];
                            for mut stream in streams {
                                // send to each registered stream for that PK
                                send_message_on_stream(&msg, &mut stream).await;
                                used_streams.push(stream);
                            }

                            let _ = self.notification_streams.insert(pk, used_streams);
                        } else {
                            error!("Could not find stream for Message response")
                        }
                    } else {
                        error!("Could not find PublicKey for Message response")
                    }
                }
            }
            None => {
                info!(
                        "{} for message-id {:?}, Unable to find client message to respond to. The message may have already been sent to the client previously.",
                        self, correlation_id
                    );

                let _ = self.tracked_outgoing.insert(correlation_id, msg.clone());
                return Ok(());
            }
        }
        Ok(())
    }
}

async fn send_message_on_stream(message: &MsgEnvelope, stream: &mut SendStream) {
    trace!("Sending message on stream");
    let bytes = utils::serialise(message);

    let res = stream.send(bytes).await;

    match res {
        Ok(()) => info!("Message sent successfully to client via stream"),
        Err(error) => error!(
            "There was an error sending client message on the stream:  {:?}",
            error
        ),
    };
}

impl Display for ClientMsgHandling {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientMsgHandling")
    }
}
