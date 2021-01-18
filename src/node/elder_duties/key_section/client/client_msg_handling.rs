// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use super::client_input_parse::{try_deserialize_handshake, try_deserialize_msg};
pub use super::onboarding::Onboarding;
use crate::with_chaos;
use crate::{Error, Result};
use dashmap::{mapref::entry::Entry, DashMap};
#[cfg(features = "chaos")]
use log::debug;
use log::{error, info, trace, warn};
use sn_data_types::HandshakeRequest;
use sn_messaging::{Address, Message, MessageId, MsgEnvelope};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Tracks incoming and outgoingg messages
/// between client and network.
pub struct ClientMsgHandling {
    onboarding: Onboarding,
    tracked_incoming: DashMap<MessageId, SocketAddr>,
    tracked_outgoing: DashMap<MessageId, MsgEnvelope>,
}

impl ClientMsgHandling {
    pub fn new(onboarding: Onboarding) -> Self {
        Self {
            onboarding,
            tracked_incoming: Default::default(),
            tracked_outgoing: Default::default(),
        }
    }

    pub async fn process_handshake(
        &self,
        handshake: HandshakeRequest,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        trace!("Processing client handshake");

        with_chaos!({
            debug!("Chaos: Dropping handshake");
            return Ok(());
        });

        let result = self.onboarding.onboard_client(handshake, peer_addr).await;

        result
    }

    /// Track client socket address and msg_id for coordinating responses
    pub async fn track_incoming_message(
        &self,
        msg: &Message,
        client_address: SocketAddr,
    ) -> Result<()> {
        let msg_id = msg.id();

        trace!("Tracking incoming client message {:?}", msg_id);

        with_chaos!({
            debug!("Chaos: Dropping incoming message {:?}", msg_id);
            return Ok(());
        });

        // We could have received a group decision containing a client msg,
        // before receiving the msg from that client directly.
        if let Some((_, msg)) = self.tracked_outgoing.remove(&msg_id) {
            warn!(
                "Tracking incoming: Prior group decision on msg {:?} found.",
                msg_id
            );
            let _ = self.match_outgoing(&msg).await;
        }

        // Keep track of messags to find client target via correlation id
        if let Entry::Vacant(ve) = self.tracked_incoming.entry(msg_id) {
            let _ = ve.insert(client_address);
        } else {
            info!(
                "Pending MessageId {:?} reused - ignoring client message.",
                msg_id
            );
        }
        Ok(())
    }

    pub async fn match_outgoing(&self, msg: &MsgEnvelope) -> Result<()> {
        let msg_id = msg.id();

        trace!("Matching outgoing message {:?}", msg_id);

        match msg.destination()? {
            Address::Client { .. } => (),
            _ => {
                error!("{} for message-id {:?}, Invalid destination.", self, msg_id);
                return Err(Error::InvalidMessage(
                    msg_id,
                    "Address::Client was expected".to_string(),
                ));
            }
        };

        self.send_message_to_client(&msg).await
    }

    async fn send_message_to_client(&self, message: &MsgEnvelope) -> Result<()> {
        let correlation_id = match message.message {
            Message::Event { correlation_id, .. }
            | Message::CmdError { correlation_id, .. }
            | Message::QueryResponse { correlation_id, .. } => correlation_id,
            _ => {
                error!(
                    "{} for message-id {:?}, Invalid message for client.",
                    self,
                    message.id()
                );
                return Err(Error::InvalidMessage(
                    message.id(),
                    "Not a client message".to_string(),
                ));
            }
        };

        trace!("Message outgoing, correlates to {:?}", correlation_id);

        match self.tracked_incoming.remove(&correlation_id) {
            Some((_, client_address)) => {
                let bytes = message.serialize()?;

                trace!("will send message via qp2p");
                self.onboarding.send_bytes_to(client_address, bytes).await
            }
            None => {
                info!(
                        "{} for message-id {:?}, Unable to find client message to respond to. The message may have already been sent to the client previously.",
                        self, correlation_id
                    );

                let _ = self
                    .tracked_outgoing
                    .insert(correlation_id, message.clone());
                return Ok(());
            }
        }
    }
}

impl Display for ClientMsgHandling {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientMsgHandling")
    }
}
