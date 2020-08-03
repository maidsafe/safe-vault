// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client_input_parse;
mod client_msg_tracking;
mod onboarding;
use self::{
    client_input_parse::{try_deserialize_handshake, try_deserialize_msg, ClientInput},
    client_msg_tracking::ClientMsgTracking,
    onboarding::Onboarding,
};
use crate::{
    node::keys::NodeKeys,
    node::state_db::NodeInfo,
    node::{
        node_ops::{GatewayDuty, KeySectionDuty, MessagingDuty, NodeOperation},
        section_querying::SectionQuerying,
    },
    Result,
};
use log::{error, info, trace};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use routing::TransportEvent as ClientEvent;
use safe_nd::{Address, MsgEnvelope};
use std::fmt::{self, Display, Formatter};

/// A client gateway routes messages
/// back and forth between a client and the network.
pub struct ClientGateway<R: CryptoRng + Rng> {
    keys: NodeKeys,
    section: SectionQuerying,
    client_msg_tracking: ClientMsgTracking,
    rng: R,
}

impl<R: CryptoRng + Rng> ClientGateway<R> {
    pub fn new(info: NodeInfo, section: SectionQuerying, rng: R) -> Result<Self> {
        let onboarding = Onboarding::new(info.public_id(), section.clone());
        let client_msg_tracking = ClientMsgTracking::new(info.public_id(), onboarding);

        let gateway = Self {
            keys: info.keys,
            section,
            client_msg_tracking,
            rng,
        };

        Ok(gateway)
    }

    pub fn process(&mut self, cmd: &GatewayDuty) -> Option<NodeOperation> {
        use GatewayDuty::*;
        match cmd {
            FindClientFor(msg) => self.try_find_client(msg).map(|c| c.into()),
            ProcessClientEvent(event) => self.process_client_event(event),
        }
    }

    fn try_find_client(&mut self, msg: &MsgEnvelope) -> Option<MessagingDuty> {
        if let Address::Client(xorname) = &msg.destination() {
            if self.section.handles(&xorname) {
                return self.client_msg_tracking.match_outgoing(msg);
            }
        }
        Some(MessagingDuty::SendToSection(msg.clone()))
    }

    /// This is where client input is parsed.
    fn process_client_event(&mut self, event: &ClientEvent) -> Option<NodeOperation> {
        use ClientEvent::*;
        match event {
            ConnectedTo { peer } => {
                if !self.client_msg_tracking.contains(peer.peer_addr()) {
                    info!("{}: Connected to new client on {}", self, peer.peer_addr());
                }
            }
            ConnectionFailure { peer, .. } => {
                self.client_msg_tracking.remove_client(peer.peer_addr());
            }
            NewMessage { peer, msg } => {
                let parsed = if self.client_msg_tracking.contains(peer.peer_addr()) {
                    try_deserialize_msg(msg)
                } else {
                    try_deserialize_handshake(msg, peer.peer_addr())
                }?;

                let parsed = match parsed {
                    ClientInput::Msg(msg) => {
                        let result = self
                            .client_msg_tracking
                            .track_incoming(msg.id(), peer.peer_addr());
                        if result.is_some() {
                            return result.map(|c| c.into());
                        }
                        msg
                    }
                    ClientInput::Handshake(request) => {
                        let mut rng = ChaChaRng::from_seed(self.rng.gen());
                        return self
                            .client_msg_tracking
                            .process_handshake(request, peer.peer_addr(), &mut rng)
                            .map(|c| c.into());
                    }
                };
                use KeySectionDuty::*;
                return Some(
                    EvaluateClientMsg {
                        public_id: parsed.public_id,
                        msg: parsed.msg,
                    }
                    .into(),
                );
            }
            SentUserMessage { peer, .. } => {
                trace!(
                    "{}: Succesfully sent Message to: {}",
                    self,
                    peer.peer_addr()
                );
            }
            UnsentUserMessage { peer, .. } => {
                info!("{}: Could not send message to: {}", self, peer.peer_addr());
            }
            BootstrapFailure | BootstrappedTo { .. } => {
                error!("Unexpected bootstrapping client event")
            }
            Finish => {
                info!("{}: Received Finish event", self);
            }
        }
        None
    }
}

impl<R: CryptoRng + Rng> Display for ClientGateway<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.keys.public_key())
    }
}
