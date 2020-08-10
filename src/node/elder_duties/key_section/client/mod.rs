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
    client_input_parse::{try_deserialize_handshake, try_deserialize_msg},
    client_msg_tracking::ClientMsgTracking,
    onboarding::Onboarding,
};
use crate::{
    node::state_db::NodeInfo,
    node::{
        node_ops::{GatewayDuty, KeySectionDuty, MessagingDuty, NodeOperation},
        section_querying::SectionQuerying,
    },
    utils, Error, Result,
};
use log::{error, info, trace, warn};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use routing::TransportEvent as ClientEvent;
use safe_nd::{Address, MsgEnvelope, MsgSender};
use std::fmt::{self, Display, Formatter};

/// A client gateway routes messages
/// back and forth between a client and the network.
pub struct ClientGateway<R: CryptoRng + Rng> {
    section: SectionQuerying,
    client_msg_tracking: ClientMsgTracking,
    rng: R,
}

impl<R: CryptoRng + Rng> ClientGateway<R> {
    pub fn new(info: NodeInfo, section: SectionQuerying, rng: R) -> Result<Self> {
        let onboarding = Onboarding::new(info.public_key().ok_or(Error::Logic)?, section.clone());
        let client_msg_tracking = ClientMsgTracking::new(onboarding);

        let gateway = Self {
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
                if self
                    .client_msg_tracking
                    .get_public_key(peer.peer_addr())
                    .is_none()
                {
                    info!("{}: Connected to new client on {}", self, peer.peer_addr());
                }
            }
            ConnectionFailure { peer, .. } => {
                self.client_msg_tracking.remove_client(peer.peer_addr());
            }
            NewMessage { peer, msg } => {
                let existing_client = self.client_msg_tracking.get_public_key(peer.peer_addr());
                if let Some(public_key) = existing_client {
                    let msg = try_deserialize_msg(msg)?;
                    info!("Deserialized client msg from {}", public_key);
                    if !validate_client_sig(&msg) {
                        return None;
                    }
                    let result = self
                        .client_msg_tracking
                        .track_incoming(msg.id(), peer.peer_addr());
                    if result.is_some() {
                        return result.map(|c| c.into());
                    }
                    use KeySectionDuty::*;
                    return Some(EvaluateClientMsg(msg).into());
                } else {
                    let hs = try_deserialize_handshake(msg, peer.peer_addr())?;
                    let mut rng = ChaChaRng::from_seed(self.rng.gen());
                    return self
                        .client_msg_tracking
                        .process_handshake(hs, peer.peer_addr(), &mut rng)
                        .map(|c| c.into());
                }
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

fn validate_client_sig(msg: &MsgEnvelope) -> bool {
    let signature = match &msg.origin {
        MsgSender::Client(proof) => proof.signature(),
        _ => return false,
    };
    match msg
        .origin
        .id()
        .verify(&signature, utils::serialise(&msg.message))
    {
        Ok(_) => true,
        Err(error) => {
            warn!(
                "{:?} from {} is invalid: {}",
                msg.message.id(),
                msg.origin.id(),
                error
            );
            false
        }
    }
}

impl<R: CryptoRng + Rng> Display for ClientGateway<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientGateway")
    }
}
