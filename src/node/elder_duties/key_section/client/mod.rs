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
    node::node_ops::{GatewayDuty, KeySectionDuty, MessagingDuty, NodeOperation},
    node::state_db::NodeInfo,
    utils, Error, Network, Result,
};
use log::{error, info, warn};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use routing::{event::Event as RoutingEvent, SrcLocation};
use safe_nd::{Address, MsgEnvelope, MsgSender};
use std::fmt::{self, Display, Formatter};

/// A client gateway routes messages
/// back and forth between a client and the network.
pub struct ClientGateway<R: CryptoRng + Rng> {
    client_msg_tracking: ClientMsgTracking,
    rng: R,
    routing: Network,
}

impl<R: CryptoRng + Rng> ClientGateway<R> {
    pub fn new(info: NodeInfo, routing: Network, rng: R) -> Result<Self> {
        let onboarding = Onboarding::new(info.public_key().ok_or(Error::Logic)?, routing.clone());
        let client_msg_tracking = ClientMsgTracking::new(onboarding);

        let gateway = Self {
            client_msg_tracking,
            rng,
            routing,
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
            if self.routing.matches_our_prefix(*xorname) {
                return self.client_msg_tracking.match_outgoing(msg);
            }
        }
        Some(MessagingDuty::SendToSection(msg.clone()))
    }

    /// This is where client input is parsed.
    fn process_client_event(&mut self, event: &RoutingEvent) -> Option<NodeOperation> {
        match event {
            RoutingEvent::MessageReceived {
                content,
                src: SrcLocation::Client(addr),
                ..
            } => {
                let existing_client = self.client_msg_tracking.get_public_key(*addr);
                if let Some(public_key) = existing_client {
                    let msg = try_deserialize_msg(content)?;
                    info!("Deserialized client msg from {}", public_key);
                    if !validate_client_sig(&msg) {
                        return None;
                    }
                    match self.client_msg_tracking.track_incoming(msg.id(), *addr) {
                        Some(c) => Some(c.into()),
                        None => Some(KeySectionDuty::EvaluateClientMsg(msg).into()),
                    }
                } else {
                    let hs = try_deserialize_handshake(content, *addr)?;
                    let mut rng = ChaChaRng::from_seed(self.rng.gen());
                    self.client_msg_tracking
                        .process_handshake(hs, *addr, &mut rng)
                        .map(|c| c.into())
                }
            }
            other => {
                error!("NOT SUPPORTED YET: {:?}", other);
                None
            }
        }
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
