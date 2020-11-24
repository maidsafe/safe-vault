// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client_input_parse;
mod client_msg_handling;
mod onboarding;
use self::{
    client_input_parse::{try_deserialize_handshake, try_deserialize_msg},
    client_msg_handling::ClientMsgHandling,
    onboarding::Onboarding,
};
use crate::{
    node::node_ops::{GatewayDuty, KeySectionDuty, NodeMessagingDuty, NodeOperation},
    node::state_db::NodeInfo,
    Network, Result,
};
use log::{error, info, trace, warn};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use sn_data_types::{Address, MsgEnvelope};
use sn_routing::Event as RoutingEvent;
use std::fmt::{self, Display, Formatter};

/// A client gateway routes messages
/// back and forth between a client and the network.
pub struct ClientGateway<R: CryptoRng + Rng> {
    client_msg_handling: ClientMsgHandling,
    rng: R,
    routing: Network,
}

impl<R: CryptoRng + Rng> ClientGateway<R> {
    pub async fn new(info: &NodeInfo, routing: Network, rng: R) -> Result<Self> {
        let onboarding = Onboarding::new(info.public_key().await, routing.clone());
        let client_msg_handling = ClientMsgHandling::new(onboarding);

        let gateway = Self {
            client_msg_handling,
            rng,
            routing,
        };

        Ok(gateway)
    }

    pub async fn process_as_gateway(&mut self, cmd: GatewayDuty) -> Option<NodeOperation> {
        trace!("Processing as gateway");
        use GatewayDuty::*;
        match cmd {
            FindClientFor(msg) => self.try_find_client(&msg).await.map(|c| c.into()),
            ProcessClientEvent(event) => self.process_client_event(event).await,
        }
    }

    async fn try_find_client(&mut self, msg: &MsgEnvelope) -> Option<NodeMessagingDuty> {
        trace!("trying to find client...");
        if let Address::Client(xorname) = &msg.destination().ok()? {
            if self.routing.matches_our_prefix(*xorname).await {
                trace!("Message matches gateway prefix");
                let _ = self.client_msg_handling.match_outgoing(msg).await;

                return None;
            }
        }
        Some(NodeMessagingDuty::SendToSection {
            msg: msg.clone(),
            as_node: true,
        })
    }

    /// This is where client input is parsed.
    async fn process_client_event(&mut self, event: RoutingEvent) -> Option<NodeOperation> {
        trace!("Processing client event");
        match event {
            RoutingEvent::ClientMessageReceived {
                content, src, send, ..
            } => {
                let existing_client = self.client_msg_handling.get_public_key(src);
                if let Some(public_key) = existing_client {
                    let msg = try_deserialize_msg(&content)?;
                    info!("Deserialized client msg from {}", public_key);
                    trace!("Deserialized client msg is {:?}", msg.message);
                    if !validate_client_sig(&msg) {
                        return None;
                    }
                    match self
                        .client_msg_handling
                        .track_incoming(&msg.message, src, send)
                        .await
                    {
                        Some(c) => Some(c.into()),
                        None => Some(KeySectionDuty::EvaluateClientMsg(msg).into()),
                    }
                } else {
                    let hs = try_deserialize_handshake(&content, src)?;
                    let mut rng = ChaChaRng::from_seed(self.rng.gen());
                    let _ = self
                        .client_msg_handling
                        .process_handshake(hs, src, send, &mut rng)
                        .await;

                    None
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
    if !msg.origin.is_client() {
        return false;
    }
    let verification = msg.verify();
    if let Ok(true) = verification {
        true
    } else {
        warn!(
            "Msg {:?} from {:?} is invalid. Verification: {:?}",
            msg.message.id(),
            msg.origin.address().xorname(),
            verification
        );
        false
    }
}

impl<R: CryptoRng + Rng> Display for ClientGateway<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientGateway")
    }
}
