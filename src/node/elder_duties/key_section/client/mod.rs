// Copyright 2021 MaidSafe.net limited.
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
    node::NodeInfo,
    ElderState, Error, Result,
};
use log::{error, trace, warn};
use sn_data_types::Error as DtError;
use sn_messaging::{Address, MsgEnvelope};
use sn_routing::Event as RoutingEvent;
use std::fmt::{self, Display, Formatter};

/// A client gateway routes messages
/// back and forth between a client and the network.
pub struct ClientGateway {
    client_msg_handling: ClientMsgHandling,
    elder_state: ElderState,
}

impl ClientGateway {
    pub async fn new(_info: &NodeInfo, elder_state: ElderState) -> Result<Self> {
        let onboarding = Onboarding::new(elder_state.clone());
        let client_msg_handling = ClientMsgHandling::new(onboarding);

        let gateway = Self {
            client_msg_handling,
            elder_state,
        };

        Ok(gateway)
    }

    pub async fn process_as_gateway(&self, cmd: GatewayDuty) -> Result<NodeOperation> {
        trace!("Processing as gateway");
        use GatewayDuty::*;
        match cmd {
            FindClientFor(msg) => self.try_find_client(&msg).await,
            ProcessClientEvent(event) => self.process_client_event(event).await,
            NoOp => Ok(NodeOperation::NoOp),
        }
    }

    async fn try_find_client(&self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        trace!("trying to find client...");
        if let Address::Client(xorname) = &msg.destination()? {
            if self.elder_state.prefix().matches(xorname) {
                trace!("Message matches gateway prefix");
                let _ = self.client_msg_handling.match_outgoing(msg).await;
                return Ok(NodeOperation::NoOp);
            }
        }
        Ok(NodeMessagingDuty::SendToSection {
            msg: msg.clone(),
            as_node: true,
        }
        .into())
    }

    /// This is where client input is parsed.
    async fn process_client_event(&self, event: RoutingEvent) -> Result<NodeOperation> {
        trace!("Processing client event");
        match event {
            RoutingEvent::ClientMessageReceived { content, src, .. } => {
                // This check was about checking we knew and client was valid... but even if we don't
                // we should be handling it...
                match try_deserialize_handshake(&content, src) {
                    Ok(hs) => {
                        let _ = self.client_msg_handling.process_handshake(hs, src).await;
                        Ok(NodeOperation::NoOp)
                    }
                    Err(_e) => {
                        // this is not a handshake, so lets try processing as client message...
                        trace!(
                            "Message is not a handshake, so let's process it as client message..."
                        );
                        let msg = try_deserialize_msg(content)?;

                        trace!("Deserialized client msg is {:?}", msg.message);
                        if !validate_client_sig(&msg) {
                            return Err(Error::NetworkData(DtError::InvalidSignature));
                        }

                        match self
                            .client_msg_handling
                            .track_incoming_message(&msg.message, src)
                            .await
                        {
                            Ok(()) => Ok(KeySectionDuty::EvaluateClientMsg(msg).into()),
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            other => {
                error!("NOT SUPPORTED YET: {:?}", other);
                Err(Error::Logic(
                    "Event not supported in Client event processing".to_string(),
                ))
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

impl Display for ClientGateway {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientGateway")
    }
}
