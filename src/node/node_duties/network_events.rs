// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::msg_analysis::NetworkMsgAnalysis;
use crate::node::node_ops::{ElderDuty, NodeDuty, NodeOperation};
use bytes::Bytes;
use hex_fmt::HexFmt;
use log::{error, info, trace, warn};
use sn_data_types::{MsgEnvelope, PublicKey};
use sn_routing::event::Event as RoutingEvent;
use xor_name::XorName;

/// Maps events from the transport layer
/// into domain messages for the various modules.
pub struct NetworkEvents {
    analysis: NetworkMsgAnalysis,
}

impl NetworkEvents {
    pub fn new(analysis: NetworkMsgAnalysis) -> Self {
        Self { analysis }
    }

    pub fn process_network_event(&mut self, event: RoutingEvent) -> Option<NodeOperation> {
        use ElderDuty::*;
        use NodeDuty::*;

        trace!("Processing Routing Event: {:?}", event);
        match event {
            RoutingEvent::PromotedToAdult => {
                info!("Node promoted to Adult");
                Some(BecomeAdult.into())
            }
            RoutingEvent::PromotedToElder => {
                info!("Node promoted to Elder");
                Some(BecomeElder.into())
            }
            RoutingEvent::MemberLeft { name, age } => {
                trace!("A node has left the section. Node: {:?}", name);
                Some(
                    ProcessLostMember {
                        name: XorName(name.0),
                        age,
                    }
                    .into(),
                )
            }
            RoutingEvent::InfantJoined { name, .. } => {
                trace!("New node has joined the network");
                Some(ProcessNewMember(XorName(name.0)).into())
            }
            RoutingEvent::MemberJoined {
                name,
                previous_name,
                age,
            } => {
                trace!("New member has joined the section");
                Some(
                    ProcessRelocatedMember {
                        old_node_id: XorName(name.0),
                        new_node_id: XorName(previous_name.0),
                        age,
                    }
                    .into(),
                )
            }
            RoutingEvent::Connected(_) => {
                info!("Node connected.");
                None
            }
            RoutingEvent::MessageReceived { content, src, dst } => {
                info!(
                    "Received network message: {:8?}\n Sent from {:?} to {:?}",
                    HexFmt(&content),
                    src,
                    dst
                );
                self.evaluate_msg(content)
            }
            RoutingEvent::EldersChanged {
                key,
                elders,
                prefix,
            } => Some(
                ProcessElderChange {
                    prefix,
                    key: PublicKey::Bls(key),
                    elders: elders.into_iter().map(|e| XorName(e.0)).collect(),
                }
                .into(),
            ),
            // Ignore all other events
            _ => None,
        }
    }

    fn evaluate_msg(&mut self, content: Bytes) -> Option<NodeOperation> {
        match bincode::deserialize::<MsgEnvelope>(&content) {
            Ok(msg) => {
                warn!("Message Envelope received. Contents: {:?}", &msg);
                self.analysis.evaluate(&msg)
            }
            Err(e) => {
                error!(
                    "Error deserializing received network message into MsgEnvelope type: {:?}",
                    e
                );
                None
            }
        }
    }
}
