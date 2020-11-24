// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::msg_analysis::NetworkMsgAnalysis;
use crate::node::{
    duty_cfg::DutyConfig,
    node_ops::{ElderDuty, NodeOperation},
};
use crate::Network;
use bytes::Bytes;
use hex_fmt::HexFmt;
use log::{error, info, trace, warn};
use sn_data_types::{MsgEnvelope, PublicKey};
use sn_routing::{Event as RoutingEvent, MIN_AGE};
use xor_name::XorName;

/// Maps events from the transport layer
/// into domain messages for the various modules.
pub struct NetworkEvents {
    duty_cfg: DutyConfig,
    analysis: NetworkMsgAnalysis,
}

impl NetworkEvents {
    pub fn new(duty_cfg: DutyConfig, analysis: NetworkMsgAnalysis) -> Self {
        Self { duty_cfg, analysis }
    }

    pub async fn process_network_event(
        &mut self,
        event: RoutingEvent,
        network: &Network,
    ) -> Option<NodeOperation> {
        use ElderDuty::*;

        trace!("Processing Routing Event: {:?}", event);
        match event {
            RoutingEvent::PromotedToElder => {
                info!("Node promoted to Elder");
                self.duty_cfg.setup_as_elder().await
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
            RoutingEvent::MemberJoined {
                name,
                previous_name,
                age,
                startup_relocation,
            } => {
                trace!("New member has joined the section");
                if startup_relocation {
                    trace!("New node has joined the network");
                    Some(ProcessNewMember(XorName(name.0)).into())
                } else if let Some(prev_name) = previous_name {
                    Some(
                        ProcessRelocatedMember {
                            old_node_id: XorName(prev_name.0),
                            new_node_id: XorName(name.0),
                            age,
                        }
                        .into(),
                    )
                } else {
                    None
                }
            }
            RoutingEvent::MessageReceived { content, src, dst } => {
                info!(
                    "Received network message: {:8?}\n Sent from {:?} to {:?}",
                    HexFmt(&content),
                    src,
                    dst
                );
                self.evaluate_msg(content).await
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
            RoutingEvent::Relocated { .. } => {
                // Check our current status
                let age = network.age().await;
                if age > MIN_AGE {
                    info!("Node promoted to Adult");
                    info!("Our Age: {:?}", age);
                    self.duty_cfg.setup_as_adult()
                } else {
                    info!("Our AGE: {:?}", age);
                    None
                }
            }
            RoutingEvent::Demoted => {
                let age = network.age().await;
                if age > MIN_AGE {
                    info!("Node promoted to Adult");
                    info!("Our Age: {:?}", age);
                    self.duty_cfg.setup_as_adult()
                } else {
                    info!("We are not Adult, do nothing");
                    info!("Our Age: {:?}", age);
                    None
                }
            }
            // Ignore all other events
            _ => None,
        }
    }

    async fn evaluate_msg(&mut self, content: Bytes) -> Option<NodeOperation> {
        match bincode::deserialize::<MsgEnvelope>(&content) {
            Ok(msg) => {
                warn!("Message Envelope received. Contents: {:?}", &msg);
                self.analysis.evaluate(&msg).await
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
