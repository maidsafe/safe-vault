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
use crate::{Error, Network, Result};
use bytes::Bytes;
use hex_fmt::HexFmt;
use log::{error, info, trace};
use sn_data_types::PublicKey;
use sn_messaging::MsgEnvelope;
use sn_routing::{Event as RoutingEvent, NodeElderChange, MIN_AGE};
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

    // Dump elders and adults count
    async fn log_node_counts(&mut self) {
        let elder_count = format!(
            "No. of Elders in our Section: {:?}",
            self.analysis.no_of_elders().await
        );
        let adult_count = format!(
            "No. of Adults in our Section: {:?}",
            self.analysis.no_of_adults().await
        );
        let separator_len = std::cmp::max(elder_count.len(), adult_count.len());
        let separator = std::iter::repeat('-')
            .take(separator_len)
            .collect::<String>();
        info!("--{}--", separator);
        info!("| {:<1$} |", elder_count, separator_len);
        info!("| {:<1$} |", adult_count, separator_len);
        info!("--{}--", separator);
    }

    pub async fn process_network_event(
        &mut self,
        event: RoutingEvent,
        network: &Network,
    ) -> Result<NodeOperation> {
        use ElderDuty::*;

        trace!("Processing Routing Event: {:?}", event);
        match event {
            RoutingEvent::MemberLeft { name, age } => {
                trace!("A node has left the section. Node: {:?}", name);
                self.log_node_counts().await;
                Ok(ProcessLostMember {
                    name: XorName(name.0),
                    age,
                }
                .into())
            }
            RoutingEvent::MemberJoined {
                name,
                previous_name,
                age,
                ..
            } => {
                info!("New member has joined the section");
                self.log_node_counts().await;
                if let Some(prev_name) = previous_name {
                    trace!("The new member is a Relocated Node");
                    let first: NodeOperation = ProcessRelocatedMember {
                        old_node_id: XorName(prev_name.0),
                        new_node_id: XorName(name.0),
                        age,
                    }
                    .into();

                    // Switch joins_allowed off a new adult joining.
                    let second: NodeOperation = SwitchNodeJoin(false).into();
                    Ok(vec![first, second].into())
                } else {
                    trace!("New node has just joined the network and is a fresh node.",);
                    Ok(ProcessNewMember(XorName(name.0)).into())
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
                self_status_change,
            } => {
                let mut ops = Vec::new();
                match self_status_change {
                    NodeElderChange::Promoted => ops.push(self.duty_cfg.setup_as_elder().await?),
                    NodeElderChange::Demoted => {
                        let age = network.age().await;
                        if age > MIN_AGE {
                            info!("Node promoted to Adult");
                            info!("Our Age: {:?}", age);
                            ops.push(self.duty_cfg.setup_as_adult()?);
                        } else {
                            info!("We are not Adult, do nothing");
                            info!("Our Age: {:?}", age);
                        }
                    }
                    NodeElderChange::None => {
                        trace!("Node status has not changed");
                    }
                }
                ops.push(
                    ProcessElderChange {
                        prefix,
                        key: PublicKey::Bls(key),
                        elders: elders.into_iter().map(|e| XorName(e.0)).collect(),
                    }
                    .into(),
                );
                Ok(ops.into())
            }
            RoutingEvent::Relocated { .. } => {
                // Check our current status
                let age = network.age().await;
                if age > MIN_AGE {
                    info!("Node promoted to Adult");
                    info!("Our Age: {:?}", age);
                    self.duty_cfg.setup_as_adult()
                } else {
                    info!("Our AGE: {:?}", age);
                    Ok(NodeOperation::NoOp)
                }
            }
            // Ignore all other events
            _ => Ok(NodeOperation::NoOp),
        }
    }

    async fn evaluate_msg(&mut self, content: Bytes) -> Result<NodeOperation> {
        match MsgEnvelope::from(content) {
            Ok(msg) => {
                info!("Message Envelope received. Contents: {:?}", &msg);
                self.analysis.evaluate(&msg).await
            }
            Err(e) => {
                error!(
                    "Error deserializing received network message into MsgEnvelope type: {:?}",
                    e
                );
                Err(Error::Logic(format!(
                    "Error deserializing network msg into MsgEnvelope: {:?}",
                    e
                )))
            }
        }
    }
}
