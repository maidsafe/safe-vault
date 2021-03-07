// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::msg_analysis::ReceivedMsgAnalysis;
use crate::node::node_ops::{ElderDuty, NetworkDuties, NetworkDuty, NodeDuty};
use crate::{Network, Result};
use hex_fmt::HexFmt;
use log::{info, trace};
use sn_data_types::PublicKey;
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, NodeElderChange, MIN_AGE};
use xor_name::XorName;

/// Maps events from the transport layer
/// into domain messages for the various modules.
pub struct NetworkEvents {
    analysis: ReceivedMsgAnalysis,
}

impl NetworkEvents {
    pub fn new(analysis: ReceivedMsgAnalysis) -> Self {
        Self { analysis }
    }

    // // Dump elders and adults count
    // async fn log_node_counts(&mut self) {
    //     let elder_count = format!(
    //         "No. of Elders in our Section: {:?}",
    //         self.analysis.no_of_elders().await
    //     );
    //     let adult_count = format!(
    //         "No. of Adults in our Section: {:?}",
    //         self.analysis.no_of_adults().await
    //     );
    //     let separator_len = std::cmp::max(elder_count.len(), adult_count.len());
    //     let separator = std::iter::repeat('-')
    //         .take(separator_len)
    //         .collect::<String>();
    //     info!("--{}--", separator);
    //     info!("| {:<1$} |", elder_count, separator_len);
    //     info!("| {:<1$} |", adult_count, separator_len);
    //     info!("--{}--", separator);
    // }

    pub async fn process_network_event(
        &mut self,
        event: RoutingEvent,
        network: &Network,
    ) -> Result<NetworkDuties> {
        use ElderDuty::*;
        //trace!("Processing Routing Event: {:?}", event);
        match event {
            RoutingEvent::MemberLeft { name, age } => {
                trace!("A node has left the section. Node: {:?}", name);
                //self.log_node_counts().await;
                Ok(NetworkDuties::from(ProcessLostMember {
                    name: XorName(name.0),
                    age,
                }))
            }
            RoutingEvent::MemberJoined {
                name,
                previous_name,
                age,
                ..
            } => {
                //info!("New member has joined the section");
                //self.log_node_counts().await;
                if let Some(prev_name) = previous_name {
                    trace!("The new member is a Relocated Node");
                    let first = NetworkDuty::from(ProcessRelocatedMember {
                        old_node_id: XorName(prev_name.0),
                        new_node_id: XorName(name.0),
                        age,
                    });

                    // Switch joins_allowed off a new adult joining.
                    //let second = NetworkDuty::from(SwitchNodeJoin(false));
                    Ok(vec![first]) // , second
                } else {
                    //trace!("New node has just joined the network and is a fresh node.",);
                    Ok(NetworkDuties::from(ProcessNewMember(XorName(name.0))))
                }
            }
            RoutingEvent::ClientMessageReceived { msg, user } => {
                info!("Received client message: {:8?}\n Sent from {:?}", msg, user);
                self.analysis.evaluate(
                    *msg,
                    SrcLocation::EndUser(user),
                    DstLocation::Node(self.analysis.name()),
                )
            }
            RoutingEvent::MessageReceived { content, src, dst } => {
                // info!(
                //     "Received network message: {:8?}\n Sent from {:?} to {:?}",
                //     HexFmt(&content),
                //     src,
                //     dst
                // );
                self.analysis.evaluate(Message::from(content)?, src, dst)
            }
            RoutingEvent::EldersChanged {
                key,
                previous_key,
                elders,
                prefix,
                self_status_change,
                sibling_key,
            } => {
                let mut duties: NetworkDuties = match self_status_change {
                    NodeElderChange::Promoted => NetworkDuties::from(NodeDuty::AssumeElderDuties {
                        new_key: PublicKey::Bls(key),
                        previous_key: PublicKey::Bls(previous_key),
                    }),
                    NodeElderChange::Demoted => NetworkDuties::from(NodeDuty::AssumeAdultDuties),
                    NodeElderChange::None => vec![],
                };

                let mut sibling_pk = None;
                if let Some(pk) = sibling_key {
                    sibling_pk = Some(PublicKey::Bls(pk));
                }

                duties.push(NetworkDuty::from(NodeDuty::InitiateElderChange {
                    prefix,
                    key: PublicKey::Bls(key),
                    elders: elders.into_iter().map(|e| XorName(e.0)).collect(),
                    sibling_key: sibling_pk,
                }));

                Ok(duties)
            }
            RoutingEvent::Relocated { .. } => {
                // Check our current status
                let age = network.age().await;
                if age > MIN_AGE {
                    info!("Node promoted to Adult");
                    info!("Our Age: {:?}", age);
                    Ok(NetworkDuties::from(NodeDuty::AssumeAdultDuties))
                } else {
                    info!("Our AGE: {:?}", age);
                    Ok(vec![])
                }
            }
            // Ignore all other events
            _ => Ok(vec![]),
        }
    }
}
