// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client_msg;
mod node_msg;

use super::node_ops::{NodeDuty, OutgoingMsg};
use crate::{error::convert_to_error_message, network::Network, Error};
use client_msg::map_client_msg;
use log::{info, trace};
use node_msg::map_node_msg;
use sn_data_types::PublicKey;
use sn_messaging::{
    client::{CmdError, Message},
    Aggregation, MessageId, SrcLocation,
};
use sn_routing::XorName;
use sn_routing::{Event as RoutingEvent, NodeElderChange, MIN_AGE};
use std::{thread::sleep, time::Duration};

#[derive(Debug)]
pub struct Mapping {
    pub op: NodeDuty,
    pub ctx: Option<MsgContext>,
}

#[derive(Debug, Clone)]
pub enum MsgContext {
    Msg { msg: Message, src: SrcLocation },
    Bytes { msg: bytes::Bytes, src: SrcLocation },
}

/// Process any routing event
pub async fn map_routing_event(event: RoutingEvent, network_api: &Network) -> Mapping {
    info!("Handling RoutingEvent: {:?}", event);
    match event {
        RoutingEvent::MessageReceived {
            content, src, dst, ..
        } => match Message::from(content.clone()) {
            Ok(msg) => map_node_msg(msg, src, dst),
            Err(error) => {
                // We generate a message id here since we cannot
                // retrieve the message id from the message received
                let msg_id = MessageId::from_content(&content).unwrap_or_else(|_| MessageId::new());
                let error_data = convert_to_error_message(Error::Message(error));

                Mapping {
                    ctx: Some(MsgContext::Bytes { msg: content, src }),
                    op: NodeDuty::Send(OutgoingMsg {
                        msg: Message::CmdError {
                            error: CmdError::Data(error_data),
                            id: MessageId::in_response_to(&msg_id),
                            correlation_id: msg_id,
                        },
                        section_source: false, // strictly this is not correct, but we don't expect responses to an error..
                        dst: src.to_dst(),
                        aggregation: Aggregation::None,
                    }),
                }
            }
        },
        RoutingEvent::ClientMessageReceived { msg, user } => map_client_msg(*msg, user),
        RoutingEvent::EldersChanged {
            prefix,
            key,
            sibling_key,
            self_status_change,
            ..
        } => {
            log_network_stats(network_api).await;
            let first_section = network_api.our_prefix().await.is_empty();
            let first_elder = network_api.our_elder_names().await.len() == 1;
            if first_section && first_elder {
                return Mapping {
                    op: NodeDuty::Genesis,
                    ctx: None,
                };
            }

            match self_status_change {
                NodeElderChange::None => {
                    if !network_api.is_elder().await {
                        return Mapping {
                            op: NodeDuty::NoOp,
                            ctx: None,
                        };
                    }
                    // sync to others if we are elder
                    // -- ugly temporary until fixed in routing --
                    let mut sanity_counter = 0_i32;
                    while sanity_counter < 240 {
                        match network_api.our_public_key_set().await {
                            Ok(pk_set) => {
                                if key == pk_set.public_key() {
                                    break;
                                } else {
                                    trace!("******Elders changed, we are still Elder but we seem to be lagging the DKG...");
                                }
                            }
                            Err(e) => {
                                trace!(
                                    "******Elders changed, should NOT be an error here...! ({:?})",
                                    e
                                );
                                sanity_counter += 1;
                            }
                        }
                        sleep(Duration::from_millis(500))
                    }
                    // -- ugly temporary until fixed in routing --

                    trace!("******Elders changed, we are still Elder");
                    let op = if let Some(sibling_key) = sibling_key {
                        NodeDuty::SectionSplit {
                            our_prefix: prefix,
                            our_key: PublicKey::from(key),
                            sibling_key: PublicKey::from(sibling_key),
                            newbie: false,
                        }
                    } else {
                        NodeDuty::EldersChanged {
                            our_prefix: prefix,
                            our_key: PublicKey::from(key),
                            newbie: false,
                        }
                    };
                    Mapping { op, ctx: None }
                }
                NodeElderChange::Promoted => {
                    // -- ugly temporary until fixed in routing --
                    let mut sanity_counter = 0_i32;
                    while network_api.our_public_key_set().await.is_err() {
                        if sanity_counter > 240 {
                            trace!("******Elders changed, we were promoted, but no key share found, so skip this..");
                            return Mapping {
                                op: NodeDuty::NoOp,
                                ctx: None,
                            };
                        }
                        sanity_counter += 1;
                        trace!("******Elders changed, we are promoted, but still no key share..");
                        sleep(Duration::from_millis(500))
                    }
                    // -- ugly temporary until fixed in routing --

                    trace!("******Elders changed, we are promoted");
                    let op = if let Some(sibling_key) = sibling_key {
                        NodeDuty::SectionSplit {
                            our_prefix: prefix,
                            our_key: PublicKey::from(key),
                            sibling_key: PublicKey::from(sibling_key),
                            newbie: true,
                        }
                    } else {
                        NodeDuty::EldersChanged {
                            our_prefix: prefix,
                            our_key: PublicKey::from(key),
                            newbie: true,
                        }
                    };
                    Mapping { op, ctx: None }
                }
                NodeElderChange::Demoted => Mapping {
                    op: NodeDuty::LevelDown,
                    ctx: None,
                },
            }
        }
        RoutingEvent::MemberLeft { name, age } => {
            log_network_stats(network_api).await;
            Mapping {
                op: NodeDuty::ProcessLostMember {
                    name: XorName(name.0),
                    age,
                },
                ctx: None,
            }
        }
        RoutingEvent::MemberJoined { previous_name, .. } => {
            log_network_stats(network_api).await;
            let op = if previous_name.is_some() {
                trace!("A relocated node has joined the section.");
                // Switch joins_allowed off a new adult joining.
                NodeDuty::SetNodeJoinsAllowed(false)
            } else if network_api.our_prefix().await.is_empty() {
                NodeDuty::NoOp
            } else {
                NodeDuty::SetNodeJoinsAllowed(false)
            };
            Mapping { op, ctx: None }
        }
        RoutingEvent::Relocated { .. } => {
            // Check our current status
            let age = network_api.age().await;
            if age > MIN_AGE {
                info!("Relocated, our Age: {:?}", age);
            }
            Mapping {
                op: NodeDuty::NoOp,
                ctx: None,
            }
        }
        RoutingEvent::AdultsChanged(adults) => {
            let op = NodeDuty::AdultsChanged(adults);
            Mapping { op, ctx: None }
        }
        // Ignore all other events
        _ => Mapping {
            op: NodeDuty::NoOp,
            ctx: None,
        },
    }
}

pub async fn log_network_stats(network_api: &Network) {
    info!("Our section: {:?}", network_api.our_prefix().await);
    info!(
        "No. of Elders: {:?}",
        network_api.our_elder_names().await.len()
    );
    info!("No. of Adults: {:?}", network_api.our_adults().await.len());
}
