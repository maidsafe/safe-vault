// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client_msg;
mod node_msg;

use crate::{
    network::Network,
    node_ops::{MsgType, NodeDuty, OutgoingLazyError},
};
use client_msg::map_client_msg;
use log::{debug, error, info, trace, warn};
use node_msg::map_node_msg;
use sn_data_types::PublicKey;
use sn_messaging::{
    client::{Error as ErrorMessage, ProcessingError},
    node::NodeMsg,
    MessageId, SrcLocation,
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
pub struct MsgContext {
    pub msg: MsgType,
    pub src: SrcLocation,
}

// Process any routing event
pub async fn map_routing_event(event: RoutingEvent, network_api: &Network) -> Mapping {
    info!("Handling RoutingEvent: {:?}", event);
    match event {
        RoutingEvent::MessageReceived {
            content, src, dst, ..
        } => match NodeMsg::from(content) {
            Ok(msg) => map_node_msg(msg, src, dst),
            Err(error) => {
                warn!("Error decoding msg bytes, sent from {:?}", src);

                // We generate a random message id here since we cannot
                // retrieve the message id from the message received
                let msg_id = MessageId::new();

                Mapping {
                    op: NodeDuty::SendError(OutgoingLazyError {
                        msg: ProcessingError::new(
                            Some(ErrorMessage::Serialization(format!(
                                "Could not deserialize Message at node: {:?}",
                                error
                            ))),
                            None,
                            msg_id,
                        ),
                        dst: src.to_dst(),
                    }),
                    ctx: None,
                }
            }
        },
        RoutingEvent::ClientMsgReceived { msg, user } => map_client_msg(&msg, user),
        RoutingEvent::SectionSplit {
            elders,
            sibling_elders,
            self_status_change,
        } => {
            let newbie = match self_status_change {
                NodeElderChange::None => false,
                NodeElderChange::Promoted => true,
                NodeElderChange::Demoted => {
                    error!("This should be unreachable, as there would be no demotions of Elders during a split.");
                    return Mapping {
                        op: NodeDuty::NoOp,
                        ctx: None,
                    };
                }
            };
            Mapping {
                op: NodeDuty::SectionSplit {
                    our_prefix: elders.prefix,
                    our_key: PublicKey::from(elders.key),
                    our_new_elders: elders.added,
                    their_new_elders: sibling_elders.added,
                    sibling_key: PublicKey::from(sibling_elders.key),
                    newbie,
                },
                ctx: None,
            }
        }
        RoutingEvent::EldersChanged {
            elders,
            self_status_change,
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
                                if elders.key == pk_set.public_key() {
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
                    Mapping {
                        op: NodeDuty::EldersChanged {
                            our_prefix: elders.prefix,
                            our_key: PublicKey::from(elders.key),
                            new_elders: elders.added,
                            newbie: false,
                        },
                        ctx: None,
                    }
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

                    Mapping {
                        op: NodeDuty::EldersChanged {
                            our_prefix: elders.prefix,
                            our_key: PublicKey::from(elders.key),
                            new_elders: elders.added,
                            newbie: true,
                        },
                        ctx: None,
                    }
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
        RoutingEvent::AdultsChanged {
            remaining,
            added,
            removed,
        } => Mapping {
            op: NodeDuty::AdultsChanged {
                remaining,
                added,
                removed,
            },
            ctx: None,
        },
        // Ignore all other events
        _ => Mapping {
            op: NodeDuty::NoOp,
            ctx: None,
        },
    }
}

pub async fn log_network_stats(network_api: &Network) {
    debug!(
        "{:?}: {:?} Elders, {:?} Adults.",
        network_api.our_prefix().await,
        network_api.our_elder_names().await.len(),
        network_api.our_adults().await.len()
    );
}
