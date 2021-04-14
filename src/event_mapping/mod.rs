// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod map_msg;

use super::node_ops::{NodeDuties, NodeDuty};
use crate::{network::Network, Result};
use hex_fmt::HexFmt;
use log::{debug, info, trace};
use map_msg::{map_node_msg, match_user_sent_msg};
use sn_data_types::PublicKey;
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use std::collections::HashSet;
use std::{thread::sleep, time::Duration};

#[derive(Debug)]
pub enum Mapping {
    Ok {
        op: NodeDuty,
        ctx: Option<MsgContext>,
    },
    Error(LazyError),
}

#[derive(Debug, Clone)]
pub enum MsgContext {
    Msg { msg: Message, src: SrcLocation },
    Bytes { msg: bytes::Bytes, src: SrcLocation },
}

#[derive(Debug)]
pub struct LazyError {
    pub msg: MsgContext,
    pub error: crate::Error,
}

/// Process any routing event
pub async fn map_routing_event(event: RoutingEvent, network_api: &Network) -> Mapping {
    info!("Handling RoutingEvent: {:?}", event);
    match event {
        RoutingEvent::MessageReceived {
            content, src, dst, ..
        } => {
            let msg = match Message::from(content.clone()) {
                Ok(msg) => msg,
                Err(error) => {
                    return Mapping::Error(LazyError {
                        msg: MsgContext::Bytes { msg: content, src },
                        error: crate::Error::Message(error),
                    })
                }
            };

            map_node_msg(msg, src, dst)
        }
        RoutingEvent::ClientMessageReceived { msg, user } => match_user_sent_msg(
            *msg.clone(),
            DstLocation::Node(network_api.our_name().await),
            user,
        ),
        RoutingEvent::EldersChanged {
            prefix,
            key,
            sibling_key,
            elders,
            self_status_change,
        } => {
            let first_section = network_api.our_prefix().await.is_empty();
            let first_elder = network_api.our_elder_names().await.len() == 1;
            if first_section && first_elder {
                return Mapping::Ok {
                    op: NodeDuty::Genesis,
                    ctx: None,
                };
            }
            match self_status_change {
                NodeElderChange::None => {
                    if !network_api.is_elder().await {
                        return Mapping::Ok {
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
                                trace!("******Elders changed, should NOT be an error here...!");
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
                    Mapping::Ok { op, ctx: None }
                }
                NodeElderChange::Promoted => {
                    // -- ugly temporary until fixed in routing --
                    let mut sanity_counter = 0_i32;
                    while network_api.our_public_key_set().await.is_err() {
                        if sanity_counter > 240 {
                            trace!("******Elders changed, we were promoted, but no key share found, so skip this..");
                            return Mapping::Ok {
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
                    Mapping::Ok { op, ctx: None }
                }
                NodeElderChange::Demoted => Mapping::Ok {
                    op: NodeDuty::LevelDown,
                    ctx: None,
                },
            }
        }
        RoutingEvent::MemberLeft { name, age } => Mapping::Ok {
            op: NodeDuty::ProcessLostMember {
                name: XorName(name.0),
                age,
            },
            ctx: None,
        },
        RoutingEvent::MemberJoined {
            name,
            previous_name,
            age,
            ..
        } => {
            let op = if let Some(prev_name) = previous_name {
                trace!("A relocated node has joined the section.");
                // Switch joins_allowed off a new adult joining.
                NodeDuty::SetNodeJoinsAllowed(false)
            } else if network_api.our_prefix().await.is_empty() {
                NodeDuty::NoOp
            } else {
                NodeDuty::SetNodeJoinsAllowed(false)
            };
            Mapping::Ok { op, ctx: None }
        }
        RoutingEvent::Relocated { .. } => {
            // Check our current status
            let age = network_api.age().await;
            if age > MIN_AGE {
                info!("Relocated, our Age: {:?}", age);
            }
            Mapping::Ok {
                op: NodeDuty::NoOp,
                ctx: None,
            }
        }
        // Ignore all other events
        _ => Mapping::Ok {
            op: NodeDuty::NoOp,
            ctx: None,
        },
    }
}
