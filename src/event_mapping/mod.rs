// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod map_msg;

use super::node_ops::{NodeDuties, NodeDuty};
use crate::{Error, Network, Result};
use futures::future::Lazy;
use hex_fmt::HexFmt;
use log::{debug, info, trace, warn};
use map_msg::{map_node_msg, match_user_sent_msg};
use sn_data_types::{Msg, PublicKey};
use sn_messaging::{
    client::{Message, ProcessMsg, ProcessingError},
    DstLocation, SrcLocation,
};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
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
    Msg {
        msg: ProcessMsg,
        src: SrcLocation,
    },
    Error {
        msg: ProcessingError,
        src: SrcLocation,
    },
    Bytes {
        msg: bytes::Bytes,
        src: SrcLocation,
    },
}

#[derive(Debug)]
pub struct LazyError {
    pub msg: MsgContext,
    pub error: Error,
}

/// Process any routing event
pub async fn map_routing_event(event: RoutingEvent, network_api: &Network) -> Mapping {
    //trace!("Processing Routing Event: {:?}", event);
    match event {
        RoutingEvent::Genesis => Mapping::Ok {
            op: NodeDuty::BeginFormingGenesisSection,
            ctx: None,
        },
        RoutingEvent::MessageReceived { content, src, dst } => {
            let msg = match Message::from(content.clone()) {
                Ok(msg) => msg,
                Err(error) => {
                    return Mapping::Error(LazyError {
                        msg: MsgContext::Bytes { msg: content, src },
                        error: crate::Error::Message(error),
                    })
                }
            };

            match msg {
                Message::Process(process_msg) => map_node_msg(process_msg, src, dst),
                Message::ProcessingError(error) => {
                    warn!("Processing error received. {:?}", error);
                    Mapping::Error(LazyError {
                        msg: MsgContext::Error {
                            msg: error.clone(),
                            src,
                        },
                        error: Error::ProcessingError(error),
                    })
                }
            }
        }
        RoutingEvent::ClientMessageReceived { msg, user } => match *msg {
            Message::Process(process_msg) => match_user_sent_msg(
                process_msg,
                DstLocation::Node(network_api.our_name().await),
                user,
            ),
            Message::ProcessingError(error) => {
                warn!("Processing error received. {:?}", error);
                Mapping::Error(LazyError {
                    msg: MsgContext::Error {
                        msg: error.clone(),
                        src: SrcLocation::EndUser(user),
                    },
                    error: Error::ProcessingError(error),
                })
            }
        },
        RoutingEvent::EldersChanged {
            prefix,
            key,
            sibling_key,
            elders,
            self_status_change,
        } => {
            match self_status_change {
                NodeElderChange::None => {
                    // sync to others if we are elder
                    let op = if network_api.is_elder().await {
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
                        if are_we_part_of_genesis(network_api).await {
                            NodeDuty::BeginFormingGenesisSection
                        } else {
                            NodeDuty::ChurnMembers {
                                our_prefix: prefix,
                                our_key: PublicKey::from(key),
                                sibling_key: sibling_key.map(PublicKey::from),
                                newbie: false,
                            }
                        }
                    } else {
                        NodeDuty::NoOp
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
                    let our_contact_info = network_api.our_connection_info().await;
                    let _ = crate::config_handler::write_connection_info(our_contact_info)
                        .unwrap_or_else(|err| {
                            log::error!("Unable to write config to disk: {}", err);
                            Default::default()
                        });

                    if are_we_part_of_genesis(network_api).await {
                        Mapping::Ok {
                            op: NodeDuty::BeginFormingGenesisSection,
                            ctx: None,
                        }
                    } else {
                        Mapping::Ok {
                            op: NodeDuty::ChurnMembers {
                                our_prefix: prefix,
                                our_key: PublicKey::from(key),
                                sibling_key: sibling_key.map(PublicKey::from),
                                newbie: true,
                            },
                            ctx: None,
                        }
                    }
                }
                NodeElderChange::Demoted => Mapping::Ok {
                    op: NodeDuty::LevelDown,
                    ctx: None,
                },
            }
        }
        RoutingEvent::MemberLeft { name, age } => {
            debug!("A node has left the section. Node: {:?}", name);
            Mapping::Ok {
                op: NodeDuty::ProcessLostMember {
                    name: XorName(name.0),
                    age,
                },
                ctx: None,
            }
        }
        RoutingEvent::MemberJoined {
            name,
            previous_name,
            age,
            ..
        } => {
            if is_forming_genesis(network_api).await {
                // during formation of genesis we do not process this event
                debug!("Forming genesis so ignore new member");
                return Mapping::Ok {
                    op: NodeDuty::NoOp,
                    ctx: None,
                };
            }

            // info!("New member has joined the section");

            //self.log_node_counts().await;
            if let Some(prev_name) = previous_name {
                trace!("The new member is a Relocated Node");
                // Switch joins_allowed off a new adult joining.
                //let second = NetworkDuty::from(SwitchNodeJoin(false));
                Mapping::Ok {
                    op: NodeDuty::ProcessRelocatedMember {
                        old_node_id: XorName(prev_name.0),
                        new_node_id: XorName(name.0),
                        age,
                    },
                    ctx: None,
                }
            } else {
                //trace!("New node has just joined the network and is a fresh node.",);
                Mapping::Ok {
                    op: NodeDuty::ProcessNewMember(XorName(name.0)),
                    ctx: None,
                }
            }
        }
        RoutingEvent::Relocated { .. } => {
            // Check our current status
            let age = network_api.age().await;
            if age > MIN_AGE {
                info!("Node promoted to Adult");
                info!("Our Age: {:?}", age);
                // return Ok(())
                // Ok(NetworkDuties::from(NodeDuty::AssumeAdultDuties))
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

/// Are we forming the genesis?
async fn is_forming_genesis(network_api: &Network) -> bool {
    let is_genesis_section = network_api.our_prefix().await.is_empty();
    let elder_count = network_api.our_elder_names().await.len();
    let section_chain_len = network_api.section_chain().await.len();
    is_genesis_section
        && elder_count < GENESIS_ELDER_COUNT
        && section_chain_len <= GENESIS_ELDER_COUNT
}

/// Are we the conclusion of genesis?
async fn are_we_part_of_genesis(network_api: &Network) -> bool {
    let is_genesis_section = network_api.our_prefix().await.is_empty();
    let elder_count = network_api.our_elder_names().await.len();
    let section_chain_len = network_api.section_chain().await.len();
    is_forming_genesis(network_api).await
        || (is_genesis_section
            && elder_count == GENESIS_ELDER_COUNT
            && section_chain_len <= GENESIS_ELDER_COUNT)
}
