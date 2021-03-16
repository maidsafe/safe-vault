// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod map_msg;

use super::node_ops::{NodeDuties, NodeDuty};
use crate::{Network, Result};
use hex_fmt::HexFmt;
use log::{debug, info, trace};
use map_msg::{map_node_msg, match_user_sent_msg};
use sn_data_types::PublicKey;
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};

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
pub async fn map_routing_event(event: RoutingEvent, network_api: Network) -> Mapping {
    trace!("Processing Routing Event: {:?}", event);
    match event {
        RoutingEvent::Genesis => Mapping::Ok {
            op: NodeDuty::BeginFormingGenesisSection,
            ctx: None,
        },
        RoutingEvent::MessageReceived { content, src, dst } => {
            info!(
                "Received network message: {:8?}\n Sent from {:?} to {:?}",
                HexFmt(&content),
                src,
                dst
            );

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
        RoutingEvent::ClientMessageReceived { msg, user } => {
            info!(
                "TODO: Received client message: {:8?}\n Sent from {:?}",
                msg, user
            );
            match_user_sent_msg(
                *msg.clone(),
                DstLocation::Node(network_api.our_name().await),
                user,
            )
        }
        RoutingEvent::EldersChanged {
            elders,
            sibling_elders,
            self_status_change,
        } => {
            trace!("******Elders changed event!");
            match self_status_change {
                NodeElderChange::None => {
                    // sync to others if we are elder
                    let op = if network_api.is_elder().await {
                        NodeDuty::ChurnMembers {
                            elders,
                            sibling_elders,
                        }
                    } else {
                        NodeDuty::NoOp
                    };
                    Mapping::Ok { op, ctx: None }
                }
                NodeElderChange::Promoted => {
                    if is_forming_genesis(network_api).await {
                        Mapping::Ok {
                            op: NodeDuty::BeginFormingGenesisSection,
                            ctx: None,
                        }
                    } else {
                        Mapping::Ok {
                            op: NodeDuty::LevelUp,
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

            info!("New member has joined the section");

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
async fn is_forming_genesis(network_api: Network) -> bool {
    let is_genesis_section = network_api.our_prefix().await.is_empty();
    let elder_count = network_api.our_elder_names().await.len();
    let section_chain_len = network_api.section_chain().await.len();
    is_genesis_section
        && elder_count <= GENESIS_ELDER_COUNT
        && section_chain_len <= GENESIS_ELDER_COUNT
}
