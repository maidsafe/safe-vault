// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::node_ops::{NodeDuties, NodeDuty};
use crate::{node::handle_msg::handle, Network, Result};
use hex_fmt::HexFmt;
use log::{debug, info, trace};
use sn_data_types::PublicKey;
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};

/// Process any routing event
pub async fn handle_network_event(
    event: RoutingEvent,
    network_api: Network,
) -> Result<NodeDuties> {
    trace!("Processing Routing Event: {:?}", event);
    match event {
        RoutingEvent::Genesis => Ok(vec![NodeDuty::BeginFormingGenesisSection]),
        RoutingEvent::MemberLeft { name, age } => {
            debug!("A node has left the section. Node: {:?}", name);
            Ok(vec![NodeDuty::ProcessLostMember {
                name: XorName(name.0),
                age,
            }])
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
                return Ok(vec![]);
            }

            info!("New member has joined the section");

            //self.log_node_counts().await;
            if let Some(prev_name) = previous_name {
                trace!("The new member is a Relocated Node");
                let first = NodeDuty::ProcessRelocatedMember {
                    old_node_id: XorName(prev_name.0),
                    new_node_id: XorName(name.0),
                    age,
                };

                // Switch joins_allowed off a new adult joining.
                //let second = NetworkDuty::from(SwitchNodeJoin(false));
                Ok(vec![first]) // , second
            } else {
                //trace!("New node has just joined the network and is a fresh node.",);
                Ok(vec![NodeDuty::ProcessNewMember(XorName(name.0))])
            }
        }
        RoutingEvent::ClientMessageReceived { msg, user } => {
            info!(
                "TODO: Received client message: {:8?}\n Sent from {:?}",
                msg, user
            );
            handle(
                *msg,
                SrcLocation::EndUser(user),
                DstLocation::Node(network_api.our_name().await),
            )
            .await
        }
        RoutingEvent::MessageReceived { content, src, dst } => {
            info!(
                "Received network message: {:8?}\n Sent from {:?} to {:?}",
                HexFmt(&content),
                src,
                dst
            );
            handle(Message::from(content)?, src, dst).await
            // ERR -> LAZY
        }
        RoutingEvent::EldersChanged {
            key,
            elders,
            prefix,
            self_status_change,
            sibling_key,
        } => {
            trace!("******Elders changed event!");
            // let mut duties: NetworkDuties =
            match self_status_change {
                NodeElderChange::None => {
                    // do nothing
                }
                NodeElderChange::Promoted => {
                    if is_forming_genesis(network_api).await {
                        return Ok(vec![NodeDuty::BeginFormingGenesisSection]);
                    } else {
                        // After genesis section formation, any new Elder will be informed
                        // by its peers of data required.
                        // It may also request this if missing.
                        // For now we start with defaults
                        debug!("TODO: FINISH ELDER MAKING");
                        // unimplemented!("PROMOTED");

                        // Ok(NetworkDuties::from(NodeDuty::CompleteTransitionToElder{
                        //     node_rewards: Default::default(),
                        //     section_wallet: WalletInfo {
                        //         replicas:  network_api.public_key_set().await?,
                        //         history: ActorHistory{
                        //             credits: vec![],
                        //             debits: vec![]
                        //         }
                        //     },
                        //     user_wallets: Default::default()
                        // }))
                    }
                }
                NodeElderChange::Demoted => {
                    //TODO: Demotion
                    debug!("TODO: demotion");
                    // NetworkDuties::from(NodeDuty::AssumeAdultDuties)
                }
            };

            let mut sibling_pk = None;
            if let Some(pk) = sibling_key {
                sibling_pk = Some(PublicKey::Bls(pk));
            }
            // TODO: Update elder info.

            // duties.push(NetworkDuty::from(NodeDuty::UpdateElderInfo {
            //     prefix,
            //     key: PublicKey::Bls(key),
            //     elders: elders.into_iter().map(|e| XorName(e.0)).collect(),
            //     sibling_key: sibling_pk,
            // }));

            // Ok(duties)

            Ok(vec![])
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
            Ok(vec![])
        }
        // Ignore all other events
        _ => Ok(vec![]),
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
