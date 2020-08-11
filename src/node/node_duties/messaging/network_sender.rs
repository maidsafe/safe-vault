// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{network::Routing, node::node_ops::MessagingDuty, utils};
use log::{error, info};
use routing::{DstLocation, SrcLocation};
use safe_nd::{Address, MsgEnvelope};
use std::collections::BTreeSet;
use xor_name::XorName;

/// Sending of msgs to other nodes in the network.
pub(super) struct NetworkSender<R: Routing + Clone> {
    routing: R,
}

impl<R: Routing + Clone> NetworkSender<R> {
    pub fn new(routing: R) -> Self {
        Self { routing }
    }

    pub fn send_to_node(&mut self, msg: MsgEnvelope) -> Option<MessagingDuty> {
        let name = *self.routing.id().name();
        let dst = match msg.destination() {
            Address::Node(xorname) => DstLocation::Node(XorName(xorname.0)),
            Address::Section(_) => return Some(MessagingDuty::SendToSection(msg)),
            Address::Client(_) => return None,
        };
        self.routing
            .send_message(SrcLocation::Node(name), dst, utils::serialise(&msg))
            .map_or_else(
                |err| {
                    error!("Unable to send MsgEnvelope to Peer: {:?}", err);
                    None
                },
                |()| {
                    info!("Sent MsgEnvelope to Peer {:?} from node {:?}", dst, name);
                    None
                },
            )
    }

    pub fn send_to_nodes(
        &mut self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Option<MessagingDuty> {
        let name = *self.routing.id().name();
        for target in targets {
            self.routing
                .send_message(
                    SrcLocation::Node(name),
                    DstLocation::Node(XorName(target.0)),
                    utils::serialise(&msg),
                )
                .map_or_else(
                    |err| {
                        error!("Unable to send MsgEnvelope to Peer: {:?}", err);
                    },
                    |()| {
                        info!("Sent MsgEnvelope to Peer {:?} from node {:?}", target, name);
                    },
                );
        }
        None
    }

    pub fn send_to_network(&mut self, msg: MsgEnvelope) -> Option<MessagingDuty> {
        let name = *self.routing.id().name();
        let dst = match msg.destination() {
            Address::Node(xorname) => DstLocation::Node(XorName(xorname.0)),
            Address::Client(xorname) | Address::Section(xorname) => {
                DstLocation::Section(XorName(xorname.0))
            }
        };
        self.routing
            .send_message(SrcLocation::Node(name), dst, utils::serialise(&msg))
            .map_or_else(
                |err| {
                    error!("Unable to send to section: {:?}", err);
                    None
                },
                |()| {
                    info!("Sent to section with: {:?}", msg);
                    None
                },
            )
    }
}
