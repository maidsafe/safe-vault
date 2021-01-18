// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node::node_ops::{GatewayDuty, NodeMessagingDuty, NodeOperation},
    Error, Network, Result,
};
use log::{error, info};
use sn_messaging::{Address, MsgEnvelope};
use sn_routing::{DstLocation, SrcLocation};
use std::collections::BTreeSet;
use xor_name::XorName;

/// Sending of msgs to other nodes in the network.
pub(super) struct NetworkSender {
    network: Network,
}

impl NetworkSender {
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    pub async fn send_to_client(
        &mut self,
        msg: MsgEnvelope,
        as_node: bool,
    ) -> Result<NodeOperation> {
        let dst = match msg.destination()? {
            Address::Client(xorname) => xorname,
            Address::Node(_) => return Ok(NodeMessagingDuty::SendToNode(msg).into()),
            Address::Section(_) => {
                return Ok(NodeMessagingDuty::SendToSection { msg, as_node }.into())
            }
        };
        if self.network.matches_our_prefix(dst).await {
            Ok(GatewayDuty::FindClientFor(msg).into())
        } else {
            Ok(NodeMessagingDuty::SendToSection { msg, as_node }.into())
        }
    }

    pub async fn send_to_node(&mut self, msg: MsgEnvelope, as_node: bool) -> Result<NodeOperation> {
        let name = self.network.name().await;
        let dst = match msg.destination()? {
            Address::Node(xorname) => DstLocation::Node(xorname),
            Address::Section(_) => {
                return Ok(NodeMessagingDuty::SendToSection { msg, as_node }.into())
            }
            Address::Client(_) => return self.send_to_client(msg, as_node).await,
        };

        let result = self
            .network
            .send_message(SrcLocation::Node(name), dst, msg.serialize()?)
            .await;

        result.map_or_else(
            |err| {
                error!("Unable to send MsgEnvelope to Peer: {:?}", err);
                Err(Error::Logic(format!(
                    "{:?}: Unable to send Msg to Peer",
                    msg.id()
                )))
            },
            |()| {
                info!("Sent MsgEnvelope to Peer {:?} from node {:?}", dst, name);
                Ok(NodeOperation::NoOp)
            },
        )
    }

    pub async fn send_to_nodes(
        &mut self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Result<NodeOperation> {
        let name = self.network.name().await;
        let bytes = &msg.serialize()?;
        for target in targets {
            self.network
                .send_message(
                    SrcLocation::Node(name),
                    DstLocation::Node(XorName(target.0)),
                    bytes.clone(),
                )
                .await
                .map_or_else(
                    |err| {
                        error!("Unable to send MsgEnvelope to Peer: {:?}", err);
                    },
                    |()| {
                        info!("Sent MsgEnvelope to Peer {:?} from node {:?}", target, name);
                    },
                );
        }
        Ok(NodeOperation::NoOp)
    }

    pub async fn send_to_network(
        &mut self,
        msg: MsgEnvelope,
        as_node: bool,
    ) -> Result<NodeOperation> {
        let dst = match msg.destination()? {
            Address::Node(xorname) => DstLocation::Node(xorname),
            Address::Client(xorname) | Address::Section(xorname) => DstLocation::Section(xorname),
        };
        info!("Destination: {:?}", dst);
        let src = if as_node {
            SrcLocation::Node(self.network.name().await)
        } else {
            SrcLocation::Section(self.network.our_prefix().await)
        };
        let result = self.network.send_message(src, dst, msg.serialize()?).await;

        result.map_or_else(
            |err| {
                error!("Unable to send to section: {:?}", err);
                Err(Error::Logic(format!(
                    "{:?}: Unable to send to section",
                    msg.id()
                )))
            },
            |()| {
                info!("Sent to section with: {:?}", msg);
                Ok(NodeOperation::NoOp)
            },
        )
    }
}
