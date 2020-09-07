// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod client_sender;
pub mod network_sender;

use crate::node::node_ops::{MessagingDuty, NodeOperation};
use crate::Network;
use client_sender::ClientSender;
use log::info;
use network_sender::NetworkSender;

/// Sending of messages
/// to nodes and clients in the network.
pub struct Messaging {
    client_sender: ClientSender,
    network_sender: NetworkSender,
}

impl Messaging {
    pub fn new(routing: Network) -> Self {
        let client_sender = ClientSender::new(routing.clone());
        let network_sender = NetworkSender::new(routing);
        Self {
            client_sender,
            network_sender,
        }
    }

    pub async fn process(&mut self, duty: MessagingDuty) -> Option<NodeOperation> {
        use MessagingDuty::*;
        info!("Sending message: {:?}", duty);
        let result = match duty {
            SendToClient { address, msg } => self.client_sender.send(address, &msg).await,
            SendToNode(msg) => self.network_sender.send_to_node(msg).await,
            SendToSection(msg) => self.network_sender.send_to_network(msg).await,
            SendToAdults { targets, msg } => self.network_sender.send_to_nodes(targets, &msg).await,
            SendHandshake { address, response} => {
                self.client_sender.handshake(address, &response).await
            }
            DisconnectClient(_address) => None, // TODO: self.client_sender.disconnect(address),
        };

        result.map(|c| c.into())
    }
}
