// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod network_sender;

use crate::node::node_ops::{NodeMessagingDuty, NodeOperation};
use crate::{Network, Outcome};
use log::info;
use network_sender::NetworkSender;

/// Sending of messages
/// to nodes and clients in the network.
pub struct Messaging {
    network_sender: NetworkSender,
}

impl Messaging {
    pub fn new(routing: Network) -> Self {
        let network_sender = NetworkSender::new(routing);
        Self { network_sender }
    }

    pub async fn process_messaging_duty(
        &mut self,
        duty: NodeMessagingDuty,
    ) -> Outcome<NodeOperation> {
        use NodeMessagingDuty::*;
        info!("Sending message: {:?}", duty);
        match duty {
            SendToClient(msg) => self.network_sender.send_to_client(msg, true).await,
            SendToNode(msg) => self.network_sender.send_to_node(msg, true).await,
            SendToSection { msg, as_node } => {
                self.network_sender.send_to_network(msg, as_node).await
            }
            SendToAdults { targets, msg } => self.network_sender.send_to_nodes(targets, &msg).await,
        }
    }
}
