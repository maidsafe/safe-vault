// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::node_ops::MessagingDuty, Network};
use log::{info, trace, warn};

use sn_data_types::{Address, MsgEnvelope};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Sending of messages to clients.
pub(super) struct ClientSender {
    routing: Network,
}

impl ClientSender {
    pub fn new(routing: Network) -> Self {
        Self { routing }
    }

    pub async fn send(
        &mut self,
        _recipient: SocketAddr,
        msg: &MsgEnvelope,
    ) -> Option<MessagingDuty> {
        trace!("Attempting to send at clientSender");
        match msg.destination() {
            Address::Node(_) => Some(MessagingDuty::SendToNode(msg.clone())),
            Address::Section(_) => Some(MessagingDuty::SendToSection(msg.clone())),
            Address::Client(_) => None,
        }
    }
}

impl Display for ClientSender {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ClientSender")
    }
}
