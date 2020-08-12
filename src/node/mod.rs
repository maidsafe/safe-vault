// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod state_db;

mod adult_duties;
mod elder_duties;
mod keys;
mod msg_wrapping;
mod node_duties;
mod node_ops;

pub use crate::node::node_duties::messaging::Receiver;
pub use crate::node::state_db::{Command, Init};
use crate::{
    node::{
        keys::NodeSigningKeys,
        node_duties::{messaging::Received, NodeDuties},
        node_ops::{GatewayDuty, NetworkDuty, NodeDuty, NodeOperation},
        state_db::{get_age_group, store_age_group, store_new_reward_keypair, AgeGroup, NodeInfo},
    },
    Config, Network, Result,
};
use bls::SecretKey;
use log::{info, warn};
use rand::{CryptoRng, Rng};
use safe_nd::PublicKey;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Main node struct.
pub struct Node<R: CryptoRng + Rng> {
    duties: NodeDuties<R>,
    receiver: Receiver,
    routing: Network,
}

impl<R: CryptoRng + Rng> Node<R> {
    /// Initialize a new node.
    pub fn new(receiver: Receiver, routing: Network, config: &Config, rng: R) -> Result<Self> {
        let root_dir_buf = config.root_dir()?;
        let root_dir = root_dir_buf.as_path();

        let reward_key = match config.wallet_address() {
            Some(public_key) => PublicKey::Bls(state_db::pk_from_hex(public_key)?),
            None => {
                let secret = SecretKey::random();
                let public = secret.public_key();
                store_new_reward_keypair(root_dir, &secret, &public)?;
                PublicKey::Bls(public)
            }
        };
        let age_group = get_age_group(&root_dir)?.unwrap_or_else(|| {
            let age_group = Infant;
            store_age_group(root_dir, age_group.clone()).unwrap_or(());
            age_group
        });

        let keys = NodeSigningKeys::new(routing.clone());

        let node_info = NodeInfo {
            keys,
            root_dir: root_dir_buf,
            init_mode: Init::New,
            /// Upper limit in bytes for allowed network storage on this node.
            /// An Adult would be using the space for chunks,
            /// while an Elder uses it for metadata.
            max_storage_capacity: config.max_capacity(),
        };

        let mut duties = NodeDuties::new(node_info, routing.clone(), rng);

        use AgeGroup::*;
        let _ = match age_group {
            Infant => None,
            Adult => duties.process(node_ops::NodeDuty::BecomeAdult),
            Elder => duties.process(node_ops::NodeDuty::BecomeElder),
        };

        let node = Self {
            duties,
            receiver,
            routing,
        };

        node.register(reward_key);

        Ok(node)
    }

    fn register(&self, _reward_key: PublicKey) {}

    /// Returns our connection info.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.routing.our_connection_info().map_err(From::from)
    }

    /// Returns whether routing node is in elder state.
    pub fn is_elder(&mut self) -> bool {
        self.routing.is_elder()
    }

    /// Starts the node, and runs the main event loop.
    /// Blocks until the node is terminated, which is done
    /// by client sending in a `Command` to free it.
    pub fn run(&mut self) {
        use GatewayDuty::*;
        use NodeDuty::*;
        loop {
            let result = match self.receiver.next_event() {
                Received::Client(event) => {
                    info!("Received a Client Event from quic-p2p.");
                    ProcessClientEvent(event).into()
                }
                Received::Network(event) => {
                    info!("Received a Network Event from routing: {:?}", event);
                    ProcessNetworkEvent(event).into()
                }
                Received::Unknown(channel) => {
                    if let Err(err) = self.routing.handle_selected_operation(channel.index) {
                        warn!("Could not process operation: {}", err);
                    }
                    continue;
                }
                Received::Shutdown => break,
            };
            self.process_while_any(Some(result));
        }
    }

    /// Keeps processing resulting node operations.
    fn process_while_any(&mut self, op: Option<NodeOperation>) {
        use NodeOperation::*;
        let mut next_op = op;
        while let Some(op) = next_op {
            next_op = match op {
                Single(operation) => self.process(operation),
                Multiple(ops) => Some(
                    ops.into_iter()
                        .filter_map(|c| self.process(c))
                        .collect::<Vec<_>>()
                        .into(),
                ),
                None => break,
            }
        }
    }

    fn process(&mut self, duty: NetworkDuty) -> Option<NodeOperation> {
        use NetworkDuty::*;
        match duty {
            RunAsAdult(duty) => {
                info!("Running as Adult: {:?}", duty);
                self.duties.adult_duties()?.process(&duty)
            }
            RunAsElder(duty) => {
                info!("Running as Elder: {:?}", duty);
                self.duties.elder_duties()?.process(duty)
            }
            RunAsNode(duty) => {
                info!("Running as Node: {:?}", duty);
                self.duties.process(duty)
            }
        }
    }
}

impl<R: CryptoRng + Rng> Display for Node<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
