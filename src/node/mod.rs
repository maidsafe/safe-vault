// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod economy;
pub mod state_db;

mod adult_duties;
mod elder_duties;
mod keys;
mod msg_wrapping;
mod node_duties;
mod node_ops;
mod section_querying;

pub use crate::node::node_duties::messaging::Receiver;
pub use crate::node::state_db::{Command, Init};
use crate::{
    node::{
        keys::NodeKeys,
        node_duties::{messaging::Received, NodeDuties},
        node_ops::{GatewayDuty, NetworkDuty, NodeDuty, NodeOperation},
        state_db::{read_state, AgeGroup, NodeInfo},
    },
    Config, Result,
};
use log::{info, warn};
use rand::{CryptoRng, Rng};
use routing::Node as Routing;
use safe_nd::NodeKeypairs;
use std::{
    cell::RefCell,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    rc::Rc,
};

/// Main node struct.
pub struct Node<R: CryptoRng + Rng> {
    duties: NodeDuties<R>,
    receiver: Receiver,
    routing: Rc<RefCell<Routing>>,
}

impl<R: CryptoRng + Rng> Node<R> {
    /// Initialize a new node.
    pub fn new(
        receiver: Receiver,
        routing: Rc<RefCell<Routing>>,
        config: &Config,
        mut rng: R,
    ) -> Result<Self> {
        let root_dir_buf = config.root_dir()?;
        let root_dir = root_dir_buf.as_path();

        let (age_group, keypairs) = read_state(&root_dir)?.unwrap_or_else(|| {
            let keypairs = NodeKeypairs::new(&mut rng);
            (Infant, keypairs)
        });

        let keypairs = Rc::new(RefCell::new(keypairs));
        let keys = NodeKeys::new(keypairs.clone());

        let node_info = NodeInfo {
            keys,
            root_dir: root_dir_buf,
            init_mode: Init::New,
            /// Upper limit in bytes for allowed network storage on this node.
            /// An Adult would be using the space for chunks,
            /// while an Elder uses it for metadata.
            max_storage_capacity: config.max_capacity(),
        };

        let mut duties = NodeDuties::new(keypairs, node_info, routing.clone(), rng);

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

        Ok(node)
    }

    /// Returns our connection info.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.routing
            .borrow_mut()
            .our_connection_info()
            .map_err(From::from)
    }

    /// Returns whether routing node is in elder state.
    pub fn is_elder(&mut self) -> bool {
        self.routing.borrow().is_elder()
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
                    info!("Received a Client Event from quic-p2p: {:?}", event);
                    ProcessClientEvent(event).into()
                }
                Received::Network(event) => {
                    info!("Received a Network Event from routing: {:?}", event);
                    ProcessNetworkEvent(event).into()
                }
                Received::Unknown(channel) => {
                    if let Err(err) = self
                        .routing
                        .borrow_mut()
                        .handle_selected_operation(channel.index)
                    {
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
                info!("Handling Adult duty: {:?}", duty);
                self.duties.adult_duties()?.process(&duty)
            }
            RunAsElder(duty) => {
                info!("Handling Elder duty: {:?}", duty);
                self.duties.elder_duties()?.process(duty)
            }
            RunAsNode(duty) => {
                info!("Handling Node duty: {:?}", duty);
                self.duties.process(duty)
            }
        }
    }
}

impl<R: CryptoRng + Rng> Display for Node<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.duties.id())
    }
}
