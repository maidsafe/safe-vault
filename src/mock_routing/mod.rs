// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub use routing::{
    event,
    rng::{self, MainRng},
    FullId, P2pNode, RoutingError, SrcLocation, TransportConfig, TransportEvent,
};

use bytes::Bytes;
use crossbeam_channel::{self as mpmc, Receiver, RecvError, Select, Sender};
use log::trace;
use mock_quic_p2p::{self as quic_p2p, Peer, QuicP2p, QuicP2pError};
use routing::{event::Event, XorName};
use std::{
    cell::RefCell,
    collections::HashSet,
    net::SocketAddr,
    rc::{Rc, Weak},
};
use unwrap::unwrap;

/// Consensus group reference
pub type ConsensusGroupRef = Rc<RefCell<ConsensusGroup>>;

// TODO reexport quic_p2p::Token from routing as Token and use it from routing like rest of the
// types above
/// Token for sending messages
pub type Token = u64;

/// Consensus
pub struct ConsensusGroup {
    consensused: HashSet<Vec<u8>>,
    event_channels: Vec<Sender<Event>>,
}

impl ConsensusGroup {
    /// Creates a new consensus group.
    pub fn new() -> ConsensusGroupRef {
        Rc::new(RefCell::new(Self {
            consensused: Default::default(),
            event_channels: Vec::new(),
        }))
    }

    fn vote_for(&mut self, event: Vec<u8>) {
        if self.consensused.insert(event.clone()) {
            for channel in &self.event_channels {
                unwrap!(channel.send(Event::Consensus(event.clone())));
            }
        }
    }

    /// Promote the vaults in the concensus group to elders.
    pub fn promote_all(&self) {
        for channel in &self.event_channels {
            unwrap!(channel.send(Event::Promoted));
        }
    }
}

/// Node configuration.
pub struct NodeConfig {
    /// If true, configures the node to start a new network instead of joining an existing one.
    pub first: bool,
    /// The ID of the node or `None` for randomly generated one.
    pub full_id: Option<FullId>,
    /// Configuration for the underlying network transport.
    pub transport_config: TransportConfig,
    /// Global network parameters. Must be identical for all nodes in the network.
    pub network_params: NetworkParams,
    /// Random number generator to be used by the node. Can be used to achieve repeatable tests by
    /// providing a pre-seeded RNG. By default uses a random seed provided by the OS.
    pub rng: MainRng,
    /// Specifies if the node should be an elder or not
    pub is_elder: bool,
    /// Concensus group of the node
    pub concensus_group: Option<ConsensusGroupRef>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            first: false,
            full_id: None,
            transport_config: TransportConfig::default(),
            network_params: NetworkParams::default(),
            rng: rng::new(),
            is_elder: false,
            concensus_group: None,
        }
    }
}

/// Network parameters: number of elders, safe section size
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkParams {
    /// The number of elders per section
    pub elder_size: usize,
    /// Minimum number of nodes we consider safe in a section
    pub safe_section_size: usize,
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full routing node.
pub struct Node {
    events_tx: Sender<Event>,
    quic_p2p: QuicP2p,
    network_node_rx: Receiver<TransportEvent>,
    network_node_rx_idx: usize,
    consensus_group: Option<Weak<RefCell<ConsensusGroup>>>,
    is_elder: bool,
}

impl Node {
    /// Create a new routing Node with the specified configuration
    pub fn new(config: NodeConfig) -> (Node, Receiver<Event>, Receiver<TransportEvent>) {
        let (quic_p2p, network_node_rx, network_client_rx) =
            unwrap!(setup_quic_p2p(&Default::default()));

        let (events_tx, events_rx) = mpmc::unbounded();

        let consensus_group = if let Some(group) = config.concensus_group {
            group.borrow_mut().event_channels.push(events_tx.clone());

            Some(Rc::downgrade(&group))
        } else {
            None
        };

        (
            Node {
                network_node_rx,
                quic_p2p,
                events_tx,
                network_node_rx_idx: 0,
                consensus_group,
                is_elder: config.is_elder,
            },
            events_rx,
            network_client_rx,
        )
    }

    /// Initialise the routing node.
    ///
    /// Registering of interests with the event loop will happen here. Without this routing will
    /// not be able to take part in the event loop triggers.
    pub fn register<'a>(&'a mut self, sel: &mut Select<'a>) {
        self.network_node_rx_idx = sel.recv(&self.network_node_rx);
    }

    /// Returns the connection information of all the current section elders.
    pub fn our_elders(&self) -> impl Iterator<Item = &P2pNode> {
        vec![].into_iter()
    }

    /// Vote for an event.
    pub fn vote_for_user_event(&mut self, event: Vec<u8>) -> Result<(), RoutingError> {
        if !self.is_elder {
            return Err(RoutingError::InvalidState);
        }
        if let Some(ref consensus_group) = self.consensus_group {
            let _ = consensus_group
                .upgrade()
                .map(|group| group.borrow_mut().vote_for(event));
        } else {
            unwrap!(self.events_tx.send(Event::Consensus(event)));
        }
        Ok(())
    }

    /// Handle an event loop trigger with the mentioned operation
    pub fn handle_selected_operation(&mut self, op_index: usize) -> Result<(), RecvError> {
        match op_index {
            idx if idx == self.network_node_rx_idx => {
                let _event = self.network_node_rx.recv()?;
            }
            idx => panic!("Unknown operation selected: {}", idx),
        }
        Ok(())
    }

    /// Find out if the given XorName matches our prefix.
    pub fn matches_our_prefix(&self, _name: &XorName) -> Result<bool, RoutingError> {
        // Currently due to there being just one section, this will always be true
        // TODO: This would return an error if we are neither an elder nor an adult
        Ok(true)
    }

    /// Find out the closest Elders to a given XorName that we know of.
    ///
    /// Note that the Adults of a section only know about their section Elders. Hence they will
    /// always return the section Elders' info.
    pub fn closest_known_elders_to(&self, _name: &XorName) -> impl Iterator<Item = &P2pNode> {
        // Currently due to there being just one section, return our section eleders.
        self.our_elders()
    }

    /// Return the client connection info
    pub fn our_connection_info(&mut self) -> Result<SocketAddr, RoutingError> {
        Ok(unwrap!(self.quic_p2p.our_connection_info()))
    }

    /// Return if the Node is an elder or not.
    pub fn is_elder(&self) -> bool {
        self.is_elder
    }

    /// Send a message to a client peer
    pub fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
        token: Token,
    ) -> Result<(), RoutingError> {
        trace!("({}) Sending message to {}", token, peer_addr);
        self.quic_p2p.send(Peer::Client(peer_addr), msg, token);
        Ok(())
    }

    /// Disconnect form a client peer
    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<(), RoutingError> {
        self.quic_p2p.disconnect_from(peer_addr);
        Ok(())
    }
}

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {}

impl NodeBuilder {
    /// Creates new `Node`.
    pub fn create(self) -> (Node, Receiver<Event>, Receiver<TransportEvent>) {
        let (quic_p2p, network_node_rx, network_client_rx) =
            unwrap!(setup_quic_p2p(&Default::default()));
        let (events_tx, events_rx) = mpmc::unbounded();

        (
            Node {
                network_node_rx,
                quic_p2p,
                events_tx,
                network_node_rx_idx: 0,
                consensus_group: None,
                is_elder: false,
            },
            events_rx,
            network_client_rx,
        )
    }

    /// Creates new `Node` within a section of nodes.
    pub fn create_within_group(
        self,
        consensus_group: ConsensusGroupRef,
    ) -> (Node, Receiver<Event>, Receiver<TransportEvent>) {
        let (quic_p2p, network_node_rx, network_client_rx) =
            unwrap!(setup_quic_p2p(&Default::default()));
        let (events_tx, events_rx) = mpmc::unbounded();

        consensus_group
            .borrow_mut()
            .event_channels
            .push(events_tx.clone());

        (
            Node {
                network_node_rx,
                quic_p2p,
                events_tx,
                network_node_rx_idx: 0,
                consensus_group: Some(Rc::downgrade(&consensus_group)),
                is_elder: false,
            },
            events_rx,
            network_client_rx,
        )
    }
}

fn setup_quic_p2p(
    config: &TransportConfig,
) -> Result<(QuicP2p, Receiver<TransportEvent>, Receiver<TransportEvent>), QuicP2pError> {
    let (event_senders, node_receiver, client_receiver) = {
        let (node_tx, node_rx) = crossbeam_channel::unbounded();
        let (client_tx, client_rx) = crossbeam_channel::unbounded();
        (
            quic_p2p::EventSenders { node_tx, client_tx },
            node_rx,
            client_rx,
        )
    };
    let quic_p2p = quic_p2p::Builder::new(event_senders)
        .with_config(config.clone())
        .build()?;
    Ok((quic_p2p, node_receiver, client_receiver))
}
