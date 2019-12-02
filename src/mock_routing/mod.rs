// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Mock version of Quic-P2P
//pub mod quic_p2p;

use bytes::Bytes;
use crossbeam_channel::{self as mpmc, Receiver, RecvError, Select, Sender};
use log::trace;
pub use routing::quic_p2p::Config as NetworkConfig;
pub use routing::quic_p2p::NodeInfo as ConnectionInfo;
use routing::quic_p2p::{self, Error, Event as NetworkEvent, Peer, QuicP2p};
pub use routing::{ClientEvent, Event, InterfaceError, RoutingError};
use std::{
    cell::RefCell,
    convert::TryFrom,
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
    event_channels: Vec<Sender<Event>>,
}

impl ConsensusGroup {
    /// Creates a new consensus group.
    pub fn new() -> ConsensusGroupRef {
        Rc::new(RefCell::new(Self {
            event_channels: Vec::new(),
        }))
    }

    fn vote_for(&self, event: Vec<u8>) {
        for channel in &self.event_channels {
            unwrap!(channel.send(Event::Consensus(event.clone())));
        }
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full routing node.
pub struct Node {
    events_tx: Sender<Event>,
    quic_p2p: QuicP2p,
    network_rx: Receiver<NetworkEvent>,
    network_rx_idx: usize,
    consensus_group: Option<Weak<RefCell<ConsensusGroup>>>,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {}
    }

    /// Initialise the routing node.
    ///
    /// Registering of interests with the event loop will happen here. Without this routing will
    /// not be able to take part in the event loop triggers.
    pub fn register<'a>(&'a mut self, sel: &mut Select<'a>) {
        self.network_rx_idx = sel.recv(&self.network_rx);
    }

    /// Vote for an event.
    pub fn vote_for(&mut self, event: Vec<u8>) {
        if let Some(ref consensus_group) = self.consensus_group {
            let _ = consensus_group
                .upgrade()
                .map(|group| group.borrow_mut().vote_for(event));
        } else {
            unwrap!(self.events_tx.send(Event::Consensus(event)));
        }
    }

    /// Handle an event loop trigger with the mentioned operation
    pub fn handle_selected_operation(&mut self, op_index: usize) -> Result<(), RecvError> {
        match op_index {
            idx if idx == self.network_rx_idx => {
                let event = self.network_rx.recv()?;
                self.handle_network_event(event);
            }
            idx => panic!("Unknown operation selected: {}", idx),
        }
        Ok(())
    }

    /// Return the client connection info
    pub fn our_connection_info(&mut self) -> Result<ConnectionInfo, RoutingError> {
        Ok(unwrap!(self.quic_p2p.our_connection_info()))
    }

    /// Send a message to a client peer
    pub fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
        token: Token,
    ) -> Result<(), InterfaceError> {
        trace!("({}) Sending message to {}", token, peer_addr);
        self.quic_p2p.send(Peer::Client { peer_addr }, msg, token);
        Ok(())
    }

    /// Disconnect form a client peer
    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<(), InterfaceError> {
        self.quic_p2p.disconnect_from(peer_addr);
        Ok(())
    }

    fn handle_network_event(&mut self, event: NetworkEvent) {
        //if let Ok(client_event) = TryFrom::try_from(event) {
        if let Ok(client_event) = into_client_event(event) {
            unwrap!(self.events_tx.send(Event::ClientEvent(client_event)));
        }
    }
}

pub fn into_client_event(network_event: NetworkEvent) -> Result<ClientEvent, ()> {
    //type Error = ();

    //fn try_from(value: NetworkEvent) -> Result<Self, Self::Error> {
        use ClientEvent::*;
        use NetworkEvent::*;

        //let client_event = match value {
        let client_event = match network_event {
            ConnectedTo { peer } => ConnectedToClient {
                peer_addr: peer.peer_addr(),
            },
            NewMessage { peer_addr, msg } => NewMessageFromClient { peer_addr, msg },
            ConnectionFailure {
                peer_addr,
                err: _err,
            } => ConnectionFailureToClient { peer_addr },
            UnsentUserMessage {
                peer_addr,
                msg,
                token,
            } => UnsentUserMsgToClient {
                peer_addr,
                msg,
                token,
            },
            SentUserMessage {
                peer_addr,
                msg,
                token,
            } => SentUserMsgToClient {
                peer_addr,
                msg,
                token,
            },
            _event => {
                // There's no equivalent `ClientEvent`
                return Err(());
            }
        };

        Ok(client_event)
    //}
}

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {}

impl NodeBuilder {
    /// Creates new `Node`.
    pub fn create(self) -> Result<(Node, Receiver<Event>), RoutingError> {
        let (quic_p2p, network_rx) = unwrap!(setup_quic_p2p(&Default::default()));
        let (events_tx, events_rx) = mpmc::unbounded();

        Ok((
            Node {
                network_rx,
                quic_p2p,
                events_tx,
                network_rx_idx: 0,
                consensus_group: None,
            },
            events_rx,
        ))
    }

    /// Creates new `Node` within a section of nodes.
    pub fn create_within_group(
        self,
        consensus_group: ConsensusGroupRef,
    ) -> Result<(Node, Receiver<Event>), RoutingError> {
        let (quic_p2p, network_rx) = unwrap!(setup_quic_p2p(&Default::default()));
        let (events_tx, events_rx) = mpmc::unbounded();

        consensus_group
            .borrow_mut()
            .event_channels
            .push(events_tx.clone());

        Ok((
            Node {
                network_rx,
                quic_p2p,
                events_tx,
                network_rx_idx: 0,
                consensus_group: Some(Rc::downgrade(&consensus_group)),
            },
            events_rx,
        ))
    }
}

fn setup_quic_p2p(config: &NetworkConfig) -> Result<(QuicP2p, Receiver<NetworkEvent>), Error> {
    let (event_sender, event_receiver) = crossbeam_channel::unbounded();
    let quic_p2p = quic_p2p::Builder::new(event_sender)
        .with_config(config.clone())
        .build()?;
    Ok((quic_p2p, event_receiver))
}
