// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{node::Node, OurType};
use bytes::Bytes;
use fxhash::{FxHashMap, FxHashSet};
use rand::{seq::SliceRandom, Rng, RngCore};
use std::{
    cell::RefCell,
    cmp,
    collections::{hash_map::Entry, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::{Rc, Weak},
};

const IP_BASE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const PORT: u16 = 9999;

/// Handle to the mock network. Create one before testing with mocks.
/// This handle is cheap to clone. Each clone refers to the same underlying mock network instance.
#[derive(Clone)]
pub struct Network(Rc<RefCell<Inner>>);

impl Network {
    /// Construct new mock network.
    pub fn new<R: RngCore + 'static>(rng: R) -> Self {
        let inner = Rc::new(RefCell::new(Inner {
            rng: Box::new(rng),
            nodes: Default::default(),
            connections: Default::default(),
            used_ips: Default::default(),
        }));

        NETWORK.with(|network| *network.borrow_mut() = Some(inner.clone()));

        Network(inner)
    }

    /// Generate new unique socket addrs.
    pub fn gen_addr(&self) -> SocketAddr {
        self.0.borrow_mut().gen_addr(None, None)
    }

    /// Poll the network by delivering the queued messages.
    pub fn poll(&self) {
        while let Some((connection, packet)) = self.pop_random_packet() {
            self.process_packet(&connection, packet)
        }
    }

    /// Disconnect peer at `addr0` from the peer at `addr1`.
    pub fn disconnect(&self, addr0: &SocketAddr, addr1: &SocketAddr) {
        let node = self.0.borrow().find_node(addr0);
        if let Some(node) = node {
            node.borrow_mut().disconnect(*addr1)
        }
    }

    /// Is the peer at `addr0` connected to the one at `addr1`?
    pub fn is_connected(&self, addr0: &SocketAddr, addr1: &SocketAddr) -> bool {
        self.0.borrow().is_connected(addr0, addr1)
    }

    fn pop_random_packet(&self) -> Option<(Connection, Packet)> {
        self.0.borrow_mut().pop_random_packet()
    }

    fn process_packet(&self, connection: &Connection, packet: Packet) {
        let response = if let Some(dst) = self.find_node(&connection.dst) {
            dst.borrow_mut().receive_packet(connection.src, packet);
            None
        } else {
            match packet {
                Packet::BootstrapRequest(_) => Some(Packet::BootstrapFailure),
                Packet::ConnectRequest(_) => Some(Packet::ConnectFailure),
                Packet::Message(msg) => Some(Packet::MessageFailure(msg)),
                _ => None,
            }
        };

        if let Some(packet) = response {
            self.send(connection.dst, connection.src, packet)
        }
    }

    fn find_node(&self, addr: &SocketAddr) -> Option<Rc<RefCell<Node>>> {
        self.0.borrow().find_node(addr)
    }

    fn send(&self, src: SocketAddr, dst: SocketAddr, packet: Packet) {
        self.0.borrow_mut().send(src, dst, packet)
    }
}

pub(super) struct Inner {
    rng: Box<RngCore>,
    nodes: FxHashMap<SocketAddr, Weak<RefCell<Node>>>,
    connections: FxHashMap<Connection, Queue>,
    used_ips: FxHashSet<IpAddr>,
}

impl Inner {
    pub fn gen_addr(&mut self, ip: Option<IpAddr>, port: Option<u16>) -> SocketAddr {
        let ip = ip.unwrap_or_else(|| {
            self.nodes
                .keys()
                .map(|addr| addr.ip())
                .chain(self.used_ips.iter().cloned())
                .max()
                .map(next_ip)
                .unwrap_or(IP_BASE)
        });
        let port = port.unwrap_or(PORT);

        let _ = self.used_ips.insert(ip);

        SocketAddr::new(ip, port)
    }

    pub fn insert_node(&mut self, addr: SocketAddr, node: Rc<RefCell<Node>>) {
        match self.nodes.entry(addr) {
            Entry::Occupied(_) => panic!("Node with {} already exists", addr),
            Entry::Vacant(entry) => {
                let _ = entry.insert(Rc::downgrade(&node));
            }
        }
    }

    pub fn remove_node(&mut self, addr: &SocketAddr) {
        let _ = self.nodes.remove(addr);
    }

    pub fn send(&mut self, src: SocketAddr, dst: SocketAddr, packet: Packet) {
        self.connections
            .entry(Connection::new(src, dst))
            .or_insert_with(Queue::new)
            .push(packet)
    }

    pub fn disconnect(&mut self, src: SocketAddr, dst: SocketAddr) {
        // TODO (quic-p2p): mock-crust dropped all in-flight messages from `src` to `dst` and
        // from `dst` to `src` here. Should we do the same?
        self.send(src, dst, Packet::Disconnect);
    }

    fn find_node(&self, addr: &SocketAddr) -> Option<Rc<RefCell<Node>>> {
        self.nodes.get(addr).and_then(Weak::upgrade)
    }

    fn pop_random_packet(&mut self) -> Option<(Connection, Packet)> {
        let connections: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .map(|(connection, _)| connection)
            .collect();

        let connection = if let Some(connection) = connections.choose(&mut *self.rng) {
            **connection
        } else {
            return None;
        };

        self.pop_packet(connection)
            .map(|packet| (connection, packet))
    }

    fn pop_packet(&mut self, connection: Connection) -> Option<Packet> {
        match self.connections.entry(connection) {
            Entry::Occupied(mut entry) => {
                let packet = entry.get_mut().pop_random_msg(&mut self.rng);
                if entry.get().is_empty() {
                    let _ = entry.remove_entry();
                }
                packet
            }
            Entry::Vacant(_) => None,
        }
    }

    fn is_connected(&self, addr0: &SocketAddr, addr1: &SocketAddr) -> bool {
        self.find_node(addr0)
            .map(|node| node.borrow().is_connected(addr1))
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub(super) enum Packet {
    BootstrapRequest(OurType),
    BootstrapSuccess,
    BootstrapFailure,
    ConnectRequest(OurType),
    ConnectSuccess,
    ConnectFailure,
    Message(Bytes),
    MessageFailure(Bytes),
    Disconnect,
}

struct Queue(VecDeque<Packet>);

impl Queue {
    fn new() -> Self {
        Queue(VecDeque::new())
    }

    fn push(&mut self, packet: Packet) {
        self.0.push_back(packet)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // This function will pop random msg from the queue.
    fn pop_random_msg<R: Rng>(&mut self, rng: &mut R) -> Option<Packet> {
        let first_non_msg_packet = self
            .0
            .iter()
            .position(|packet| {
                if let Packet::Message(_) = packet {
                    false
                } else {
                    true
                }
            })
            .unwrap_or(0);

        let selected = rng.gen_range(0, cmp::max(first_non_msg_packet, 1));
        self.0.remove(selected)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
struct Connection {
    src: SocketAddr,
    dst: SocketAddr,
}

impl Connection {
    fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }
}

thread_local! {
    pub(super) static NETWORK: RefCell<Option<Rc<RefCell<Inner>>>> = RefCell::new(None);
}

fn next_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from_be_bytes(ip.octets()) + 1)),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes(ip.octets()) + 1)),
    }
}
