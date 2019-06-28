// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Builder, Config, Event, Network, NodeInfo, OurType, Peer, QuicP2p};
use bytes::Bytes;
use crossbeam_channel::{self as mpmc, Receiver, TryRecvError};
use fxhash::FxHashSet;
use rand;
use std::{iter, net::SocketAddr};
use unwrap::unwrap;

// Assert that the expression matches the expected pattern.
macro_rules! assert_match {
    ($e:expr, $p:pat => $arm:expr) => {
        match $e {
            $p => $arm,
            e => panic!("{:?} does not match {}", e, stringify!($p)),
        }
    };

    ($e:expr, $p:pat) => {
        assert_match!($e, $p => ())
    };
}

#[test]
fn successful_bootstrap_node_to_node() {
    let network = Network::new(rand::thread_rng());
    let a = Agent::node();
    let b = Agent::bootstrapped_node(&network, a.addr());
    a.expect_connected_to_node(&b.addr());
}

#[test]
fn successful_bootstrap_client_to_node() {
    let network = Network::new(rand::thread_rng());
    let a = Agent::node();
    let b = Agent::bootstrapped_client(&network, a.addr());
    a.expect_connected_to_client(&b.addr());
}

#[test]
fn bootstrap_to_nonexisting_node() {
    let network = Network::new(rand::thread_rng());
    let a_addr = network.gen_addr();

    let config = Config::node().with_hard_coded_contacts(iter::once(a_addr));
    let mut b = Agent::with_config(config);
    b.inner.bootstrap();
    network.poll();

    b.expect_bootstrap_failure();
}

#[test]
fn bootstrap_to_multiple_nodes() {
    let network = Network::new(rand::thread_rng());

    let bootstrappers: Vec<_> = (0..3).map(|_| Agent::node()).collect();

    let config = Config::node().with_hard_coded_contacts(bootstrappers.iter().map(Agent::addr));
    let mut bootstrapee = Agent::with_config(config);
    bootstrapee.inner.bootstrap();
    network.poll();

    let actual_addr =
        bootstrapee.expect_bootstrapped_to_exactly_one_of(bootstrappers.iter().map(Agent::addr));

    // The other nodes either don't connect to us or they disconnect afterwards.
    for bootstrapper in bootstrappers {
        if bootstrapper.addr() == actual_addr {
            continue;
        }

        match bootstrapper.rx.try_recv() {
            Ok(event) => {
                assert_connected_to_node(event, &bootstrapee.addr());
                bootstrapper.expect_connection_failure(&bootstrapee.addr());
            }
            Err(TryRecvError::Empty) => (),
            Err(err) => panic!("Unexpected {:?}", err),
        }
    }
}

#[test]
fn bootstrap_using_bootstrap_cache() {
    let network = Network::new(rand::thread_rng());

    // Address of a bootstrap node that is currently offline.
    let a_addr = network.gen_addr();

    let config = Config::node().with_hard_coded_contacts(iter::once(a_addr));
    let mut b = Agent::with_config(config);

    let mut c = Agent::node();

    // B successfully connects to C, thus adding it ot its bootstrap cache, then disconnects.
    establish_connection(&network, &mut b, &mut c);
    b.disconnect_from(c.addr());
    network.poll();

    // B now bootstraps. Because A (which is a hard-coded-contact) is offline, it bootstraps
    // against C which is in the bootstrap cache.
    b.inner.bootstrap();
    network.poll();

    b.expect_bootstrapped_to(&c.addr());
    b.expect_none();
}

#[test]
fn successful_connect_node_to_node() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::node();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);
}

#[test]
fn successful_connect_client_to_node() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::client();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);
}

#[test]
fn connect_to_nonexisting_node() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::node();
    let b_addr = network.gen_addr();

    a.connect_to(b_addr);
    network.poll();

    a.expect_none();
}

#[test]
fn connect_to_already_connected_node() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::node();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);

    a.connect_to(b.addr());
    network.poll();

    a.expect_none();
    b.expect_none();
}

#[test]
fn disconnect_incoming_bootstrap_connection() {
    let network = Network::new(rand::thread_rng());

    let a = Agent::node();
    let mut b = Agent::bootstrapped_node(&network, a.addr());
    a.expect_connected_to_node(&b.addr());

    b.disconnect_from(a.addr());
    network.poll();

    a.expect_connection_failure(&b.addr());
    b.expect_none();
}

#[test]
fn disconnect_outgoing_bootstrap_connection() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let b = Agent::bootstrapped_node(&network, a.addr());
    a.expect_connected_to_node(&b.addr());

    a.disconnect_from(b.addr());
    network.poll();

    a.expect_none();
    b.expect_connection_failure(&a.addr());
}

#[test]
fn disconnect_outgoing_connection() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);

    b.disconnect_from(a.addr());
    network.poll();

    a.expect_connection_failure(&b.addr());
    b.expect_none();
}

#[test]
fn disconnect_incoming_connection() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);

    a.disconnect_from(b.addr());
    network.poll();

    a.expect_none();
    b.expect_connection_failure(&a.addr());
}

#[test]
fn send_to_connected_node() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);

    let msg = gen_message();
    a.send(b.addr(), msg.clone());
    network.poll();

    b.expect_new_message(&a.addr(), &msg);
}

// TODO: unignore once proper error handling is in place in routing and this functionality is
// restored
#[ignore]
#[test]
fn send_to_disconnecting_node() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::node();
    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);

    let msg = gen_message();
    a.send(b.addr(), msg.clone());
    b.disconnect_from(a.addr());
    network.poll();

    a.expect_connection_failure(&b.addr());
    a.expect_unsent_message(&b.addr(), &msg);
    b.expect_none();
}

#[test]
fn send_to_nonexisting_node() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let b_addr = network.gen_addr();

    let msg = gen_message();
    a.send(b_addr, msg.clone());
    network.poll();

    // Note: the real quick-p2p will only emit `UnsentUserMessage` when a connection to the peer
    // was previously successfully established. That is not the case here, so we expect nothing.
    // TODO: this is going to get changed in the real quic-p2p, so change it here too.
    a.expect_none();
}

#[test]
fn send_without_connecting_first() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::node();
    let b = Agent::node();

    let msg = gen_message();
    a.send(b.addr(), msg.clone());

    network.poll();

    a.expect_connected_to_node(&b.addr());
    b.expect_connected_to_node(&a.addr());
    b.expect_new_message(&a.addr(), &msg);
}

#[test]
fn send_multiple_messages_without_connecting_first() {
    let network = Network::new(rand::thread_rng());
    let mut a = Agent::node();
    let b = Agent::node();

    let msgs = [gen_message(), gen_message(), gen_message()];

    for msg in &msgs {
        a.send(b.addr(), msg.clone());
    }

    network.poll();

    a.expect_connected_to_node(&b.addr());
    b.expect_connected_to_node(&a.addr());

    let received_messages = b.received_messages(&a.addr());
    expected_messages_received(msgs.to_vec(), received_messages);
}

#[test]
fn our_connection_info_of_node() {
    let _network = Network::new(rand::thread_rng());

    let (tx, _) = mpmc::unbounded();
    let mut node0 = unwrap!(Builder::new(tx).with_config(Config::node()).build());

    let (tx, _) = mpmc::unbounded();
    let mut node1 = unwrap!(Builder::new(tx).with_config(Config::node()).build());

    let node_info0 = unwrap!(node0.our_connection_info());
    let node_info1 = unwrap!(node1.our_connection_info());
    assert_ne!(node_info0, node_info1);
}

#[test]
fn our_connection_info_of_client() {
    let _network = Network::new(rand::thread_rng());

    let (tx, _) = mpmc::unbounded();
    let mut client = unwrap!(Builder::new(tx).with_config(Config::client()).build());
    assert!(client.our_connection_info().is_err())
}

#[test]
fn bootstrap_cache() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let mut b = Agent::node();

    assert!(unwrap!(a.inner.bootstrap_cache()).is_empty());
    assert!(unwrap!(b.inner.bootstrap_cache()).is_empty());

    establish_connection(&network, &mut a, &mut b);

    // outgoing connections are cached
    assert!(unwrap!(a.inner.bootstrap_cache()).contains(&NodeInfo::from(b.addr())));

    // incoming connections are not cached
    assert!(unwrap!(b.inner.bootstrap_cache()).is_empty());
}

#[test]
fn drop_disconnects() {
    let network = Network::new(rand::thread_rng());

    let mut a = Agent::node();
    let a_addr = a.addr();

    let mut b = Agent::node();

    establish_connection(&network, &mut a, &mut b);

    drop(a);
    network.poll();

    b.expect_connection_failure(&a_addr);
}

struct Agent {
    inner: QuicP2p,
    rx: Receiver<Event>,
}

impl Agent {
    // Create new test agent who is a node.
    fn node() -> Self {
        Self::with_config(Config::node())
    }

    // Create new test agent who is a client.
    fn client() -> Self {
        Self::with_config(Config::client())
    }

    fn with_config(config: Config) -> Self {
        let (tx, rx) = mpmc::unbounded();
        let inner = unwrap!(Builder::new(tx).with_config(config).build());

        Self { inner, rx }
    }

    /// Create new node and bootstrap it against the given address.
    fn bootstrapped_node(network: &Network, bootstrap_addr: SocketAddr) -> Self {
        let config = Config::node().with_hard_coded_contacts(iter::once(bootstrap_addr));
        let mut node = Self::with_config(config);

        node.inner.bootstrap();
        network.poll();
        node.expect_bootstrapped_to(&bootstrap_addr);
        node
    }

    fn bootstrapped_client(network: &Network, bootstrap_addr: SocketAddr) -> Self {
        let config = Config::client().with_hard_coded_contacts(iter::once(bootstrap_addr));
        let mut client = Self::with_config(config);

        client.inner.bootstrap();
        network.poll();
        client.expect_bootstrapped_to(&bootstrap_addr);
        client
    }

    fn connect_to(&mut self, dst_addr: SocketAddr) {
        self.inner.connect_to(NodeInfo::from(dst_addr));
    }

    fn disconnect_from(&mut self, dst_addr: SocketAddr) {
        self.inner.disconnect_from(dst_addr);
    }

    fn send(&mut self, dst_addr: SocketAddr, msg: Bytes) {
        self.inner.send(Peer::node(dst_addr), msg)
    }

    fn addr(&self) -> SocketAddr {
        self.inner.addr()
    }

    fn our_type(&self) -> OurType {
        self.inner.our_type()
    }

    // Expect `Event::BootstrappedTo` with the given address.
    fn expect_bootstrapped_to(&self, addr: &SocketAddr) {
        let actual_addr = assert_match!(
            self.rx.try_recv(),
            Ok(Event::BootstrappedTo {
                node: NodeInfo { peer_addr, .. }
            }) => peer_addr
        );
        assert_eq!(actual_addr, *addr);
    }

    // Expect exactly one `Event::BootstrappedTo` with an address contained in the list. Expect no
    // other events afterwards.
    fn expect_bootstrapped_to_exactly_one_of<I>(&self, addrs: I) -> SocketAddr
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let actual_addr = assert_match!(
            self.rx.try_recv(),
            Ok(Event::BootstrappedTo {
                node: NodeInfo { peer_addr, .. }
            }) => peer_addr
        );
        assert!(addrs.into_iter().any(|addr| addr == actual_addr));
        self.expect_none();
        actual_addr
    }

    // Expect `Event::BootstrapFailure`.
    fn expect_bootstrap_failure(&self) {
        assert_match!(self.rx.try_recv(), Ok(Event::BootstrapFailure));
    }

    // Expect `Event::ConnectedTo` with a node contact.
    fn expect_connected_to_node(&self, addr: &SocketAddr) {
        let event = unwrap!(self.rx.try_recv());
        assert_connected_to_node(event, addr)
    }

    // Expect `Event::ConnectedTo` with a client contact.
    fn expect_connected_to_client(&self, addr: &SocketAddr) {
        let actual_peer_addr = assert_match!(
            self.rx.try_recv(),
            Ok(Event::ConnectedTo {
                peer: Peer::Client { peer_addr }
            }) => peer_addr
        );
        assert_eq!(actual_peer_addr, *addr);
    }

    // Expect `Event::ConnectionFailure` with the given address.
    fn expect_connection_failure(&self, addr: &SocketAddr) {
        let actual_addr = assert_match!(
            self.rx.try_recv(),
            Ok(Event::ConnectionFailure { peer_addr }) => peer_addr
        );
        assert_eq!(actual_addr, *addr);
    }

    // Expect `Event::NewMessage` with the given sender address and content.
    fn expect_new_message(&self, src_addr: &SocketAddr, expected_msg: &Bytes) {
        let (actual_addr, actual_msg) = assert_match!(
            self.rx.try_recv(),
            Ok(Event::NewMessage { peer_addr, msg }) => (peer_addr, msg)
        );

        assert_eq!(actual_addr, *src_addr);
        assert_eq!(actual_msg, *expected_msg);
    }

    // Expect `Event::UnsentUserMessage` with the given recipient address and content.
    fn expect_unsent_message(&self, dst_addr: &SocketAddr, expected_msg: &Bytes) {
        let (actual_addr, actual_msg) = assert_match!(
            self.rx.try_recv(),
            Ok(Event::UnsentUserMessage { peer_addr, msg }) => (peer_addr, msg)
        );

        assert_eq!(actual_addr, *dst_addr);
        assert_eq!(actual_msg, *expected_msg);
    }

    // Expect no event.
    fn expect_none(&self) {
        assert_match!(self.rx.try_recv(), Err(TryRecvError::Empty));
    }

    fn received_messages(&self, src_addr: &SocketAddr) -> FxHashSet<Bytes> {
        let mut received_messages = FxHashSet::default();
        while let Ok(Event::NewMessage { peer_addr, msg }) = self.rx.try_recv() {
            assert_eq!(peer_addr, *src_addr);
            let _ = received_messages.insert(msg);
        }
        received_messages
    }
}

fn expected_messages_received(sent: Vec<Bytes>, received: FxHashSet<Bytes>) {
    let expected: FxHashSet<_> = sent.into_iter().collect();
    assert_eq!(expected, received);
}

fn establish_connection(network: &Network, a: &mut Agent, b: &mut Agent) {
    a.connect_to(b.addr());
    network.poll();

    match a.our_type() {
        OurType::Client => b.expect_connected_to_client(&a.addr()),
        OurType::Node => b.expect_connected_to_node(&a.addr()),
    }

    match b.our_type() {
        OurType::Client => a.expect_connected_to_client(&b.addr()),
        OurType::Node => a.expect_connected_to_node(&b.addr()),
    }
}

fn assert_connected_to_node(event: Event, addr: &SocketAddr) {
    let actual_peer_addr = assert_match!(
        event,
        Event::ConnectedTo {
            peer:
                Peer::Node {
                    node_info: NodeInfo { peer_addr, .. }
                }
        } => peer_addr
    );
    assert_eq!(actual_peer_addr, *addr);
}

// Generate unique message.
fn gen_message() -> Bytes {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let num = COUNTER.fetch_add(1, Ordering::Relaxed);

    bytes::Bytes::from(format!("message {}", num))
}
