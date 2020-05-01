// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for integration tests

mod logging;
mod rng;

pub use self::rng::TestRng;

use self::rng::SeedPrinter;
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
#[cfg(feature = "mock_parsec")]
use fake_clock::FakeClock;
use log::trace;
use mock_quic_p2p::{self as quic_p2p, Builder, Event, Network, OurType, Peer, QuicP2p};
#[cfg(feature = "mock_parsec")]
use routing::{self, Node, NodeConfig, TransportConfig as NetworkConfig};
use safe_nd::{
    AppFullId, AppPublicId, ClientFullId, ClientPublicId, Coins, Error, HandshakeRequest,
    HandshakeResponse, Message, MessageId, Notification, PublicId, PublicKey, Request, Response,
    Signature, Transaction, TransactionId,
};
#[cfg(feature = "mock")]
use safe_vault::{
    mock_routing::{ConsensusGroup, ConsensusGroupRef},
    routing::{Node, NodeConfig},
};
use safe_vault::{Command, Config, Vault};
use serde::Serialize;
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    slice,
};
use tempdir::TempDir;
use unwrap::unwrap;

/// Default number of vaults to run the tests with.
const DEFAULT_NUM_VAULTS: usize = 8;

macro_rules! unexpected {
    ($e:expr) => {
        panic!("Unexpected {:?}", $e)
    };
}

pub struct Environment {
    rng: TestRng,
    _seed_printer: SeedPrinter,
    network: Network,
    vaults: Vec<TestVault>,
    #[cfg(feature = "mock")]
    _consensus_group: ConsensusGroupRef,
}

impl Environment {
    #[cfg(feature = "mock")]
    pub fn with_multiple_vaults(num_vaults: usize) -> Self {
        assert!(num_vaults > 0);

        logging::init();

        let seed = rng::get_seed();
        let mut rng = rng::from_seed(seed);

        let network = Network::new();

        let consensus_group = ConsensusGroup::new();
        let vaults = if num_vaults > 1 {
            let mut vaults = Vec::with_capacity(num_vaults);
            for i in 0..num_vaults {
                vaults.push(TestVault::new_with_mock_routing(
                    Some(consensus_group.clone()),
                    &mut rng,
                    i < 7,
                ));
            }
            vaults
        } else {
            vec![TestVault::new_with_mock_routing(None, &mut rng, true)]
        };

        consensus_group.borrow().promote_all();

        Self {
            rng,
            _seed_printer: SeedPrinter::new(seed),
            network,
            vaults,
            _consensus_group: consensus_group,
        }
    }

    #[cfg(feature = "mock_parsec")]
    pub fn with_multiple_vaults(num_vaults: usize) -> Self {
        assert!(num_vaults > 1);

        logging::init();
        routing::init_mock();

        let seed = rng::get_seed();
        let rng = rng::from_seed(seed);

        let mut env = Self {
            rng,
            _seed_printer: SeedPrinter::new(seed),
            network: Network::new(),
            vaults: Default::default(),
        };

        env.vaults
            .push(TestVault::new_with_real_routing(None, &mut env.rng));

        while !env.vaults[0].is_elder() {
            env.poll()
        }
        let endpoint = env.vaults[0].connection_info();

        // Create other nodes using the seed node endpoint as bootstrap contact.
        let config = NetworkConfig::node().with_hard_coded_contact(endpoint);

        for i in 1..num_vaults {
            env.vaults.push(TestVault::new_with_real_routing(
                Some(config.clone()),
                &mut env.rng,
            ));
            while !env.vaults[i].is_elder() && i != 7 {
                env.poll()
            }
        }

        env
    }

    pub fn new() -> Self {
        Self::with_multiple_vaults(DEFAULT_NUM_VAULTS)
    }

    pub fn rng(&mut self) -> &mut TestRng {
        &mut self.rng
    }

    #[cfg(not(feature = "mock_parsec"))]
    // Poll the mock network and the environment's vault.
    pub fn poll(&mut self) {
        let mut progress = true;
        while progress {
            self.network.poll(&mut self.rng);
            progress = self.vaults.iter_mut().any(|vault| vault.inner.poll());
        }
    }

    #[cfg(feature = "mock_parsec")]
    // Poll the mock network and the environment's vault.
    pub fn poll(&mut self) {
        let mut processed = true;
        while processed {
            processed = false;
            self.network.poll(&mut self.rng);
            self.vaults
                .iter_mut()
                .for_each(|vault| processed = processed || vault.inner.poll());
            // Advance time for next route/gossip iter, same as used within routing tests.
            FakeClock::advance_time(1001);
        }
    }

    pub fn new_connected_client(&mut self) -> TestClient {
        let mut client = TestClient::new_disconnected(&mut self.rng);
        self.establish_connection(&mut client);
        client
    }

    pub fn new_connected_app(&mut self, owner: ClientPublicId) -> TestApp {
        let mut app = TestApp::new_disconnected(&mut self.rng, owner);
        self.establish_connection(&mut app);
        app
    }

    pub fn new_disconnected_app(&mut self, owner: ClientPublicId) -> TestApp {
        TestApp::new_disconnected(&mut self.rng, owner)
    }

    /// Establish connection assuming we are already at the destination section.
    pub fn establish_connection<T: TestClientTrait>(&mut self, client: &mut T) {
        let connections: Vec<_> = self
            .vaults
            .iter_mut()
            .map(|vault| (vault.connection_info(), vault.is_elder()))
            .collect();
        for (conn_info, is_elder) in connections {
            if cfg!(not(feature = "mock")) && !is_elder {
                continue;
            }
            client.quic_p2p().connect_to(conn_info.clone());
            self.poll();

            client.expect_connected_to(&conn_info);

            // Bootstrap handshake procedure where we assume that we don't have to rebootstrap
            let client_public_id = client.full_id().public_id();
            client.send_bootstrap_request(&client_public_id, &conn_info);
            self.poll();

            client.handle_handshake_response_join_from(&client_public_id, &conn_info, self);
            self.poll();

            client.handle_challenge_from(&conn_info, self);
            self.poll();
        }
    }
}

trait AsMutSlice<T> {
    fn as_mut_slice(&mut self) -> &mut [T];
}

struct TestVault {
    inner: Vault<TestRng>,
    _root_dir: TempDir,
    _command_tx: Sender<Command>,
}

impl TestVault {
    /// Create a test Vault within a group.
    #[cfg(feature = "mock")]
    fn new_with_mock_routing(
        consensus_group: Option<ConsensusGroupRef>,
        rng: &mut TestRng,
        is_elder: bool,
    ) -> Self {
        let root_dir = unwrap!(TempDir::new("safe_vault"));
        trace!("Creating a test vault at root_dir {:?}", root_dir);

        let mut config = Config::default();
        config.set_root_dir(root_dir.path());

        let (command_tx, command_rx) = crossbeam_channel::bounded(0);

        let (routing_node, routing_rx, client_rx) = if let Some(group) = consensus_group {
            let mut node_config = NodeConfig::default();
            node_config.is_elder = is_elder;
            node_config.concensus_group = Some(group);
            Node::new(node_config)
        } else {
            let mut node_config = NodeConfig::default();
            node_config.is_elder = is_elder;
            Node::new(node_config)
        };
        let inner = unwrap!(Vault::new(
            routing_node,
            routing_rx,
            client_rx,
            &config,
            command_rx,
            rng::from_rng(rng),
        ));

        Self {
            inner,
            _root_dir: root_dir,
            _command_tx: command_tx,
        }
    }

    #[cfg(feature = "mock_parsec")]
    fn new_with_real_routing(network_config: Option<NetworkConfig>, rng: &mut TestRng) -> Self {
        let root_dir = unwrap!(TempDir::new("safe_vault"));
        trace!("creating a test vault at root_dir {:?}", root_dir);

        let mut config = Config::default();
        config.set_root_dir(root_dir.path());

        let (command_tx, command_rx) = crossbeam_channel::bounded(0);

        let (routing_node, routing_rx, client_rx) = if let Some(network_config) = network_config {
            let mut node_config = NodeConfig::default();
            node_config.transport_config = network_config;
            Node::new(node_config)
        } else {
            let mut node_config = NodeConfig::default();
            node_config.first = true;
            Node::new(node_config)
        };

        let inner = unwrap!(Vault::new(
            routing_node,
            routing_rx,
            client_rx,
            &config,
            command_rx,
            rng::from_rng(rng),
        ));

        Self {
            inner,
            _root_dir: root_dir,
            _command_tx: command_tx,
        }
    }

    fn connection_info(&mut self) -> SocketAddr {
        unwrap!(self.inner.our_connection_info())
    }

    #[cfg(any(feature = "mock_parsec", feature = "mock"))]
    fn is_elder(&mut self) -> bool {
        self.inner.is_elder()
    }
}

impl Deref for TestVault {
    type Target = Vault<TestRng>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TestVault {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsMutSlice<TestVault> for TestVault {
    fn as_mut_slice(&mut self) -> &mut [TestVault] {
        slice::from_mut(self)
    }
}

impl AsMutSlice<TestVault> for [TestVault] {
    fn as_mut_slice(&mut self) -> &mut [TestVault] {
        self
    }
}

pub enum FullId {
    Client(ClientFullId),
    App(AppFullId),
}

impl FullId {
    fn sign<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        match self {
            FullId::Client(full_id) => full_id.sign(data),
            FullId::App(full_id) => full_id.sign(data),
        }
    }

    fn public_id(&self) -> PublicId {
        match self {
            FullId::Client(full_id) => PublicId::Client(full_id.public_id().clone()),
            FullId::App(full_id) => PublicId::App(full_id.public_id().clone()),
        }
    }
}

pub trait TestClientTrait {
    fn quic_p2p(&mut self) -> &mut QuicP2p;
    fn rx(&self) -> &Receiver<Event>;
    fn full_id(&self) -> &FullId;
    fn set_connected_vault(&mut self, connected_vault: SocketAddr);
    fn connected_vaults(&self) -> Vec<SocketAddr>;

    fn sign<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        self.full_id().sign(data)
    }

    fn send_bootstrap_request(&mut self, client_public_id: &PublicId, conn_info: &SocketAddr) {
        let bootstrap_request = HandshakeRequest::Bootstrap(client_public_id.clone());
        self.send_to_target(&bootstrap_request, conn_info.clone());
    }

    fn handle_handshake_response_join_from(
        &mut self,
        client_public_id: &PublicId,
        conn_info: &SocketAddr,
        env: &mut Environment,
    ) {
        let (sender, bytes) = self.expect_new_message(env);
        assert_eq!(sender, *conn_info);

        let handshake_response: HandshakeResponse = unwrap!(bincode::deserialize(&bytes));
        let _payload = match handshake_response {
            HandshakeResponse::Join(payload) => payload,
            _ => panic!("Unexpected HandshakeResponse"),
        };

        // TODO: For Phase 2B and multiple sections we need handle the payload, disconnect and
        // connect to the new set of elders if necessary.

        let request = HandshakeRequest::Join(client_public_id.clone());
        self.send_to_target(&request, conn_info.clone());
    }

    fn expect_connected_to(&mut self, conn_info: &SocketAddr) {
        loop {
            match self.rx().try_recv() {
                Ok(Event::ConnectedTo {
                    peer: Peer::Node(node_info),
                }) if node_info == *conn_info => break,
                Ok(Event::SentUserMessage { .. }) => continue,
                x => unexpected!(x),
            }
        }
        self.set_connected_vault(conn_info.clone());
    }

    fn handle_challenge_from(&mut self, conn_info: &SocketAddr, env: &mut Environment) {
        let (sender, bytes) = self.expect_new_message(env);
        assert_eq!(sender, *conn_info);

        let handshake_response: HandshakeResponse = unwrap!(bincode::deserialize(&bytes));
        let payload = match handshake_response {
            // TODO: handle the set of PublicIds sent as part of the challenge response.
            HandshakeResponse::Challenge(_, payload) => payload,
            _ => panic!("Unexpected"),
        };

        let signature = self.full_id().sign(payload);
        let response = HandshakeRequest::ChallengeResult(signature);
        self.send_to_target(&response, conn_info.clone());
    }

    fn expect_new_message(&self, env: &mut Environment) -> (SocketAddr, Bytes) {
        loop {
            env.poll();
            match self.rx().try_recv() {
                Ok(Event::SentUserMessage { .. }) => continue,
                Ok(Event::NewMessage { peer, msg }) => return (peer.peer_addr(), msg),
                Err(error) => {
                    if error.is_empty() {
                        continue;
                    }
                    panic!("unexpected error {:?}", error);
                }
                x => unexpected!(x),
            }
        }
    }

    fn expect_no_new_message(&self) {
        loop {
            match self.rx().try_recv() {
                Ok(Event::SentUserMessage { .. }) => continue,
                Err(error) => {
                    assert!(error.is_empty());
                    return;
                }
                x => unexpected!(x),
            }
        }
    }

    fn send<T: Serialize>(&mut self, msg: &T) {
        let msg = Bytes::from(unwrap!(bincode::serialize(msg)));
        for node_info in self.connected_vaults() {
            self.quic_p2p().send(Peer::Node(node_info), msg.clone(), 0);
        }
    }

    fn send_to_target<T: Serialize>(&mut self, msg: &T, node_info: SocketAddr) {
        let msg = Bytes::from(unwrap!(bincode::serialize(msg)));
        self.quic_p2p().send(Peer::Node(node_info), msg, 0);
    }

    fn send_request(&mut self, request: Request) -> MessageId {
        let message_id = MessageId::new();

        let to_sign = (&request, &message_id);
        let to_sign = unwrap!(bincode::serialize(&to_sign));
        let signature = self.full_id().sign(&to_sign);

        let msg = Message::Request {
            request,
            message_id,
            signature: Some(signature),
        };

        self.send(&msg);

        message_id
    }

    fn expect_response(
        &mut self,
        expected_message_id: MessageId,
        env: &mut Environment,
    ) -> Response {
        // expect responses from all connected vaults.
        let mut expected_recivers = self.connected_vaults().len();

        loop {
            let (peer, bytes) = self.expect_new_message(env);
            let message: Message = unwrap!(bincode::deserialize(&bytes));

            match message {
                Message::Response {
                    message_id,
                    response,
                } => {
                    assert_eq!(
                        message_id, expected_message_id,
                        "Received Response with unexpected MessageId and response {:?}",
                        response
                    );
                    expected_recivers -= 1;
                    if expected_recivers == 0 {
                        return response;
                    }
                }
                Message::Request { request, .. } => unexpected!((peer, request)),
                Message::Notification { notification } => unexpected!((peer, notification)),
            }
        }
    }

    fn expect_notification(&mut self, env: &mut Environment) -> Notification {
        // expect notifications from all connected vaults.
        let connected_vaults = self.connected_vaults().len();
        let mut received_notifications = Vec::new();

        while received_notifications.len() < connected_vaults {
            let (peer, bytes) = self.expect_new_message(env);
            let message: Message = unwrap!(bincode::deserialize(&bytes));

            match message {
                Message::Notification { notification } => {
                    received_notifications.push((peer, notification))
                }
                Message::Request { request, .. } => unexpected!((peer, request)),
                Message::Response { response, .. } => unexpected!((peer, response)),
            }
        }
        received_notifications[0].1.clone()
    }

    fn expect_notification_and_response(
        &mut self,
        env: &mut Environment,
        expected_message_id: MessageId,
    ) -> (Notification, Response) {
        // expect notifications and responses from all connected vaults.
        let connected_vaults = self.connected_vaults().len();
        let mut received_notifications = Vec::new();
        let mut received_responses = Vec::new();

        while received_notifications.len() < connected_vaults
            || received_responses.len() < connected_vaults
        {
            let (peer, bytes) = self.expect_new_message(env);
            let message: Message = unwrap!(bincode::deserialize(&bytes));

            match message {
                Message::Notification { notification } => {
                    received_notifications.push((peer, notification))
                }
                Message::Request { request, .. } => unexpected!((peer, request)),
                Message::Response {
                    message_id,
                    response,
                } => {
                    assert_eq!(
                        message_id, expected_message_id,
                        "Received Response with unexpected MessageId and response {:?}",
                        response
                    );
                    received_responses.push((peer, response));
                }
            }
        }
        (
            received_notifications[0].1.clone(),
            received_responses[0].1.clone(),
        )
    }
}

pub struct TestClient {
    quic_p2p: QuicP2p,
    node_rx: Receiver<Event>,
    _client_rx: Receiver<Event>,
    full_id: FullId,
    public_id: ClientPublicId,
    connected_vaults: Vec<SocketAddr>,
}

impl TestClient {
    fn new_disconnected(rng: &mut TestRng) -> Self {
        let (tx, node_rx, client_rx) = {
            let (node_tx, node_rx) = crossbeam_channel::unbounded();
            let (client_tx, client_rx) = crossbeam_channel::unbounded();
            (
                quic_p2p::EventSenders { node_tx, client_tx },
                node_rx,
                client_rx,
            )
        };

        let config = quic_p2p::Config {
            our_type: OurType::Client,
            ..Default::default()
        };
        let client_full_id = ClientFullId::new_ed25519(rng);
        let public_id = client_full_id.public_id().clone();

        Self {
            quic_p2p: unwrap!(Builder::new(tx).with_config(config).build()),
            node_rx,
            _client_rx: client_rx,
            full_id: FullId::Client(client_full_id),
            public_id,
            connected_vaults: Default::default(),
        }
    }

    pub fn public_id(&self) -> &ClientPublicId {
        &self.public_id
    }
}

impl TestClientTrait for TestClient {
    fn quic_p2p(&mut self) -> &mut QuicP2p {
        &mut self.quic_p2p
    }

    fn rx(&self) -> &Receiver<Event> {
        &self.node_rx
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn set_connected_vault(&mut self, connected_vault: SocketAddr) {
        self.connected_vaults.push(connected_vault);
    }

    fn connected_vaults(&self) -> Vec<SocketAddr> {
        self.connected_vaults.clone()
    }
}

impl Deref for TestClient {
    type Target = QuicP2p;

    fn deref(&self) -> &Self::Target {
        &self.quic_p2p
    }
}

impl DerefMut for TestClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.quic_p2p
    }
}

pub struct TestApp {
    quic_p2p: QuicP2p,
    node_rx: Receiver<Event>,
    _client_rx: Receiver<Event>,
    full_id: FullId,
    public_id: AppPublicId,
    connected_vaults: Vec<SocketAddr>,
}

impl TestApp {
    fn new_disconnected(rng: &mut TestRng, owner: ClientPublicId) -> Self {
        let (tx, node_rx, client_rx) = {
            let (node_tx, node_rx) = crossbeam_channel::unbounded();
            let (client_tx, client_rx) = crossbeam_channel::unbounded();
            (
                quic_p2p::EventSenders { node_tx, client_tx },
                node_rx,
                client_rx,
            )
        };
        let config = quic_p2p::Config {
            our_type: OurType::Client,
            ..Default::default()
        };
        let app_full_id = AppFullId::new_ed25519(rng, owner);
        let public_id = app_full_id.public_id().clone();

        Self {
            quic_p2p: unwrap!(Builder::new(tx).with_config(config).build()),
            node_rx,
            _client_rx: client_rx,
            full_id: FullId::App(app_full_id),
            public_id,
            connected_vaults: Default::default(),
        }
    }

    pub fn public_id(&self) -> &AppPublicId {
        &self.public_id
    }
}

impl TestClientTrait for TestApp {
    fn quic_p2p(&mut self) -> &mut QuicP2p {
        &mut self.quic_p2p
    }

    fn rx(&self) -> &Receiver<Event> {
        &self.node_rx
    }

    fn full_id(&self) -> &FullId {
        &self.full_id
    }

    fn set_connected_vault(&mut self, connected_vault: SocketAddr) {
        self.connected_vaults.push(connected_vault);
    }

    fn connected_vaults(&self) -> Vec<SocketAddr> {
        self.connected_vaults.clone()
    }
}

impl Deref for TestApp {
    type Target = QuicP2p;

    fn deref(&self) -> &Self::Target {
        &self.quic_p2p
    }
}

impl DerefMut for TestApp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.quic_p2p
    }
}

pub fn get_from_response<T, D>(env: &mut Environment, client: &mut T, request: Request) -> D
where
    T: TestClientTrait,
    D: TryFrom<Response>,
    <D as TryFrom<Response>>::Error: Debug,
{
    let message_id = client.send_request(request);
    env.poll();
    let response = client.expect_response(message_id, env);
    unwrap!(response.try_into())
}

pub fn perform_mutation<T: TestClientTrait>(
    env: &mut Environment,
    client: &mut T,
    request: Request,
) {
    get_from_response::<_, ()>(env, client, request);
}

pub fn send_request_expect_ok<T, D>(
    env: &mut Environment,
    client: &mut T,
    request: Request,
    expected_success: D,
) where
    T: TestClientTrait,
    D: TryFrom<Response> + Eq + Debug,
    <D as TryFrom<Response>>::Error: Debug,
{
    assert_eq!(expected_success, get_from_response(env, client, request));
}

pub fn send_request_expect_err<T: TestClientTrait>(
    env: &mut Environment,
    client: &mut T,
    request: Request,
    expected_error: Error,
) {
    let expected_response = request.error_response(expected_error);
    let message_id = client.send_request(request.clone());
    trace!(
        "client sent request {:?} with msg_id {:?}",
        request,
        message_id
    );
    env.poll();
    assert_eq!(expected_response, client.expect_response(message_id, env));
}

pub fn create_balance(
    env: &mut Environment,
    src_client: &mut TestClient,
    dst_client: Option<&mut TestClient>,
    amount: impl IntoCoins,
) {
    let new_balance_owner = match dst_client {
        Some(ref dst_client) => *dst_client.public_id().public_key(),
        None => *src_client.public_id().public_key(),
    };
    let amount = amount.into_coins();
    let transaction_id = 0;

    let message_id = src_client.send_request(Request::CreateBalance {
        new_balance_owner,
        amount,
        transaction_id,
    });
    env.poll();

    let expected = Transaction {
        id: transaction_id,
        amount,
    };

    let (notification, response) = if let Some(target_clent) = dst_client {
        (
            target_clent.expect_notification(env),
            src_client.expect_response(message_id, env),
        )
    } else {
        src_client.expect_notification_and_response(env, message_id)
    };
    assert_eq!(notification, Notification(expected));

    let actual = unwrap!(Transaction::try_from(response));
    assert_eq!(actual, expected);
}

pub fn transfer_coins(
    env: &mut Environment,
    src_client: &mut impl TestClientTrait,
    dst_client: &mut TestClient,
    amount: impl IntoCoins,
    transaction_id: TransactionId,
) {
    let amount = amount.into_coins();

    let message_id = src_client.send_request(Request::TransferCoins {
        destination: *dst_client.public_id().name(),
        amount,
        transaction_id,
    });
    env.poll();

    let expected = Transaction {
        id: transaction_id,
        amount,
    };

    let notification = dst_client.expect_notification(env);
    assert_eq!(notification, Notification(expected));

    let response = src_client.expect_response(message_id, env);
    let actual = unwrap!(Transaction::try_from(response));
    assert_eq!(actual, expected);
}

pub fn gen_public_key(rng: &mut TestRng) -> PublicKey {
    *ClientFullId::new_ed25519(rng).public_id().public_key()
}

pub trait IntoCoins {
    fn into_coins(self) -> Coins;
}

impl IntoCoins for Coins {
    fn into_coins(self) -> Coins {
        self
    }
}

impl IntoCoins for u64 {
    fn into_coins(self) -> Coins {
        Coins::from_nano(self)
    }
}

pub fn multiply_coins(coins: Coins, factor: u64) -> Coins {
    Coins::from_nano(coins.as_nano() * factor)
}
