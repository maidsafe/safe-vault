// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities for integration tests

mod rng;

pub use self::rng::TestRng;

use bytes::Bytes;
use crossbeam_channel::Receiver;
use safe_nd::{
    Challenge, ClientFullId, ClientPublicId, Coins, Message, MessageId, PublicId, Request, Response,
};
use safe_vault::{
    mock::Network,
    quic_p2p::{self, Builder, Event, NodeInfo, OurType, Peer, QuicP2p},
    Config, Vault,
};
use serde::Serialize;
use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
    slice,
};
use tempdir::TempDir;
use unwrap::unwrap;

macro_rules! unexpected {
    ($e:expr) => {
        panic!("Unexpected {:?}", $e)
    };
}

pub struct Environment {
    rng: TestRng,
    network: Network,
}

impl Environment {
    pub fn new() -> Self {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut rng = rng::new();
        let network_rng = rng::from_rng(&mut rng);

        Self {
            rng,
            network: Network::new(network_rng),
        }
    }

    pub fn rng(&mut self) -> &mut TestRng {
        &mut self.rng
    }

    // Poll the mock network and the given vaults.
    // For convenience, this function can be called with `&mut Vault` or `&mut [Vault]`.
    pub fn poll<T: AsMutSlice<TestVault>>(&self, vaults: &mut T) {
        let mut progress = true;
        while progress {
            self.network.poll();

            progress = false;
            for vault in vaults.as_mut_slice().iter_mut() {
                if vault.inner.poll() {
                    progress = true;
                }
            }
        }
    }
}

pub trait AsMutSlice<T> {
    fn as_mut_slice(&mut self) -> &mut [T];
}

pub struct TestVault {
    inner: Vault,
    _root_dir: TempDir,
}

impl TestVault {
    pub fn new() -> Self {
        let root_dir = unwrap!(TempDir::new("safe_vault"));

        let mut config = Config::default();
        config.set_root_dir(root_dir.path());

        let inner = unwrap!(Vault::new(config));

        Self {
            inner,
            _root_dir: root_dir,
        }
    }

    pub fn connection_info(&mut self) -> NodeInfo {
        unwrap!(self.inner.our_connection_info())
    }
}

impl Deref for TestVault {
    type Target = Vault;

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

pub struct TestClient {
    quic_p2p: QuicP2p,
    rx: Receiver<Event>,
    full_id: ClientFullId,
}

impl TestClient {
    pub fn new(rng: &mut TestRng) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let config = quic_p2p::Config {
            our_type: OurType::Client,
            ..Default::default()
        };

        Self {
            quic_p2p: unwrap!(Builder::new(tx).with_config(config).build()),
            rx,
            full_id: ClientFullId::new_ed25519(rng),
        }
    }

    pub fn public_id(&self) -> &ClientPublicId {
        self.full_id.public_id()
    }

    pub fn full_id(&self) -> &ClientFullId {
        &self.full_id
    }

    pub fn expect_connected_to(&self, conn_info: &NodeInfo) {
        match self.rx.try_recv() {
            Ok(Event::ConnectedTo {
                peer: Peer::Node { ref node_info },
            }) if node_info == conn_info => (),
            x => unexpected!(x),
        }
    }

    pub fn expect_new_message(&self) -> (SocketAddr, Bytes) {
        match self.rx.try_recv() {
            Ok(Event::NewMessage { peer_addr, msg }) => (peer_addr, msg),
            x => unexpected!(x),
        }
    }

    pub fn handle_challenge_from(&mut self, conn_info: &NodeInfo) {
        let (sender, bytes) = self.expect_new_message();
        assert_eq!(sender, conn_info.peer_addr);

        let challenge: Challenge = unwrap!(bincode::deserialize(&bytes));
        let payload = match challenge {
            Challenge::Request(payload) => payload,
            Challenge::Response(..) => panic!("Unexpected Challenge::Response"),
        };

        let signature = self.full_id.sign(payload);
        let response = Challenge::Response(
            PublicId::Client(self.full_id.public_id().clone()),
            signature,
        );

        self.send(conn_info.clone(), &response);
    }

    pub fn send<T: Serialize>(&mut self, recipient: NodeInfo, msg: &T) {
        let msg = unwrap!(bincode::serialize(msg));
        self.quic_p2p.send(
            Peer::Node {
                node_info: recipient,
            },
            Bytes::from(msg),
        )
    }

    pub fn send_request(&mut self, recipient: NodeInfo, request: Request) -> MessageId {
        let message_id = MessageId::new();

        let to_sign = (&request, &message_id);
        let to_sign = unwrap!(bincode::serialize(&to_sign));
        let signature = self.full_id.sign(&to_sign);

        let msg = Message::Request {
            request,
            message_id,
            signature: Some(signature),
        };

        self.send(recipient, &msg);

        message_id
    }

    pub fn expect_response(&mut self, expected_message_id: MessageId) -> Response {
        let bytes = self.expect_new_message().1;
        let message: Message = unwrap!(bincode::deserialize(&bytes));

        match message {
            Message::Response {
                message_id,
                response,
            } => {
                assert_eq!(
                    message_id, expected_message_id,
                    "Received Response with unexpected MessageId."
                );
                response
            }
            Message::Request { request, .. } => unexpected!(request),
        }
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

pub fn establish_connection(env: &mut Environment, client: &mut TestClient, vault: &mut TestVault) {
    let conn_info = vault.connection_info();
    client.connect_to(conn_info.clone());
    env.poll(vault);

    client.expect_connected_to(&conn_info);
    client.handle_challenge_from(&conn_info);
    env.poll(vault);
}

pub fn perform_mutation(
    env: &mut Environment,
    client: &mut TestClient,
    vault: &mut TestVault,
    request: Request,
) {
    let conn_info = vault.connection_info();
    let message_id = client.send_request(conn_info, request);
    env.poll(vault);

    match client.expect_response(message_id) {
        Response::Mutation(Ok(())) => (),
        x => unexpected!(x),
    }
}

pub fn get_balance(env: &mut Environment, client: &mut TestClient, vault: &mut TestVault) -> Coins {
    let conn_info = vault.connection_info();
    let message_id = client.send_request(conn_info, Request::GetBalance);

    env.poll(vault);

    match client.expect_response(message_id) {
        Response::GetBalance(Ok(coins)) => coins,
        x => unexpected!(x),
    }
}
