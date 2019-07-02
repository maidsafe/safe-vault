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
use safe_nd::{Challenge, ClientFullId, PublicId};
use safe_vault::{
    mock::Network,
    quic_p2p::{self, Builder, Event, NodeInfo, OurType, Peer, QuicP2p},
    Config, Vault,
};
use serde::Serialize;
use std::{
    net::SocketAddr,
    ops::{Deref, DerefMut},
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
    pub fn poll<V: Vaults>(&self, vaults: &mut V) {
        loop {
            self.network.poll();
            if !vaults.poll() {
                break;
            }
        }
    }
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

pub trait Vaults {
    fn poll(&mut self) -> bool;
}

impl Vaults for TestVault {
    fn poll(&mut self) -> bool {
        self.inner.poll()
    }
}

impl Vaults for [TestVault] {
    fn poll(&mut self) -> bool {
        let mut progress = false;

        for vault in self.iter_mut() {
            if vault.inner.poll() {
                progress = true;
            }
        }

        progress
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

        self.send(
            Peer::Node {
                node_info: conn_info.clone(),
            },
            &response,
        );
    }

    pub fn send<T: Serialize>(&mut self, recipient: Peer, msg: &T) {
        let msg = unwrap!(bincode::serialize(msg));
        self.quic_p2p.send(recipient, Bytes::from(msg))
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
