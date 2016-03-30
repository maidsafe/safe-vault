// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![cfg(all(test, feature = "use-mock-crust"))]

use vault::Vault;
use routing::mock_crust::{self, Config, Endpoint, Network, ServiceHandle};

struct TestNode {
    handle: ServiceHandle,
    vault: Vault,
}

impl TestNode {
    fn new(network: &Network, config: Option<Config>) -> Self {
        let handle = network.new_service_handle(config, None);
        let vault = mock_crust::make_current(&handle, || {
            unwrap_result!(Vault::new(None))
        });

        TestNode {
            handle: handle,
            vault: vault,
        }
    }

    fn poll(&mut self) -> bool {
        self.vault.poll()
    }

    fn endpoint(&self) -> Endpoint {
        self.handle.endpoint()
    }
}

// TODO:
struct TestClient;

impl TestClient {
    fn new() -> Self {
        TestClient
    }

    fn poll(&mut self) -> bool {
        false
    }

    // fn endpoint(&self) -> Endpoint {
    //     self.handle.endpoint()
    // }
}

fn poll_all(nodes: &mut [TestNode], clients: &mut [TestClient]) {
    loop {
        let mut next = false;

        for node in nodes.iter_mut() {
            if node.poll() {
                next = true;
                break;
            }
        }

        for client in clients.iter_mut() {
            if client.poll() {
                next = true;
                break;
            }
        }

        if !next {
            break;
        }
    }
}

fn create_nodes(network:& Network, size: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();

    // Create the seed node.
    nodes.push(TestNode::new(network, None));
    nodes[0].poll();

    let config = Config::with_contacts(&[nodes[0].endpoint()]);

    // Create other nodes using the seed node endpoint as bootstrap contact.
    for i in 1..size {
        nodes.push(TestNode::new(network, Some(config.clone())));
        poll_all(&mut nodes, &mut vec![]);
    }

    nodes
}

#[test]
fn how_to_use_mock_crust() {
    // The mock network.
    let network = Network::new();

    let nodes = create_nodes(&network, 3);
}
