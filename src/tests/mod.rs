// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client;

use crate::config_handler::write_connection_info;
use crate::{utils, utils::Command, Config, Node};
use crossbeam_channel::Sender;
use sn_routing::{NodeConfig as RoutingConfig, TransportConfig as NetworkConfig};
use std::net::SocketAddr;
use std::thread;
use std::thread::JoinHandle;

#[derive(Default)]
struct Network {
    #[allow(unused)]
    nodes: Vec<(Sender<Command>, JoinHandle<()>)>,
}

impl Network {
    pub async fn new(no_of_nodes: usize) -> Self {
        let path = std::path::Path::new("nodes");
        std::fs::remove_dir_all(&path).unwrap_or(()); // Delete nodes directory if it exists;
        std::fs::create_dir_all(&path).expect("Cannot create nodes directory");
        let mut nodes = Vec::new();
        let genesis_info: SocketAddr = "127.0.0.1:12000".parse().unwrap();
        let mut node_config = Config::default();
        node_config.set_flag("verbose", 4);
        node_config.set_flag("local", 1);
        node_config.set_log_dir(path);
        node_config.listen_on_loopback();
        utils::init_logging(&node_config);
        let (command_tx, _command_rx) = crossbeam_channel::bounded(1);
        let mut genesis_config = node_config.clone();
        let handle = std::thread::Builder::new()
            .name("node-genesis".to_string())
            .spawn(move || {
                let mut runtime = tokio::runtime::Runtime::new().unwrap();
                genesis_config.set_flag("first", 1);
                let path = path.join("genesis-node");
                std::fs::create_dir_all(&path).expect("Cannot create genesis directory");
                genesis_config.set_root_dir(&path);
                genesis_config.listen_on_loopback();

                let mut routing_config = RoutingConfig::default();
                routing_config.first = genesis_config.is_first();
                routing_config.transport_config = genesis_config.network_config().clone();
                let mut node = runtime
                    .block_on(Node::new(&genesis_config, rand::rngs::OsRng::default()))
                    .expect("Unable to start Node");
                let our_conn_info = runtime
                    .block_on(node.our_connection_info())
                    .expect("Could not get genesis info");
                let _ = write_connection_info(&our_conn_info).unwrap();
                let _ = runtime.block_on(node.run()).unwrap();
            })
            .unwrap();
        nodes.push((command_tx, handle));
        for i in 1..no_of_nodes {
            thread::sleep(std::time::Duration::from_secs(30));
            let mut runtime = tokio::runtime::Runtime::new().unwrap();
            let (command_tx, _command_rx) = crossbeam_channel::bounded(1);
            let mut node_config = node_config.clone();
            let handle = thread::Builder::new()
                .name(format!("node-{n}", n = i))
                .spawn(move || {
                    let node_path = path.join(format!("node-{}", i));
                    println!("Starting new node: {:?}", &node_path);
                    std::fs::create_dir_all(&node_path).expect("Cannot create node directory");
                    node_config.set_root_dir(&node_path);

                    let mut network_config = NetworkConfig::default();
                    let _ = network_config.hard_coded_contacts.insert(genesis_info);
                    node_config.set_network_config(network_config);
                    node_config.listen_on_loopback();

                    let mut routing_config = RoutingConfig::default();
                    routing_config.transport_config = node_config.network_config().clone();
                    let rng = rand::rngs::OsRng::default();
                    let mut node = runtime.block_on(Node::new(&node_config, rng)).unwrap();
                    let _ = runtime.block_on(node.run()).unwrap();
                })
                .unwrap();
            nodes.push((command_tx, handle));
        }
        thread::sleep(std::time::Duration::from_secs(30));
        Self { nodes }
    }
}
