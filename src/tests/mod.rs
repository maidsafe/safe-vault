// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(unused)]

#[cfg(feature = "simulated-payouts")]
mod client;

use crate::config_handler::write_connection_info;
use crate::{utils, Command, Config, Node};
use crossbeam_channel::Sender;
use file_per_thread_logger::{self as logger};
use sn_routing::{NodeConfig as RoutingConfig, TransportConfig as NetworkConfig};
use std::io::Write;
use std::net::SocketAddr;
use std::thread;
use tokio::task::JoinHandle;

#[derive(Default)]
struct Network {
    vaults: Vec<(Sender<Command>, JoinHandle<Result<(), i32>>)>,
}

impl Network {
    pub async fn new(no_of_vaults: usize) -> Self {
        let path = std::path::Path::new("vaults");
        std::fs::remove_dir_all(&path).unwrap_or(()); // Delete vaults directory if it exists;
        std::fs::create_dir_all(&path).expect("Cannot create vaults directory");
        // init_logging();
        logger::allow_uninitialized();
        let mut vaults = Vec::new();
        let genesis_info: SocketAddr = "127.0.0.1:12000".parse().unwrap();
        let mut node_config = Config::default();
        node_config.set_flag("verbose", 2);
        node_config.set_flag("local", 1);
        node_config.set_log_dir(path);
        node_config.listen_on_loopback();
        utils::init_logging(&node_config);
        let (command_tx, _command_rx) = crossbeam_channel::bounded(1);
        let mut genesis_config = node_config.clone();
        // let handle = std::thread::Builder::new()
        //     .name("vault-genesis".to_string())
        let handle = tokio::spawn({
            // let handle = runtime
            //     .spawn(async move {
            // init_logging();
            genesis_config.set_flag("first", 1);
            let path = path.join("genesis-vault");
            std::fs::create_dir_all(&path).expect("Cannot create genesis directory");
            genesis_config.set_root_dir(&path);
            genesis_config.listen_on_loopback();

            let mut routing_config = RoutingConfig::default();
            routing_config.first = genesis_config.is_first();
            routing_config.transport_config = genesis_config.network_config().clone();

            let mut node = Node::new(&genesis_config, rand::rngs::OsRng::default())
                .await
                .expect("Unable to start vault Node");
            let our_conn_info = node
                .our_connection_info()
                .await
                .expect("Could not get genesis info");
            let _ = write_connection_info(&our_conn_info).unwrap();
            let _ = node.run().await.unwrap();
            futures::future::ok::<(), i32>(())
        });
        vaults.push((command_tx, handle));
        for i in 1..no_of_vaults {
            thread::sleep(std::time::Duration::from_secs(30));
            let (command_tx, _command_rx) = crossbeam_channel::bounded(1);
            let mut vault_config = node_config.clone();
            let handle = tokio::spawn({
                // init_logging();
                let vault_path = path.join(format!("vault-{}", i));
                println!("Starting new vault: {:?}", &vault_path);
                std::fs::create_dir_all(&vault_path).expect("Cannot create vault directory");
                vault_config.set_root_dir(&vault_path);

                let mut network_config = NetworkConfig::default();
                let _ = network_config.hard_coded_contacts.insert(genesis_info);
                vault_config.set_network_config(network_config);
                vault_config.listen_on_loopback();

                let mut routing_config = RoutingConfig::default();
                routing_config.transport_config = vault_config.network_config().clone();

                // let mut node =
                //     futures::executor::block_on(Node::new(&vault_config, rand::thread_rng()))
                //         .expect("Unable to start vault Node");
                let rng = rand::rngs::OsRng::default();
                let mut node = Node::new(&vault_config, rng).await.unwrap();
                let _ = node.run().await.unwrap();
                futures::future::ok::<(), i32>(())
            });
            vaults.push((command_tx, handle));
        }
        Self { vaults }
    }
}
