// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod client;

use directories::BaseDirs;
use log::debug;
use sn_launch_tool::run_with;
use std::{fs::create_dir_all, path::PathBuf};
use tokio::time::{delay_for, Duration};

#[cfg(not(target_os = "windows"))]
const SAFE_NODE_EXECUTABLE: &str = "sn_node";

#[cfg(target_os = "windows")]
const SAFE_NODE_EXECUTABLE: &str = "sn_node.exe";

static NODES_DIR: &str = "local-test-network";
static INTERVAL: &str = "3";

fn get_node_bin_path(node_path: Option<PathBuf>) -> Result<PathBuf, String> {
    match node_path {
        Some(p) => Ok(p),
        None => {
            let base_dirs =
                BaseDirs::new().ok_or_else(|| "Failed to obtain user's home path".to_string())?;

            let mut path = PathBuf::from(base_dirs.home_dir());
            path.push(".safe");
            path.push("node");
            Ok(path)
        }
    }
}

pub async fn node_run(// node_path: Option<PathBuf>,
    // INTERVAL: &str,
    // ip: Option<String>,
    // test: bool,
) -> Result<(), String> {
    println!("STARTING NODES");
    let verbosity = 4;
    // let ip = None;
    let node_path = Some(PathBuf::from("./target/release"));
    // let node_path = None;
    let node_path = get_node_bin_path(node_path)?;
    
    // let ndoes_dir = NODES_DIR;
    let arg_node_path = node_path.join(SAFE_NODE_EXECUTABLE).display().to_string();
    debug!("Running node from {}", arg_node_path);

    let base_log_dir = get_node_bin_path(None)?;
    let node_log_dir = base_log_dir.join(NODES_DIR);
    if !node_log_dir.exists() {
        println!("Creating '{}' folder", node_log_dir.display());
        create_dir_all(node_log_dir.clone()).map_err(|err| {
            format!(
                "Couldn't create target path to store nodes' generated data: {}",
                err
            )
        })?;
    }
    let arg_node_log_dir = node_log_dir.display().to_string();
    println!("Storing nodes' generated data at {}", arg_node_log_dir);

    // Let's create an args array to pass to the network launcher tool
    let mut sn_launch_tool_args = vec![
        "sn_launch_tool",
        "-v",
        "--node-path",
        &arg_node_path,
        "--nodes-dir",
        &arg_node_log_dir,
        "--interval",
        &INTERVAL,
        "--local",
    ];

    let interval_as_int = &INTERVAL.parse::<u64>().unwrap();

    let mut verbosity_arg = String::from("-");
    if verbosity > 0 {
        let v = "y".repeat(verbosity as usize);
        println!("V: {}", v);
        verbosity_arg.push_str(&v);
        sn_launch_tool_args.push(&verbosity_arg);
    }

    // if let Some(ref launch_ip) = ip {
    //     sn_launch_tool_args.push("--ip");
    //     sn_launch_tool_args.push(launch_ip);
    // };

    debug!(
        "Running network launch tool with args: {:?}",
        sn_launch_tool_args
    );

    // We can now call the tool with the args
    println!("Launching local Safe network...");
    run_with(Some(&sn_launch_tool_args))?;

    let interval_duration = Duration::from_secs(interval_as_int * 15);
    // thread::sleep(interval_duration);

    delay_for(interval_duration).await;

    // let ignore_errors = true;
    // let report_errors = false;

    Ok(())
}

// #[derive(Default)]
// struct Network {
//     #[allow(unused)]
//     nodes: Vec<(Sender<Command>, JoinHandle<()>)>,
// }

// impl Network {
//     pub async fn new(no_of_nodes: usize) -> Self {
//         let path = std::path::Path::new("nodes");
//         std::fs::remove_dir_all(&path).unwrap_or(()); // Delete nodes directory if it exists;
//         std::fs::create_dir_all(&path).expect("Cannot create nodes directory");
//         let mut nodes = Vec::new();
//         let genesis_info: SocketAddr = "127.0.0.1:12000".parse().unwrap();
//         let mut node_config = Config::default();
//         node_config.set_flag("verbose", 4);
//         node_config.set_flag("local", 1);
//         node_config.set_log_dir(path);
//         node_config.listen_on_loopback();
//         utils::init_logging(&node_config);
//         let (command_tx, _command_rx) = crossbeam_channel::bounded(1);
//         let mut genesis_config = node_config.clone();
//         let handle = std::thread::Builder::new()
//             .name("node-genesis".to_string())
//             .spawn(move || {
//                 let mut runtime = tokio::runtime::Runtime::new().unwrap();
//                 genesis_config.set_flag("first", 1);
//                 let path = path.join("genesis-node");
//                 std::fs::create_dir_all(&path).expect("Cannot create genesis directory");
//                 genesis_config.set_root_dir(&path);
//                 genesis_config.listen_on_loopback();

//                 let mut routing_config = RoutingConfig::default();
//                 routing_config.first = genesis_config.is_first();
//                 routing_config.transport_config = genesis_config.network_config().clone();
//                 let mut node = runtime
//                     .block_on(Node::new(&genesis_config, rand::rngs::OsRng::default()))
//                     .expect("Unable to start Node");
//                 let our_conn_info = runtime
//                     .block_on(node.our_connection_info())
//                     .expect("Could not get genesis info");
//                 let _ = write_connection_info(&our_conn_info).unwrap();
//                 let _ = runtime.block_on(node.run()).unwrap();
//             })
//             .unwrap();
//         nodes.push((command_tx, handle));
//         for i in 1..no_of_nodes {
//             thread::sleep(std::time::Duration::from_secs(2));
//             let mut runtime = tokio::runtime::Runtime::new().unwrap();
//             let (command_tx, _command_rx) = crossbeam_channel::bounded(1);
//             let mut node_config = node_config.clone();
//             let handle = thread::Builder::new()
//                 .name(format!("node-{n}", n = i))
//                 .spawn(move || {
//                     let node_path = path.join(format!("node-{}", i));
//                     println!("Starting new node: {:?}", &node_path);
//                     std::fs::create_dir_all(&node_path).expect("Cannot create node directory");
//                     node_config.set_root_dir(&node_path);

//                     let mut network_config = NetworkConfig::default();
//                     let _ = network_config.hard_coded_contacts.insert(genesis_info);
//                     node_config.set_network_config(network_config);
//                     node_config.listen_on_loopback();

//                     let mut routing_config = RoutingConfig::default();
//                     routing_config.transport_config = node_config.network_config().clone();
//                     let rng = rand::rngs::OsRng::default();
//                     let mut node = runtime.block_on(Node::new(&node_config, rng)).unwrap();
//                     let _ = runtime.block_on(node.run()).unwrap();
//                 })
//                 .unwrap();
//             nodes.push((command_tx, handle));
//         }
//         thread::sleep(std::time::Duration::from_secs(30));
//         Self { nodes }
//     }
// }
