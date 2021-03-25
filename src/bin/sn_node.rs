// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! sn_node provides the interface to Safe routing.  The resulting executable is the node
//! for the Safe network.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![forbid(unsafe_code)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

use log::{self, error, info};
use self_update::{cargo_crate_version, Status};
use sn_node::{self, utils, write_connection_info, Config, Node};
use std::{io::Write, process};
use structopt::{clap, StructOpt};

/// Runs a Safe Network node.
fn main() {
    let sn_node_thread = std::thread::Builder::new()
        .name("sn_node".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_node());
            Ok::<(), std::io::Error>(())
        });

    match sn_node_thread {
        Ok(thread) => match thread.join() {
            Ok(_) => {}
            Err(err) => println!("Failed to run node: {:?}", err),
        },
        Err(err) => println!("Failed to run node: {:?}", err),
    }
}

async fn run_node() {
    let mut config = match Config::new() {
        Ok(cfg) => cfg,
        Err(e) => {
            println!("Failed to create Config: {:?}", e);
            process::exit(1);
        }
    };

    if let Some(c) = &config.completions() {
        match c.parse::<clap::Shell>() {
            Ok(shell) => match gen_completions_for_shell(shell) {
                Ok(buf) => {
                    std::io::stdout().write_all(&buf).unwrap_or_else(|e| {
                        println!("Failed to print shell completions. {}", e);
                    });
                }
                Err(e) => println!("{}", e),
            },
            Err(e) => println!("Unknown completions option. {}", e),
        }
        // we exit program on both success and error.
        return;
    }

    if config.is_local() {
        config.listen_on_loopback();
    } else {
        config.network_config.forward_port = true;
    }

    utils::init_logging(&config);

    info!("Node PID is: {:?}", std::process::id());

    if config.update() || config.update_only() {
        match update() {
            Ok(status) => {
                if let Status::Updated { .. } = status {
                    println!("Node has been updated. Please restart.");
                    process::exit(0);
                }
            }
            Err(e) => error!("Updating node failed: {:?}", e),
        }

        if config.update_only() {
            process::exit(0);
        }
    }

    let message = format!(
        "Running {} v{}",
        Config::clap().get_name(),
        env!("CARGO_PKG_VERSION")
    );
    info!("\n\n{}\n{}", message, "=".repeat(message.len()));

    let mut node = match Node::new(&config).await {
        Ok(node) => node,
        Err(e) => {
            println!("Cannot start node due to error: {:?}", e);
            error!("Cannot start node due to error: {:?}", e);
            process::exit(1);
        }
    };

    let our_contact_info = node.our_connection_info().await;
    println!(
        "Node connection info:\n{}",
        serde_json::to_string(&our_contact_info)
            .unwrap_or_else(|_| "Failed to serialize connection info".into())
    );
    info!(
        "Node connection info: {}",
        serde_json::to_string(&our_contact_info)
            .unwrap_or_else(|_| "Failed to serialize connection info".into())
    );

    if config.is_first() {
        //let contact_info: HashSet<SocketAddr> = vec![our_conn_info].into_iter().collect();
        let _ = write_connection_info(our_contact_info).unwrap_or_else(|err| {
            log::error!("Unable to write config to disk: {}", err);
            Default::default()
        });
    }

    match node.run().await {
        Ok(()) => process::exit(0),
        Err(e) => {
            println!("Cannot start node due to error: {:?}", e);
            error!("Cannot start node due to error: {:?}", e);
            process::exit(1);
        }
    }
}

fn update() -> Result<Status, Box<dyn (::std::error::Error)>> {
    info!("Checking for updates...");
    let target = self_update::get_target();

    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner("maidsafe")
        .repo_name("sn_node")
        .with_target(&target)
        .build()?
        .fetch()?;

    if !releases.is_empty() {
        log::debug!("Target for update is {}", target);
        log::debug!("Found releases: {:#?}\n", releases);
        let bin_name = if target.contains("pc-windows") {
            "sn_node.exe"
        } else {
            "sn_node"
        };
        let status = self_update::backends::github::Update::configure()
            .repo_owner("maidsafe")
            .repo_name("sn_node")
            .target(&target)
            .bin_name(&bin_name)
            .show_download_progress(true)
            .no_confirm(true)
            .current_version(cargo_crate_version!())
            .build()?
            .update()?;
        println!("Update status: '{}'!", status.version());
        Ok(status)
    } else {
        println!("Current version is '{}'", cargo_crate_version!());
        println!("No releases are available for updates");
        Ok(Status::UpToDate(
            "No releases are available for updates".to_string(),
        ))
    }
}

fn gen_completions_for_shell(shell: clap::Shell) -> Result<Vec<u8>, String> {
    // Get exe path
    let exe_path =
        std::env::current_exe().map_err(|err| format!("Can't get the exec path: {}", err))?;

    // get filename without preceding path as std::ffi::OsStr (C string)
    let exec_name_ffi = match exe_path.file_name() {
        Some(v) => v,
        None => {
            return Err(format!(
                "Can't extract file_name of executable from path {}",
                exe_path.display()
            ))
        }
    };

    // Convert OsStr to string.  Can fail if OsStr contains any invalid unicode.
    let exec_name = match exec_name_ffi.to_str() {
        Some(v) => v.to_string(),
        None => {
            return Err(format!(
                "Can't decode unicode in executable name '{:?}'",
                exec_name_ffi
            ))
        }
    };

    // Generates shell completions for <shell> and prints to stdout
    let mut buf: Vec<u8> = vec![];
    Config::clap().gen_completions_to(exec_name, shell, &mut buf);

    Ok(buf)
}
