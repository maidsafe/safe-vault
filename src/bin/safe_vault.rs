// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! SAFE Vault provides the interface to SAFE routing.  The resulting executable is the Vault node
//! for the SAFE network.

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

fn main() {
    self::detail::main()
}

#[cfg(not(feature = "mock"))]
mod detail {
    use flexi_logger::{DeferredNow, Logger};
    use log::{self, Record};
    use safe_vault::{
        self,
        routing::{Node, NodeConfig},
        write_connection_info, Command, Config, Vault,
    };
    use self_update::cargo_crate_version;
    use self_update::Status;
    use std::{io::Write, process};
    use structopt::{clap, StructOpt};
    use unwrap::unwrap;

    /// Runs a SAFE Network vault.
    pub fn main() {
        let mut config = Config::new().expect("Error reading configuration file");

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

        if config.network_config().ip.is_none() {
            config.listen_on_loopback();
        }

        // Custom formatter for logs
        let do_format = move |writer: &mut dyn Write, clock: &mut DeferredNow, record: &Record| {
            write!(
                writer,
                "{} {} [{}:{}] {}",
                record.level(),
                clock.now().to_rfc3339(),
                record.file().unwrap_or_default(),
                record.line().unwrap_or_default(),
                record.args()
            )
        };

        let verbosity = config.verbose().to_level_filter().to_string();
        let logger = Logger::with_env_or_str(verbosity)
            .format(do_format)
            .suppress_timestamp();

        let _ = if let Some(log_dir) = config.log_dir() {
            logger.log_to_file().directory(log_dir)
        } else {
            logger
        }
        .start()
        .expect("Error when initialising logger");

        if config.update() || config.update_only() {
            match update() {
                Ok(status) => {
                    if let Status::Updated { .. } = status {
                        println!("Vault has been updated. Please restart.");
                        process::exit(0);
                    }
                }
                Err(e) => log::error!("Updating vault failed: {:?}", e),
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
        log::info!("\n\n{}\n{}", message, "=".repeat(message.len()));

        let (command_tx, command_rx) = crossbeam_channel::bounded(1);

        // Shutdown the vault gracefully on SIGINT (Ctrl+C).
        let result = ctrlc::set_handler(move || {
            let _ = command_tx.send(Command::Shutdown);
        });
        if let Err(error) = result {
            log::error!("Failed to set interrupt handler: {:?}", error)
        }

        let mut node_config = NodeConfig::default();
        node_config.first = config.is_first();
        node_config.transport_config = config.network_config().clone();
        let (routing_node, routing_rx, client_rx) = Node::new(node_config);

        let is_first = config.is_first();

        let mut rng = rand::thread_rng();

        match Vault::new(
            routing_node,
            routing_rx,
            client_rx,
            &config,
            command_rx,
            &mut rng,
        ) {
            Ok(mut vault) => {
                let our_conn_info = unwrap!(vault.our_connection_info());
                println!(
                    "Vault connection info:\n{}",
                    unwrap!(serde_json::to_string(&our_conn_info))
                );
                log::info!(
                    "Vault connection info: {}",
                    unwrap!(serde_json::to_string(&our_conn_info))
                );

                if is_first {
                    unwrap!(write_connection_info(&our_conn_info));
                }
                vault.run();
            }
            Err(e) => {
                println!("Cannot start vault due to error: {:?}", e);
                log::error!("Cannot start vault due to error: {:?}", e);
            }
        }
    }

    fn update() -> Result<Status, Box<dyn (::std::error::Error)>> {
        log::info!("Checking for updates...");
        let target = self_update::get_target();
        let releases = self_update::backends::github::ReleaseList::configure()
            .repo_owner("maidsafe")
            .repo_name("safe_vault")
            .with_target(&target)
            .build()?
            .fetch()?;
        if !releases.is_empty() {
            log::debug!("Target for update is {}", target);
            log::debug!("Found releases: {:#?}\n", releases);
            let bin_name = if target.contains("pc-windows") {
                "safe_vault.exe"
            } else {
                "safe_vault"
            };
            let status = self_update::backends::github::Update::configure()
                .repo_owner("maidsafe")
                .repo_name("safe_vault")
                .target(&target)
                .bin_name(&bin_name)
                .show_download_progress(true)
                .no_confirm(true)
                .current_version(cargo_crate_version!())
                .build()?
                .update()?;
            println!("Update status: `{}`!", status.version());
            return Ok(status);
        }
        log::info!("Current version is {}", cargo_crate_version!());
        log::info!("No releases are available for updates");
        Ok(Status::UpToDate(
            "No releases are available for updates".to_string(),
        ))
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
}

#[cfg(feature = "mock")]
mod detail {
    pub fn main() {
        println!("Cannot start vault with mock quic-p2p.");
    }
}
