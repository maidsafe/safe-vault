// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![allow(trivial_numeric_casts)] // FIXME

use crate::{Error, Result};
use log::{debug, Level};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sn_routing::TransportConfig as NetworkConfig;
use std::convert::Infallible;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use structopt::StructOpt;

const CONFIG_FILE: &str = "node.config";
const CONNECTION_INFO_FILE: &str = "node_connection_info.config";
const DEFAULT_ROOT_DIR_NAME: &str = "root_dir";
const DEFAULT_MAX_CAPACITY: u64 = 2 * 1024 * 1024 * 1024;
const ARGS: [&str; 18] = [
    "wallet-id",
    "max-capacity",
    "root-dir",
    "verbose",
    "hard-coded-contacts",
    "local-port",
    "local-ip",
    "max-msg-size-allowed",
    "idle-timeout-msec",
    "keep-alive-interval-msec",
    "first",
    "completions",
    "log-dir",
    "update",
    "update-only",
    "upnp-lease-duration",
    "local",
    "clear-data",
];

/// Node configuration
#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq, StructOpt)]
#[structopt(rename_all = "kebab-case", bin_name = "sn_node")]
#[structopt(global_settings = &[structopt::clap::AppSettings::ColoredHelp])]
pub struct Config {
    /// The address to be credited when this node farms SafeCoin.
    /// A hex formatted BLS public key.
    #[structopt(short, long, parse(try_from_str))]
    pub wallet_id: Option<String>,
    /// Upper limit in bytes for allowed network storage on this node.
    #[structopt(short, long)]
    pub max_capacity: Option<u64>,
    /// Root directory for ChunkStores and cached state. If not set, it defaults to "root_dir"
    /// within the sn_node project data directory, located at:
    /// Linux: $HOME/.safe/node/root_dir
    /// Windows: {FOLDERID_Profile}/.safe/node/root_dir
    /// MacOS: $HOME/.safe/node/root_dir
    #[structopt(short, long, parse(from_os_str))]
    pub root_dir: Option<PathBuf>,
    /// Verbose output. `-v` is equivalent to logging with `warn`, `-vv` to `info`, `-vvv` to
    /// `debug`, `-vvvv` to `trace`. This flag overrides RUST_LOG.
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u64,
    /// Is the node running for a local section?
    #[structopt(short, long)]
    pub local: bool,
    /// Is this the first node in a section?
    #[structopt(short, long)]
    pub first: bool,
    #[structopt(flatten)]
    #[allow(missing_docs)]
    pub network_config: NetworkConfig,
    /// dump shell completions for: [bash, fish, zsh, powershell, elvish]
    #[structopt(long)]
    pub completions: Option<String>,
    /// Send logs to a file within the specified directory
    #[structopt(long)]
    pub log_dir: Option<PathBuf>,
    /// Attempt to self-update?
    #[structopt(long)]
    pub update: bool,
    /// Attempt to self-update without starting the node process
    #[structopt(long)]
    pub update_only: bool,
    /// Delete all data from a previous node running on the same PC
    #[structopt(long)]
    pub clear_data: bool,
}

impl Config {
    /// Returns a new `Config` instance.  Tries to read from the default node config file location,
    /// and overrides values with any equivalent command line args.
    pub fn new() -> Result<Self, Error> {
        let mut config = match Self::read_from_file() {
            Ok(Some(config)) => config,
            Ok(None) | Err(_) => Default::default(),
        };
        let command_line_args = Config::clap().get_matches();

        for arg in &ARGS {
            let occurrences = command_line_args.occurrences_of(arg);
            if occurrences != 0 {
                if let Some(cla) = command_line_args.value_of(arg) {
                    config.set_value(arg, cla)?;
                } else {
                    config.set_flag(arg, occurrences);
                }
            }
        }

        config.clear_data_from_disk().unwrap_or_else(|_| {
            log::error!("Error deleting data file from disk");
        });

        Ok(config)
    }

    /// The address to be credited when this node farms SafeCoin.
    pub fn wallet_id(&self) -> Option<&String> {
        self.wallet_id.as_ref()
    }

    /// Is this the first node in a section?
    pub fn is_first(&self) -> bool {
        self.first
    }

    /// Is the node running for a local section?
    pub fn is_local(&self) -> bool {
        self.local
    }

    /// Upper limit in bytes for allowed network storage on this node.
    pub fn max_capacity(&self) -> u64 {
        self.max_capacity.unwrap_or(DEFAULT_MAX_CAPACITY)
    }

    /// Root directory for `ChunkStore`s and cached state. If not set, it defaults to
    /// `DEFAULT_ROOT_DIR_NAME` within the project's data directory (see `Config::root_dir` for the
    /// directories on each platform).
    pub fn root_dir(&self) -> Result<PathBuf> {
        Ok(match &self.root_dir {
            Some(root_dir) => root_dir.clone(),
            None => project_dirs()?.join(DEFAULT_ROOT_DIR_NAME),
        })
    }

    /// Set the root directory for `ChunkStore`s and cached state.
    pub fn set_root_dir<P: Into<PathBuf>>(&mut self, path: P) {
        self.root_dir = Some(path.into())
    }

    /// Set the directory to write the logs.
    pub fn set_log_dir<P: Into<PathBuf>>(&mut self, path: P) {
        self.log_dir = Some(path.into())
    }

    /// Get the log level.
    pub fn verbose(&self) -> Level {
        match self.verbose {
            0 => Level::Error,
            1 => Level::Warn,
            2 => Level::Info,
            3 => Level::Debug,
            _ => Level::Trace,
        }
    }

    /// Network configuration options.
    pub fn network_config(&self) -> &NetworkConfig {
        &self.network_config
    }

    /// Set network configuration options.
    pub fn set_network_config(&mut self, config: NetworkConfig) {
        self.network_config = config;
    }

    /// Get the completions option
    pub fn completions(&self) -> &Option<String> {
        &self.completions
    }

    /// Directory where to write log file/s if specified
    pub fn log_dir(&self) -> &Option<PathBuf> {
        &self.log_dir
    }

    /// Attempt to self-update?
    pub fn update(&self) -> bool {
        self.update
    }

    /// Attempt to self-update without starting the node process
    pub fn update_only(&self) -> bool {
        self.update_only
    }

    /// Set the Quic-P2P `ip` configuration to 127.0.0.1.
    pub fn listen_on_loopback(&mut self) {
        self.network_config.local_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    pub(crate) fn set_value(&mut self, arg: &str, value: &str) -> Result<(), Error> {
        if arg == "wallet-id" {
            self.wallet_id =
                Some(value.parse().map_err(|e: Infallible| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "max-capacity" {
            self.max_capacity =
                Some(value.parse().map_err(|e: ParseIntError| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "root-dir" {
            self.root_dir =
                Some(value.parse().map_err(|e: Infallible| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "verbose" {
            self.verbose = value
                .parse()
                .map_err(|e: ParseIntError| Error::Logic(format!("Config file error: {:?}", e)))?;
        } else if arg == "hard-coded-contacts" {
            self.network_config.hard_coded_contacts = serde_json::from_str(value)
                .map_err(|e| Error::Logic(format!("Config file error: {:?}", e)))?;
        } else if arg == "local-port" {
            self.network_config.local_port =
                Some(value.parse().map_err(|e: ParseIntError| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "local-ip" {
            self.network_config.local_ip = Some(value.parse().map_err(|e: AddrParseError| {
                Error::Logic(format!("Config file error: {:?}", e))
            })?);
        } else if arg == "completions" {
            self.completions =
                Some(value.parse().map_err(|e: Infallible| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "log-dir" {
            self.log_dir =
                Some(value.parse().map_err(|e: Infallible| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "max-msg-size-allowed" {
            self.network_config.max_msg_size_allowed =
                Some(value.parse().map_err(|e: ParseIntError| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "idle-timeout-msec" {
            self.network_config.idle_timeout_msec =
                Some(value.parse().map_err(|e: ParseIntError| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "keep-alive-interval-msec" {
            self.network_config.keep_alive_interval_msec =
                Some(value.parse().map_err(|e: ParseIntError| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else if arg == "upnp-lease-duration" {
            self.network_config.upnp_lease_duration =
                Some(value.parse().map_err(|e: ParseIntError| {
                    Error::Logic(format!("Config file error: {:?}", e))
                })?);
        } else {
            println!("ERROR");
        }
        Ok(())
    }

    pub(crate) fn set_flag(&mut self, arg: &str, occurrences: u64) {
        if arg == "verbose" {
            self.verbose = occurrences;
        } else if arg == "first" {
            self.first = occurrences >= 1;
        } else if arg == "update" {
            self.update = occurrences >= 1;
        } else if arg == "update-only" {
            self.update_only = occurrences >= 1;
        } else if arg == "local" {
            self.local = occurrences >= 1;
        } else if arg == "clear-data" {
            self.clear_data = occurrences >= 1;
        } else {
            println!("ERROR");
        }
    }

    // Clear data from of a previous node running on the same PC
    fn clear_data_from_disk(&self) -> Result<()> {
        if self.clear_data {
            let path = project_dirs()?.join(self.root_dir()?);
            if path.exists() {
                std::fs::remove_dir_all(&path)?;
            }
        }
        Ok(())
    }

    /// Reads the default node config file.
    fn read_from_file() -> Result<Option<Config>> {
        let path = project_dirs()?.join(CONFIG_FILE);

        match File::open(&path) {
            Ok(file) => {
                debug!("Reading settings from {}", path.display());
                let reader = BufReader::new(file);
                let config = serde_json::from_reader(reader)?;
                Ok(config)
            }
            Err(error) => {
                if error.kind() == std::io::ErrorKind::NotFound {
                    debug!("No config file available at {}", path.display());
                    Ok(None)
                } else {
                    Err(error.into())
                }
            }
        }
    }

    /// Writes a Node config file **for use by tests and examples**.
    ///
    /// The file is written to the `current_bin_dir()` with the appropriate file name.
    ///
    /// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
    /// the config file should be created by the Node's installer.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn write_config_file(&self) -> Result<PathBuf> {
        write_file(CONFIG_FILE, self)
    }
}

/// Writes connection info to file for use by clients.
///
/// The file is written to the `home_dir()` with the appropriate file name.
pub fn write_connection_info(contact: SocketAddr) -> Result<PathBuf> {
    let file_name = &contact.port().to_string();
    let mut bootstrap_path = project_dirs()?;
    bootstrap_path.push("bootstrap");
    fs::create_dir_all(bootstrap_path.clone())?;
    let path = bootstrap_path.join(file_name);
    let mut file = File::create(&path)?;
    let contact_info: HashSet<SocketAddr> = vec![contact].into_iter().collect();
    serde_json::to_writer_pretty(&mut file, &contact_info)?;
    file.sync_all()?;
    Ok(path)
}

fn write_file<T: ?Sized>(file: &str, config: &T) -> Result<PathBuf>
where
    T: Serialize,
{
    let project_dirs = project_dirs()?;
    fs::create_dir_all(project_dirs.clone())?;

    let path = project_dirs.join(file);
    let mut file = File::create(&path)?;
    serde_json::to_writer_pretty(&mut file, config)?;
    file.sync_all()?;

    Ok(path)
}

fn project_dirs() -> Result<PathBuf> {
    let mut home_dir = dirs_next::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found"))?;

    home_dir.push(".safe");
    home_dir.push("node");

    Ok(home_dir)
}

#[cfg(test)]
mod test {
    //use super::ARGS;
    use super::{Config, Error, Result};
    use std::{fs::File, io::Read, path::Path};
    //use structopt::StructOpt;

    // #[test]
    // fn smoke() -> Result<()> {
    //     let app_name = Config::clap().get_name().to_string();
    //     let test_values = [
    //         ["wallet-id", "86a23e052dd07f3043f5b98e3add38764d7384f105a25eddbce62f3e02ac13467ff4565ff31bd3f1801d86e2ef79c103"],
    //         ["max-capacity", "1"],
    //         ["root-dir", "dir"],
    //         ["verbose", "None"],
    //         ["hard-coded-contacts", "[\"127.0.0.1:33292\"]"],
    //         ["local-port", "1"],
    //         ["local-ip", "127.0.0.1"],
    //         ["max-msg-size-allowed", "1"],
    //         ["idle-timeout-msec", "1"],
    //         ["keep-alive-interval-msec", "1"],
    //         ["first", "None"],
    //         ["completions", "bash"],
    //         ["log-dir", "log-dir-path"],
    //         ["update", "None"],
    //         ["update-only", "None"],
    //         ["local", "None"],
    //         ["upnp-lease-duration", "180"],
    //         ["clear-data", "None"],
    //     ];

    //     for arg in &ARGS {
    //         let user_arg = format!("--{}", arg);
    //         let value = test_values
    //             .iter()
    //             .find(|elt| &elt[0] == arg)
    //             .ok_or_else(|| Error::Logic(format!("Missing arg: {:?}", &arg)))?[1];
    //         let matches = if value == "None" {
    //             Config::clap().get_matches_from(&[app_name.as_str(), user_arg.as_str()])
    //         } else {
    //             Config::clap().get_matches_from(&[app_name.as_str(), user_arg.as_str(), value])
    //         };
    //         let occurrences = matches.occurrences_of(arg);
    //         assert_eq!(1, occurrences);

    //         let mut config = Config {
    //             local: false,
    //             wallet_id: None,
    //             max_capacity: None,
    //             root_dir: None,
    //             verbose: 0,
    //             network_config: Default::default(),
    //             first: false,
    //             completions: None,
    //             log_dir: None,
    //             update: false,
    //             update_only: false,
    //             clear_data: false,
    //         };
    //         let empty_config = config.clone();
    //         if let Some(val) = matches.value_of(arg) {
    //             config.set_value(arg, val)?;
    //         } else {
    //             config.set_flag(arg, occurrences);
    //         }
    //         assert_ne!(empty_config, config, "Failed to set_value() for {}", arg);
    //     }
    //     Ok(())
    // }

    #[ignore]
    #[test]
    fn parse_sample_config_file() -> Result<(), Error> {
        let path = Path::new("installer/common/sample.node.config").to_path_buf();
        let mut file =
            File::open(&path).map_err(|e| Error::Logic(format!("Config file error: {:?}", e)))?;
        let mut encoded_contents = String::new();
        let _ = file
            .read_to_string(&mut encoded_contents)
            .map_err(|e| Error::Logic(format!("Config file error: {:?}", e)))?;
        let config: Config = serde_json::from_str(&encoded_contents)
            .map_err(|e| Error::Logic(format!("Config file error: {:?}", e)))?;

        assert!(
            config.wallet_id.is_some(),
            "{} is missing `wallet_id` field.",
            path.display()
        );
        assert!(
            config.max_capacity.is_some(),
            "{} is missing `max_capacity` field.",
            path.display()
        );
        assert!(
            config.root_dir.is_some(),
            "{} is missing `root_dir` field.",
            path.display()
        );
        Ok(())
    }
}
