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
use serde::{Deserialize, Serialize};
use sn_routing::TransportConfig as NetworkConfig;
use std::convert::Infallible;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::{
    collections::{HashMap, HashSet},
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
    /// Is the node running for a network on localhost ?
    #[structopt(short, long)]
    pub loopback: bool,
    /// Is the node meant for a network running withing a LAN ?
    #[structopt(short, long)]
    pub lan: bool,
    /// Is this the first node in the network ?
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

        let command_line_args = Config::from_args();
        config.merge(command_line_args);

        config.clear_data_from_disk().unwrap_or_else(|_| {
            log::error!("Error deleting data file from disk");
        });

        Ok(config)
    }

    /// Overwrites the current config with the provided values from another config
    fn merge(&mut self, config: Config) {
        if let Some(wallet_id) = config.wallet_id() {
            self.wallet_id = Some(wallet_id.clone());
        }

        if let Some(max_capacity) = &config.max_capacity {
            self.max_capacity = Some(*max_capacity);
        }

        if let Some(root_dir) = &config.root_dir {
            self.root_dir = Some(root_dir.clone());
        }

        if config.verbose > 0 {
            self.verbose = config.verbose;
        }

        self.loopback = config.loopback || self.loopback;
        self.lan = config.lan || self.lan;
        self.first = config.first || self.first;

        if let Some(completions) = &config.completions {
            self.completions = Some(completions.clone());
        }

        if let Some(log_dir) = &config.log_dir {
            self.log_dir = Some(log_dir.clone());
        }

        self.update = config.update || self.update;
        self.update_only = config.update_only || self.update_only;
        self.clear_data = config.clear_data || self.clear_data;

        if !config.network_config.hard_coded_contacts.is_empty() {
            self.network_config.hard_coded_contacts = config.network_config.hard_coded_contacts;
        }

        if let Some(port) = config.network_config.local_port {
            self.network_config.local_port = Some(port);
        }

        if let Some(ip) = config.network_config.local_ip {
            self.network_config.local_ip = Some(ip);
        }

        self.network_config.use_igd = config.network_config.use_igd || self.network_config.use_igd;

        if let Some(port) = config.network_config.external_port {
            self.network_config.external_port = Some(port);
        }

        if let Some(ip) = config.network_config.external_ip {
            self.network_config.external_ip = Some(ip);
        }

        if let Some(max_msg_size) = config.network_config.max_msg_size_allowed {
            self.network_config.max_msg_size_allowed = Some(max_msg_size);
        }

        if let Some(idle_timeout) = config.network_config.idle_timeout_msec {
            self.network_config.idle_timeout_msec = Some(idle_timeout);
        }

        if let Some(keep_alive) = config.network_config.keep_alive_interval_msec {
            self.network_config.keep_alive_interval_msec = Some(keep_alive);
        }

        if let Some(bootstrap_cache_dir) = config.network_config.bootstrap_cache_dir {
            self.network_config.bootstrap_cache_dir = Some(bootstrap_cache_dir);
        }

        if let Some(upnp_lease_duration) = config.network_config.upnp_lease_duration {
            self.network_config.upnp_lease_duration = Some(upnp_lease_duration);
        }
    }

    /// The address to be credited when this node farms SafeCoin.
    pub fn wallet_id(&self) -> Option<&String> {
        self.wallet_id.as_ref()
    }

    /// Is this the first node in a section?
    pub fn is_first(&self) -> bool {
        self.first
    }

    /// Is the node running on localhost ?
    pub fn is_localhost(&self) -> bool {
        self.loopback
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

    /// Writes the config file to disk
    pub fn write_to_disk(&self) -> Result<PathBuf> {
        write_file(CONFIG_FILE, self)
    }
}

/// Writes connection info to file for use by clients.
///
/// The file is written to the `current_bin_dir()` with the appropriate file name.
pub fn write_connection_info(contacts: &HashSet<SocketAddr>) -> Result<PathBuf> {
    write_file(CONNECTION_INFO_FILE, contacts)
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

#[test]
fn smoke() {
    // NOTE: IF this value is being changed due to a change in the config,
    // the change in config also be handled in Config::merge()
    // and in examples/config_handling.rs
    let expected_size = 296;

    assert_eq!(std::mem::size_of::<Config>(), expected_size);
}
