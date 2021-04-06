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
    /// If the node is the first node on the network, the local address to be used should be passed.
    /// To use a random port number, use 0. If this argument is passed `--local-ip` and `--local-port`
    /// is not requried, however if they are passed, they should match the value provided here.
    #[structopt(long)]
    pub first: Option<SocketAddr>,
    /// Local address to be used for the node. This field is mandatory if manual port forwarding is being used.
    /// Otherwise, the value is fetched from `--first` (for genesis) and obtained by connecting to the
    /// bootstrap node otherwise.
    #[structopt(long)]
    pub local_addr: Option<SocketAddr>,
    /// External address of the node. This field can be used to specify the external socket address when
    /// manual port forwarding is used. If this field is provided, either `--first` or `--local-addr` must
    /// be provided
    #[structopt(long)]
    pub public_addr: Option<SocketAddr>,
    /// This flag can be used to skip port forwarding using IGD. This is used when running a network on LAN
    /// or when a node is connected to the internect directly without a router. Eg. Digital Ocean droplets.
    #[structopt(long)]
    pub skip_igd: bool,
    /// Hard Coded contacts
    #[structopt(
        short,
        long,
        default_value = "[]",
        parse(try_from_str = serde_json::from_str)
    )]
    pub hard_coded_contacts: HashSet<SocketAddr>,
    /// This is the maximum message size we'll allow the peer to send to us. Any bigger message and
    /// we'll error out probably shutting down the connection to the peer. If none supplied we'll
    /// default to the documented constant.
    #[structopt(long)]
    pub max_msg_size_allowed: Option<u32>,
    /// If we hear nothing from the peer in the given interval we declare it offline to us. If none
    /// supplied we'll default to the documented constant.
    ///
    /// The interval is in milliseconds. A value of 0 disables this feature.
    #[structopt(long)]
    pub idle_timeout_msec: Option<u64>,
    /// Interval to send keep-alives if we are idling so that the peer does not disconnect from us
    /// declaring us offline. If none is supplied we'll default to the documented constant.
    ///
    /// The interval is in milliseconds. A value of 0 disables this feature.
    #[structopt(long)]
    pub keep_alive_interval_msec: Option<u32>,
    /// Directory in which the bootstrap cache will be stored. If none is supplied, the platform specific
    /// default cache directory is used.
    #[structopt(long)]
    pub bootstrap_cache_dir: Option<String>,
    /// Duration of a UPnP port mapping.
    #[structopt(long)]
    pub upnp_lease_duration: Option<u32>,
    #[structopt(skip)]
    #[allow(missing_docs)]
    pub network_config: NetworkConfig,
}

impl Config {
    /// Returns a new `Config` instance.  Tries to read from the default node config file location,
    /// and overrides values with any equivalent command line args.
    pub fn new() -> Result<Self, Error> {
        let mut config = match Self::read_from_file() {
            Ok(Some(config)) => config,
            Ok(None) | Err(_) => Default::default(),
        };

        let mut command_line_args = Config::from_args();
        command_line_args.validate()?;

        if let Some(socket_addr) = command_line_args.first {
            command_line_args.local_addr = Some(socket_addr);
        }

        config.merge(command_line_args);

        config.clear_data_from_disk().unwrap_or_else(|_| {
            log::error!("Error deleting data file from disk");
        });

        Ok(config)
    }

    fn validate(&mut self) -> Result<(), Error> {
        if let Some(external_addr) = self.public_addr {
            if self.first.is_none() && self.local_addr.is_none() {
                return Err(Error::Configuration("--public-addr passed without specifing local address using --first or --local-addr".to_string()));
            }
        }

        if self.public_addr.is_none() && self.local_addr.is_some() {
            println!("Warning: Local Address provided is skipped since external address is not provided.");
            self.local_addr = None;
        }
        Ok(())
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

        if let Some(completions) = &config.completions {
            self.completions = Some(completions.clone());
        }

        if let Some(log_dir) = &config.log_dir {
            self.log_dir = Some(log_dir.clone());
        }

        self.update = config.update || self.update;
        self.update_only = config.update_only || self.update_only;
        self.clear_data = config.clear_data || self.clear_data;

        if let Some(socket_addr) = config.first {
            self.first = Some(socket_addr);
            self.local_addr = Some(socket_addr);
        }

        if let Some(local_addr) = config.local_addr {
            self.local_addr = config.local_addr;
            self.network_config.local_port = Some(local_addr.port());
            self.network_config.local_ip = Some(local_addr.ip());
        }

        if let Some(public_addr) = config.public_addr {
            self.public_addr = config.public_addr;
            self.network_config.external_port = Some(public_addr.port());
            self.network_config.external_ip = Some(public_addr.ip());
        }

        self.network_config.forward_port = !config.skip_igd;

        if !config.hard_coded_contacts.is_empty() {
            self.network_config.hard_coded_contacts = config.hard_coded_contacts;
        }

        if let Some(max_msg_size) = config.max_msg_size_allowed {
            self.network_config.max_msg_size_allowed = Some(max_msg_size);
        }

        if let Some(idle_timeout) = config.idle_timeout_msec {
            self.network_config.idle_timeout_msec = Some(idle_timeout);
        }

        if let Some(keep_alive) = config.keep_alive_interval_msec {
            self.network_config.keep_alive_interval_msec = Some(keep_alive);
        }

        if let Some(bootstrap_cache_dir) = config.bootstrap_cache_dir {
            self.network_config.bootstrap_cache_dir = Some(bootstrap_cache_dir);
        }

        if let Some(upnp_lease_duration) = config.upnp_lease_duration {
            self.network_config.upnp_lease_duration = Some(upnp_lease_duration);
        }
    }

    /// The address to be credited when this node farms SafeCoin.
    pub fn wallet_id(&self) -> Option<&String> {
        self.wallet_id.as_ref()
    }

    /// Is this the first node in a section?
    pub fn is_first(&self) -> bool {
        self.first.is_some()
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

/// Writes connection info to file for use by clients (and joining nodes when local network).
///
/// The file is written to the `current_bin_dir()` with the appropriate file name.
pub fn add_connection_info(contact: SocketAddr) -> Result<PathBuf> {
    let hard_coded_contacts = if let Some(mut hard_coded_contacts) = read_conn_info_from_file()? {
        let _ = hard_coded_contacts.insert(contact);
        hard_coded_contacts
    } else {
        vec![contact].into_iter().collect()
    };

    write_file(CONNECTION_INFO_FILE, &hard_coded_contacts)
}

/// Removes connection info from file.
///
/// The file is written to the `current_bin_dir()` with the appropriate file name.
pub fn remove_connection_info(contact: SocketAddr) -> Result<PathBuf> {
    if let Some(mut hard_coded_contacts) = read_conn_info_from_file()? {
        let _ = hard_coded_contacts.remove(&contact);
        write_file(CONNECTION_INFO_FILE, &hard_coded_contacts)
    } else {
        Err(Error::Logic("Connection info file not found".to_string()))
    }
}

/// Reads the default node config file.
fn read_conn_info_from_file() -> Result<Option<HashSet<SocketAddr>>> {
    let path = project_dirs()?.join(CONNECTION_INFO_FILE);

    match File::open(&path) {
        Ok(file) => {
            debug!("Reading connection info from {}", path.display());
            let reader = BufReader::new(file);
            let config = serde_json::from_reader(reader)?;
            Ok(config)
        }
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                debug!("No connection info file available at {}", path.display());
                Ok(None)
            } else {
                Err(error.into())
            }
        }
    }
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
    let expected_size = 504;

    assert_eq!(std::mem::size_of::<Config>(), expected_size);
}
