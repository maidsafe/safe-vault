// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::routing::NetworkConfig;
use crate::Result;
use directories::ProjectDirs;
use lazy_static::lazy_static;
use log::Level;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use structopt::StructOpt;
use unwrap::unwrap;

lazy_static! {
    static ref PROJECT_DIRS: Option<ProjectDirs> = ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        CONFIG_DIR_APPLICATION,
    );
}

const CONFIG_DIR_QUALIFIER: &str = "net";
const CONFIG_DIR_ORGANISATION: &str = "MaidSafe";
const CONFIG_DIR_APPLICATION: &str = "safe_vault";
const CONFIG_FILE: &str = "vault.config";
const CONNECTION_INFO_FILE: &str = "vault_connection_info.config";
const DEFAULT_ROOT_DIR_NAME: &str = "root_dir";
const DEFAULT_MAX_CAPACITY: u64 = 2 * 1024 * 1024 * 1024;
const ARGS: [&str; 17] = [
    "wallet-address",
    "max-capacity",
    "root-dir",
    "verbose",
    "hard-coded-contacts",
    "port",
    "ip",
    "max-msg-size-allowed",
    "idle-timeout-msec",
    "keep-alive-interval-msec",
    "our-complete-cert",
    "our-type",
    "first",
    "completions",
    "log-dir",
    "update",
    "update-only",
];

/// Vault configuration
#[derive(Default, Clone, Debug, Serialize, Deserialize, Eq, PartialEq, StructOpt)]
#[structopt(rename_all = "kebab-case", bin_name = "safe_vault")]
#[structopt(raw(global_settings = "&[structopt::clap::AppSettings::ColoredHelp]"))]
pub struct Config {
    /// The address to be credited when this vault farms SafeCoin.
    #[structopt(short, long, parse(try_from_str))]
    // TODO - Fix before committing - Use ClientPublicId rather than String
    wallet_address: Option<String>,
    /// Upper limit in bytes for allowed network storage on this vault.
    #[structopt(short, long)]
    max_capacity: Option<u64>,
    /// Root directory for ChunkStores and cached state. If not set, it defaults to "root_dir"
    /// within the safe_vault project data directory, located at... Linux: $XDG_DATA_HOME/safe_vault
    /// or $HOME/.local/share/safe_vault | Windows:
    /// {FOLDERID_RoamingAppData}/MaidSafe/safe_vault/data | MacOS: $HOME/Library/Application
    /// Support/net.MaidSafe.safe_vault
    #[structopt(short, long, parse(from_os_str))]
    root_dir: Option<PathBuf>,
    /// Verbose output. `-v` is equivalent to logging with `warn`, `-vv` to `info`, `-vvv` to
    /// `debug`, `-vvvv` to `trace`. This flag overrides RUST_LOG.
    #[structopt(short, long, parse(from_occurrences))]
    verbose: u64,
    /// Is this the first node in a section?
    #[structopt(short, long)]
    first: bool,
    #[structopt(flatten)]
    #[allow(missing_docs)]
    network_config: NetworkConfig,
    /// dump shell completions for: [bash, fish, zsh, powershell, elvish]
    #[structopt(long)]
    completions: Option<String>,
    /// Send logs to a file within the specified directory
    #[structopt(long)]
    log_dir: Option<String>,
    /// Attempt to self-update?
    #[structopt(long)]
    update: bool,
    /// Attempt to self-update without starting the vault process
    #[structopt(long, name = "update-only")]
    update_only: bool,
}

impl Config {
    /// Returns a new `Config` instance.  Tries to read from the default vault config file location,
    /// and overrides values with any equivalent command line args.
    pub fn new() -> Result<Self> {
        let mut config = Self::read_from_file()?.unwrap_or_default();

        let command_line_args = Config::clap().get_matches();
        for arg in &ARGS {
            let occurrences = command_line_args.occurrences_of(arg);
            if occurrences != 0 {
                if let Some(cla) = command_line_args.value_of(arg) {
                    config.set_value(arg, cla);
                } else {
                    config.set_flag(arg, occurrences);
                }
            }
        }

        Ok(config)
    }

    /// The address to be credited when this vault farms SafeCoin.
    pub fn wallet_address(&self) -> Option<&String> {
        self.wallet_address.as_ref()
    }

    /// Is this the first node in a section?
    pub fn is_first(&self) -> bool {
        self.first
    }

    /// Upper limit in bytes for allowed network storage on this vault.
    pub fn max_capacity(&self) -> u64 {
        self.max_capacity.unwrap_or(DEFAULT_MAX_CAPACITY)
    }

    /// Root directory for `ChunkStore`s and cached state. If not set, it defaults to
    /// `DEFAULT_ROOT_DIR_NAME` within the project's data directory (see `Config::root_dir` for the
    /// directories on each platform).
    pub fn root_dir(&self) -> Result<PathBuf> {
        Ok(match &self.root_dir {
            Some(root_dir) => root_dir.clone(),
            None => project_dirs()?.data_dir().join(DEFAULT_ROOT_DIR_NAME),
        })
    }

    /// Set the root directory for `ChunkStore`s and cached state.
    pub fn set_root_dir<P: Into<PathBuf>>(&mut self, path: P) {
        self.root_dir = Some(path.into())
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
    pub fn log_dir(&self) -> &Option<String> {
        &self.log_dir
    }

    /// Attempt to self-update?
    pub fn update(&self) -> bool {
        self.update
    }

    /// Attempt to self-update without starting the vault process
    pub fn update_only(&self) -> bool {
        self.update_only
    }

    /// Set the Quic-P2P `ip` configuration to 127.0.0.1.
    pub fn listen_on_loopback(&mut self) {
        self.network_config.ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    fn set_value(&mut self, arg: &str, value: &str) {
        if arg == ARGS[0] {
            self.wallet_address = Some(unwrap!(value.parse()));
        } else if arg == ARGS[1] {
            self.max_capacity = Some(unwrap!(value.parse()));
        } else if arg == ARGS[2] {
            self.root_dir = Some(unwrap!(value.parse()));
        } else if arg == ARGS[3] {
            self.verbose = unwrap!(value.parse());
        } else if arg == ARGS[4] {
            self.network_config.hard_coded_contacts = unwrap!(serde_json::from_str(value));
        } else if arg == ARGS[5] {
            self.network_config.port = Some(unwrap!(value.parse()));
        } else if arg == ARGS[6] {
            self.network_config.ip = Some(unwrap!(value.parse()));
        } else if arg == ARGS[11] {
            self.network_config.our_type = unwrap!(value.parse());
        } else if arg == ARGS[13] {
            self.completions = Some(unwrap!(value.parse()));
        } else if arg == ARGS[14] {
            self.log_dir = Some(unwrap!(value.parse()));
        } else {
            #[cfg(not(feature = "mock_base"))]
            {
                if arg == ARGS[7] {
                    self.network_config.max_msg_size_allowed = Some(unwrap!(value.parse()));
                } else if arg == ARGS[8] {
                    self.network_config.idle_timeout_msec = Some(unwrap!(value.parse()));
                } else if arg == ARGS[9] {
                    self.network_config.keep_alive_interval_msec = Some(unwrap!(value.parse()));
                } else if arg == ARGS[10] {
                    self.network_config.our_complete_cert = Some(unwrap!(value.parse()));
                } else {
                    println!("ERROR");
                }
            }

            #[cfg(feature = "mock_base")]
            println!("ERROR");
        }
    }

    fn set_flag(&mut self, arg: &str, occurrences: u64) {
        if arg == ARGS[3] {
            self.verbose = occurrences;
        } else if arg == ARGS[12] {
            self.first = occurrences >= 1;
        } else if arg == ARGS[15] {
            self.update = occurrences >= 1;
        } else if arg == ARGS[16] {
            self.update_only = occurrences >= 1;
        } else {
            println!("ERROR");
        }
    }

    /// Reads the default vault config file.
    fn read_from_file() -> Result<Option<Config>> {
        let path = project_dirs()?.config_dir().join(CONFIG_FILE);

        match File::open(&path) {
            Ok(file) => {
                println!("Reading settings from {}", path.display());
                let reader = BufReader::new(file);
                let config = serde_json::from_reader(reader)?;
                Ok(config)
            }
            Err(error) => {
                if error.kind() == std::io::ErrorKind::NotFound {
                    println!("No config file available at {}", path.display());
                    Ok(None)
                } else {
                    Err(error.into())
                }
            }
        }
    }

    /// Writes a Vault config file **for use by tests and examples**.
    ///
    /// The file is written to the `current_bin_dir()` with the appropriate file name.
    ///
    /// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
    /// the config file should be created by the Vault's installer.
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn write_config_file(&self) -> Result<PathBuf> {
        write_file(CONFIG_FILE, self)
    }
}

/// Writes connection info to file for use by clients.
///
/// The file is written to the `current_bin_dir()` with the appropriate file name.
pub fn write_connection_info(peer_addr: &SocketAddr) -> Result<PathBuf> {
    write_file(CONNECTION_INFO_FILE, peer_addr)
}

fn write_file<T: ?Sized>(file: &str, config: &T) -> Result<PathBuf>
where
    T: Serialize,
{
    let project_dirs = project_dirs()?;
    let dir = project_dirs.config_dir();
    fs::create_dir_all(dir)?;

    let path = dir.join(file);
    let mut file = File::create(&path)?;
    serde_json::to_writer_pretty(&mut file, config)?;
    file.sync_all()?;

    Ok(path)
}

fn project_dirs() -> Result<&'static ProjectDirs> {
    PROJECT_DIRS
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found").into())
}

#[cfg(test)]
mod test {
    use super::Config;
    #[cfg(not(feature = "mock_base"))]
    use super::ARGS;
    #[cfg(not(feature = "mock_base"))]
    use std::mem;
    use std::{fs::File, io::Read, path::Path};
    #[cfg(not(feature = "mock_base"))]
    use structopt::StructOpt;
    use unwrap::unwrap;

    #[cfg(not(feature = "mock_base"))]
    #[test]
    fn smoke() {
        let expected_size = 344;
        assert_eq!(
            expected_size,
            mem::size_of::<Config>(),
            "Ensure that any changes to `Config` are reflected in `ARGS`."
        );

        let app_name = Config::clap().get_name().to_string();
        let base64_certificate = std::iter::repeat("A")
            .take(400)
            .collect::<Vec<_>>()
            .join("");
        let test_values = [
            ["wallet-address", "abc"],
            ["max-capacity", "1"],
            ["root-dir", "dir"],
            ["verbose", "None"],
            ["hard-coded-contacts", "[\"127.0.0.1:33292\"]"],
            ["port", "1"],
            ["ip", "127.0.0.1"],
            ["max-msg-size-allowed", "1"],
            ["idle-timeout-msec", "1"],
            ["keep-alive-interval-msec", "1"],
            ["our-complete-cert", &base64_certificate],
            ["our-type", "client"],
            ["first", "None"],
            ["completions", "bash"],
            ["log-dir", "log-dir-path"],
            ["update", "None"],
            ["update-only", "None"],
        ];

        for arg in &ARGS {
            let user_arg = format!("--{}", arg);
            let value = unwrap!(test_values.iter().find(|elt| &elt[0] == arg))[1];
            let matches = if value == "None" {
                Config::clap().get_matches_from(&[app_name.as_str(), user_arg.as_str()])
            } else {
                Config::clap().get_matches_from(&[app_name.as_str(), user_arg.as_str(), value])
            };
            let occurrences = matches.occurrences_of(arg);
            assert_eq!(1, occurrences);

            let mut config = Config {
                wallet_address: None,
                max_capacity: None,
                root_dir: None,
                verbose: 0,
                network_config: Default::default(),
                first: false,
                completions: None,
                log_dir: None,
                update: false,
                update_only: false,
            };
            let empty_config = config.clone();
            if let Some(val) = matches.value_of(arg) {
                config.set_value(arg, val);
            } else {
                config.set_flag(arg, occurrences);
            }
            assert!(empty_config != config, "Failed to set_value() for {}", arg);
        }
    }

    #[ignore]
    #[test]
    fn parse_sample_config_file() {
        let path = Path::new("installer/common/sample.vault.config").to_path_buf();
        let mut file = unwrap!(File::open(&path), "Error opening {}:", path.display());
        let mut encoded_contents = String::new();
        let _ = unwrap!(
            file.read_to_string(&mut encoded_contents),
            "Error reading {}:",
            path.display()
        );
        let config: Config = unwrap!(
            serde_json::from_str(&encoded_contents),
            "Error parsing {} as JSON:",
            path.display()
        );

        assert!(
            config.wallet_address.is_some(),
            "{} is missing `wallet_address` field.",
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
    }
}
