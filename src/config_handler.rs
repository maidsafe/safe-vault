// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{quic_p2p::Config as QuicP2pConfig, quic_p2p::NodeInfo, Result};
use directories::ProjectDirs;
use lazy_static::lazy_static;
use log::{trace, Level};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{self, BufReader},
    net::{IpAddr, Ipv4Addr},
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
const ARGS: [&str; 12] = [
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
    #[structopt(flatten)]
    #[allow(missing_docs)]
    quic_p2p_config: QuicP2pConfig,
}

impl Config {
    /// Returns a new `Config` instance.  Tries to read from the default vault config file location,
    /// and overrides values with any equivalent command line args.
    pub fn new() -> Self {
        let mut config = Self::read_from_file().unwrap_or(Self {
            wallet_address: None,
            max_capacity: None,
            root_dir: None,
            verbose: 0,
            quic_p2p_config: Default::default(),
        });

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

        config
    }

    /// The address to be credited when this vault farms SafeCoin.
    pub fn wallet_address(&self) -> Option<&String> {
        self.wallet_address.as_ref()
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

    /// Quic-P2P configuration options.
    pub fn quic_p2p_config(&self) -> &QuicP2pConfig {
        &self.quic_p2p_config
    }

    /// Set Quic-P2P configuration options.
    pub fn set_quic_p2p_config(&mut self, config: QuicP2pConfig) {
        self.quic_p2p_config = config;
    }

    /// Set the Quic-P2P `ip` configuration to 127.0.0.1.
    pub fn listen_on_loopback(&mut self) {
        self.quic_p2p_config.ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
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
            self.quic_p2p_config.hard_coded_contacts = unwrap!(serde_json::from_str(value));
        } else if arg == ARGS[5] {
            self.quic_p2p_config.port = Some(unwrap!(value.parse()));
        } else if arg == ARGS[6] {
            self.quic_p2p_config.ip = Some(unwrap!(value.parse()));
        } else if arg == ARGS[11] {
            self.quic_p2p_config.our_type = unwrap!(value.parse());
        } else {
            #[cfg(not(feature = "mock"))]
            {
                if arg == ARGS[7] {
                    self.quic_p2p_config.max_msg_size_allowed = Some(unwrap!(value.parse()));
                } else if arg == ARGS[8] {
                    self.quic_p2p_config.idle_timeout_msec = Some(unwrap!(value.parse()));
                } else if arg == ARGS[9] {
                    self.quic_p2p_config.keep_alive_interval_msec = Some(unwrap!(value.parse()));
                } else if arg == ARGS[10] {
                    self.quic_p2p_config.our_complete_cert = Some(unwrap!(value.parse()));
                } else {
                    println!("ERROR");
                }
            }

            #[cfg(feature = "mock")]
            println!("ERROR");
        }
    }

    fn set_flag(&mut self, arg: &str, occurrences: u64) {
        if arg == ARGS[3] {
            self.verbose = occurrences;
        } else {
            println!("ERROR");
        }
    }

    /// Reads the default vault config file.
    fn read_from_file() -> Result<Config> {
        let path = project_dirs()?.config_dir().join(CONFIG_FILE);
        let file = match File::open(&path) {
            Ok(file) => {
                trace!("Reading settings from {}", path.display());
                file
            }
            Err(error) => {
                trace!("No config file available at {}", path.display());
                return Err(error.into());
            }
        };
        let reader = BufReader::new(file);
        let config = serde_json::from_reader(reader)?;
        Ok(config)
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
pub fn write_config_file(config: &Config) -> Result<PathBuf> {
    write_file(CONFIG_FILE, config)
}

/// Writes connection info to file for use by clients.
///
/// The file is written to the `current_bin_dir()` with the appropriate file name.
pub fn write_connection_info(node_info: &NodeInfo) -> Result<PathBuf> {
    write_file(CONNECTION_INFO_FILE, node_info)
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
    #[cfg(not(feature = "mock"))]
    use super::ARGS;
    use serde_json;
    #[cfg(not(feature = "mock"))]
    use std::mem;
    use std::{fs::File, io::Read, path::Path};
    #[cfg(not(feature = "mock"))]
    use structopt::StructOpt;
    use unwrap::unwrap;

    #[cfg(not(feature = "mock"))]
    #[test]
    fn smoke() {
        let expected_size = if cfg!(target_pointer_width = "64") {
            240
        } else {
            152
        };
        assert_eq!(
            expected_size,
            mem::size_of::<Config>(),
            "Ensure that any changes to `Config` are reflected in `ARGS`."
        );

        let app_name = Config::clap().get_name().to_string();
        let certificate = quic_p2p::SerialisableCertificate::default();
        let node_info = format!(
            "[{{\"peer_addr\":\"127.0.0.1:33292\",\"peer_cert_der\":{:?}}}]",
            certificate.cert_der
        );
        let cert_str = certificate.to_string();
        let test_values = [
            ["wallet-address", "abc"],
            ["max-capacity", "1"],
            ["root-dir", "dir"],
            ["verbose", "None"],
            ["hard-coded-contacts", node_info.as_str()],
            ["port", "1"],
            ["ip", "127.0.0.1"],
            ["max-msg-size-allowed", "1"],
            ["idle-timeout-msec", "1"],
            ["keep-alive-interval-msec", "1"],
            ["our-complete-cert", cert_str.as_str()],
            ["our-type", "client"],
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
                quic_p2p_config: Default::default(),
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
