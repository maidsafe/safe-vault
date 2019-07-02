// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{quic_p2p::Config as QuicP2pConfig, Result};
use directories::ProjectDirs;
use log::trace;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::{
    env,
    fs::File,
    io::{self, BufReader},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};
use structopt::StructOpt;
use unwrap::unwrap;

const CONFIG_DIR_QUALIFIER: &str = "net";
const CONFIG_DIR_ORGANISATION: &str = "MaidSafe";
const CONFIG_DIR_APPLICATION: &str = "safe_vault";
const CONFIG_FILE: &str = "vault.config";
const DEFAULT_ROOT_DIR_NAME: &str = "safe_vault";
const DEFAULT_MAX_CAPACITY: u64 = 2 * 1024 * 1024 * 1024;
const ARGS: [&str; 11] = [
    "wallet-address",
    "max-capacity",
    "root-dir",
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
#[structopt(rename_all = "kebab-case")]
pub struct Config {
    /// The address to be credited when this vault farms SafeCoin.
    #[structopt(short, long, parse(try_from_str))]
    // TODO - Fix before committing - Use ClientPublicId rather than String
    wallet_address: Option<String>,
    /// Upper limit in bytes for allowed network storage on this vault.
    #[structopt(short, long)]
    max_capacity: Option<u64>,
    /// Root directory for ChunkStores and cached state.  If not set, it defaults to "safe_vault"
    /// within a temporary directory, e.g. %TMP% or $TMPDIR.
    #[structopt(short, long, parse(from_os_str))]
    root_dir: Option<PathBuf>,
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
            quic_p2p_config: Default::default(),
        });

        let command_line_args = Config::clap().get_matches();
        for arg in &ARGS {
            if command_line_args.occurrences_of(arg) != 0 {
                config.set_value(arg, unwrap!(command_line_args.value_of(arg)));
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

    /// Root directory for `ChunkStore`s and cached state.  If not set, it defaults to
    /// `DEFAULT_ROOT_DIR_NAME` within
    /// [`env::temp_dir()`](https://doc.rust-lang.org/std/env/fn.temp_dir.html).
    pub fn root_dir(&self) -> PathBuf {
        self.root_dir
            .clone()
            .unwrap_or_else(|| env::temp_dir().join(DEFAULT_ROOT_DIR_NAME))
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
            self.quic_p2p_config.hard_coded_contacts = unwrap!(serde_json::from_str(value));
        } else if arg == ARGS[4] {
            self.quic_p2p_config.port = Some(unwrap!(value.parse()));
        } else if arg == ARGS[5] {
            self.quic_p2p_config.ip = Some(unwrap!(value.parse()));
        } else if arg == ARGS[10] {
            self.quic_p2p_config.our_type = unwrap!(value.parse());
        } else {
            #[cfg(not(feature = "mock"))]
            {
                if arg == ARGS[6] {
                    self.quic_p2p_config.max_msg_size_allowed = Some(unwrap!(value.parse()));
                } else if arg == ARGS[7] {
                    self.quic_p2p_config.idle_timeout_msec = Some(unwrap!(value.parse()));
                } else if arg == ARGS[8] {
                    self.quic_p2p_config.keep_alive_interval_msec = Some(unwrap!(value.parse()));
                } else if arg == ARGS[9] {
                    self.quic_p2p_config.our_complete_cert = Some(unwrap!(value.parse()));
                } else {
                    println!("ERROR");
                }
            }

            #[cfg(feature = "mock")]
            println!("ERROR");
        }
    }

    /// Reads the default vault config file.
    fn read_from_file() -> Result<Config> {
        let path = dirs()?.config_dir().join(CONFIG_FILE);
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
    let dirs = dirs()?;
    let dir = dirs.config_dir();
    fs::create_dir_all(dir)?;

    let path = dir.join(CONFIG_FILE);
    let mut file = File::create(&path)?;
    serde_json::to_writer_pretty(&mut file, config)?;
    file.sync_all()?;

    Ok(path)
}

fn dirs() -> Result<ProjectDirs> {
    ProjectDirs::from(
        CONFIG_DIR_QUALIFIER,
        CONFIG_DIR_ORGANISATION,
        CONFIG_DIR_APPLICATION,
    )
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
            216
        } else {
            160
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
            let matches =
                Config::clap().get_matches_from(&[app_name.as_str(), user_arg.as_str(), value]);
            assert_eq!(1, matches.occurrences_of(arg));

            let mut config = Config {
                wallet_address: None,
                max_capacity: None,
                root_dir: None,
                quic_p2p_config: Default::default(),
            };
            let empty_config = config.clone();
            config.set_value(arg, unwrap!(matches.value_of(arg)));
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
