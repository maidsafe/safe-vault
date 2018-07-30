// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use config_file_handler::{self, FileHandler};
use error::InternalError;
use routing::XorName;
use safe_crypto::PublicSignKey;
use std::ffi::OsString;

/// Lets a vault configure a wallet address and storage limit.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    /// Used to store the address where SafeCoin will be sent.
    pub wallet_address: Option<XorName>,
    /// Upper limit for allowed network storage on this vault.
    pub max_capacity: Option<u64>, // measured by Bytes
    /// Root directory for chunk_store directories.
    pub chunk_store_root: Option<String>,
    /// Key that is allowed to put mutable data for account creation invitations.
    pub invite_key: Option<PublicSignKey>,
    /// Developer options.
    pub dev: Option<DevConfig>,
}

/// Extra configuration options intended for developers
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DevConfig {
    /// Allow clients to make unlimited mutation requests, i.e. ignore `DEFAULT_MAX_OPS_COUNT`.
    pub disable_mutation_limit: bool,
}

/// Reads the default vault config file.
pub fn read_config_file() -> Result<Config, InternalError> {
    // if the config file is not present, a default one will be generated
    let file_handler = FileHandler::new(&get_file_name()?, false)?;
    let cfg = file_handler.read_file()?;
    Ok(cfg)
}

/// Writes a Vault config file **for use by tests and examples**.
///
/// The file is written to the `current_bin_dir()`
/// with the appropriate file name.
///
/// N.B. This method should only be used as a utility for test and examples.  In normal use cases,
/// the config file should be created by the Vault's installer.
#[cfg(test)]
#[allow(dead_code)]
pub fn write_config_file(config: &Config) -> Result<::std::path::PathBuf, InternalError> {
    use serde_json;
    use std::fs::File;
    use std::io::Write;

    let mut config_path = config_file_handler::current_bin_dir()?;
    config_path.push(get_file_name()?);
    let mut file = File::create(&config_path)?;
    write!(&mut file, "{}", serde_json::to_string_pretty(&config)?)?;
    file.sync_all()?;
    Ok(config_path)
}

fn get_file_name() -> Result<OsString, InternalError> {
    let mut name = config_file_handler::exe_file_stem()?;
    name.push(".vault.config");
    Ok(name)
}

#[cfg(test)]
mod test {
    use super::Config;
    use serde_json;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

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
            config.chunk_store_root.is_some(),
            "{} is missing `chunk_store_root` field.",
            path.display()
        );
        assert!(
            config.invite_key.is_some(),
            "{} is missing `invite_key` field.",
            path.display()
        );
        assert!(
            config.dev.is_some(),
            "{} is missing `dev` field.",
            path.display()
        );
    }
}
