// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities

use crate::{config_handler::Config, Error, Network, Result};
use bls::{self, serde_impl::SerdeSecret};
use bytes::Bytes;
use flexi_logger::{DeferredNow, Logger};
use log::{debug, error};
use log::{Log, Metadata, Record};
use pickledb::{PickleDb, PickleDbDumpPolicy};
use rand::{distributions::Standard, CryptoRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use sn_data_types::{BlsKeypairShare, Keypair};
use std::{fs, path::Path};
use std::{io::Write, time::Duration};

const NODE_MODULE_NAME: &str = "sn_node";
#[allow(unused)]
const PERIODIC_DUMP_INTERVAL: Duration = Duration::from_secs(60);

/// Specifies whether to try loading cached data from disk, or to just construct a new instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Init {
    /// Load cached data from disk
    Load,
    /// Start a new cache instance
    New,
}

pub(crate) fn new_auto_dump_db<D: AsRef<Path>, N: AsRef<Path>>(
    db_dir: D,
    db_name: N,
    init_mode: Init,
) -> Result<PickleDb> {
    let db_path = db_dir.as_ref().join(db_name);
    if init_mode == Init::New {
        debug!("Creating auto dump database at {}", db_path.display());
        fs::create_dir_all(db_dir)?;
        let db = PickleDb::new_json(db_path, PickleDbDumpPolicy::AutoDump);
        return Ok(db);
    }
    debug!("Loading auto dump database at {}", db_path.display());
    let result = PickleDb::load_json(db_path.clone(), PickleDbDumpPolicy::AutoDump);
    if let Err(ref error) = &result {
        error!(
            "Failed to load auto dump db at {}: {}",
            db_path.display(),
            error
        );
    }
    Ok(result?)
}

#[allow(unused)]
pub(crate) fn new_periodic_dump_db<D: AsRef<Path>, N: AsRef<Path>>(
    db_dir: D,
    db_name: N,
    init_mode: Init,
) -> Result<PickleDb> {
    let db_path = db_dir.as_ref().join(db_name);
    if init_mode == Init::New {
        debug!("Creating database at {}", db_path.display());
        match fs::create_dir_all(db_dir) {
            Ok(_) => Ok(()),
            Err(error) => {
                error!("Error making DB. {:?}", error);
                Err(error)
            }
        }?;

        let db = PickleDb::new_json(
            db_path,
            PickleDbDumpPolicy::PeriodicDump(PERIODIC_DUMP_INTERVAL),
        );
        return Ok(db);
    }
    debug!("Loading database at {}", db_path.display());
    let result = PickleDb::load_json(
        db_path.clone(),
        PickleDbDumpPolicy::PeriodicDump(PERIODIC_DUMP_INTERVAL),
    );
    if let Err(ref error) = &result {
        error!("Failed to load {}: {}", db_path.display(), error);
    }
    Ok(result?)
}

pub(crate) fn random_vec<R: CryptoRng + Rng>(rng: &mut R, size: usize) -> Vec<u8> {
    rng.sample_iter(&Standard).take(size).collect()
}

pub(crate) fn serialise<T: Serialize>(data: &T) -> Result<Bytes> {
    let serialised_data = bincode::serialize(data).map_err(Error::Bincode)?;
    Ok(Bytes::copy_from_slice(serialised_data.as_slice()))
}

#[allow(unused)]
pub(crate) fn deserialise<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(Error::Bincode)
}

// NB: needs to allow for nodes not having a key share yet?
pub(crate) async fn key_pair(routing: Network) -> Result<Keypair> {
    let index = routing.our_index().await?;
    let bls_secret_key = routing.secret_key_share().await?;
    let secret = SerdeSecret(bls_secret_key.clone());
    let public = bls_secret_key.public_key_share();
    let public_key_set = routing.public_key_set().await?;
    Ok(Keypair::BlsShare(BlsKeypairShare {
        index,
        secret,
        public,
        public_key_set,
    }))
}

/// Initialize logging
pub fn init_logging(config: &Config) {
    // Custom formatter for logs
    let do_format = move |writer: &mut dyn Write, clock: &mut DeferredNow, record: &Record| {
        let handle = std::thread::current();
        write!(
            writer,
            "[{}] {} {} [{}:{}] {}",
            handle
                .name()
                .unwrap_or(&format!("Thread-{:?}", handle.id())),
            record.level(),
            clock.now().to_rfc3339(),
            record.file().unwrap_or_default(),
            record.line().unwrap_or_default(),
            record.args()
        )
    };

    let level_filter = config.verbose().to_level_filter();
    let module_log_filter = format!("{}={}", NODE_MODULE_NAME, level_filter.to_string());
    let logger = Logger::with_env_or_str(module_log_filter)
        .format(do_format)
        .suppress_timestamp();

    let logger = if let Some(log_dir) = config.log_dir() {
        logger.log_to_file().directory(log_dir)
    } else {
        logger
    };

    if let Ok((logger, _)) = logger.build() {
        let logger = LoggerWrapper(logger);

        async_log::Logger::wrap(logger, || 5433)
            .start(config.verbose().to_level_filter())
            .unwrap_or(());
    }
}

struct LoggerWrapper(Box<dyn Log>);

impl Log for LoggerWrapper {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.0.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        self.0.log(record)
    }

    fn flush(&self) {
        self.0.flush();
    }
}

/// Command that the user can send to a running node to control its execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Shutdown the node
    Shutdown,
}
