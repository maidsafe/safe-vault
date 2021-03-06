// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utilities

use crate::{config_handler::Config, Error, Result};
use bytes::Bytes;
use flexi_logger::{DeferredNow, Logger};
use log::debug;
use log::{Log, Metadata, Record};
use pickledb::{PickleDb, PickleDbDumpPolicy};
use rand::{distributions::Standard, CryptoRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use std::io::Write;
use std::{fs, path::Path};

const NODE_MODULE_NAME: &str = "sn_node";

pub(crate) fn new_auto_dump_db<D: AsRef<Path>, N: AsRef<Path>>(
    db_dir: D,
    db_name: N,
) -> Result<PickleDb> {
    let db_path = db_dir.as_ref().join(db_name);
    //debug!("Trying to load Database at {}", db_path.display(),);
    match PickleDb::load_bin(db_path.clone(), PickleDbDumpPolicy::AutoDump) {
        Ok(db) => Ok(db),
        Err(_) => {
            //debug!("Database not found, creating it..");
            fs::create_dir_all(db_dir)?;
            let mut _db = PickleDb::new_bin(db_path.clone(), PickleDbDumpPolicy::AutoDump);
            // dump is needed to actually write the db to disk.
            _db.dump()?;
            //debug!("Created database");
            PickleDb::load_bin(db_path, PickleDbDumpPolicy::AutoDump).map_err(Error::PickleDb)
        }
    }
}

#[allow(dead_code)]
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
