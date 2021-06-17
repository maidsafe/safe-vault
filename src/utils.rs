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
use flexi_logger::{Cleanup, Criterion, DeferredNow, FileSpec, Logger, Naming};
use log::{Log, Metadata, Record};
use pickledb::{PickleDb, PickleDbDumpPolicy};
use rand::{distributions::Standard, CryptoRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use std::io::Write;
use std::{fs, path::Path};

const NODE_MODULE_NAME: &str = "sn_node";

/// Easily create a `BTreeSet`.
#[macro_export]
macro_rules! btree_set {
    ($($item:expr),*) => {{
        let mut _set = ::std::collections::BTreeSet::new();
        $(
            let _ = _set.insert($item);
        )*
        _set
    }};

    ($($item:expr),*,) => {
        btree_set![$($item),*]
    };
}

/// Easily create a `BTreeMap` with the key => value syntax.
#[macro_export]
macro_rules! btree_map {
    () => ({
        ::std::collections::BTreeMap::new()
    });

    ($($key:expr => $value:expr),*) => {{
        let mut _map = ::std::collections::BTreeMap::new();
        $(
            let _ = _map.insert($key, $value);
        )*
        _map
    }};

    ($($key:expr => $value:expr),*,) => {
        btree_map![$($key => $value),*]
    };
}

pub(crate) fn new_auto_dump_db<D: AsRef<Path>, N: AsRef<Path>>(
    db_dir: D,
    db_name: N,
) -> Result<PickleDb> {
    let db_path = db_dir.as_ref().join(db_name);
    match PickleDb::load_bin(db_path.clone(), PickleDbDumpPolicy::AutoDump) {
        Ok(db) => Ok(db),
        Err(_) => {
            fs::create_dir_all(db_dir)?;
            let mut db = PickleDb::new_bin(db_path.clone(), PickleDbDumpPolicy::AutoDump);

            // dump is needed to actually write the db to disk.
            db.dump()?;

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
pub fn init_logging(config: &Config) -> Result<()> {
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
    let logger = Logger::try_with_env_or_str(module_log_filter)
        .map_err(|e| Error::Configuration(format!("{:?}", e)))?
        .format(do_format)
        .rotate(
            Criterion::Size(1024 * 1024), // 1 mb
            Naming::Numbers,
            Cleanup::KeepLogFiles(5),
        );

    let logger = if let Some(log_dir) = config.log_dir() {
        logger.log_to_file(
            FileSpec::try_from(log_dir)
                .map_err(|e| Error::Configuration(format!("{:?}", e)))?
                .suppress_timestamp(),
        )
    } else {
        logger
    };

    if let Ok((logger, _)) = logger.build() {
        let logger = LoggerWrapper(logger);

        async_log::Logger::wrap(logger, || 5433)
            .start(config.verbose().to_level_filter())
            .unwrap_or(());
    }

    Ok(())
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
