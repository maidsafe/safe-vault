// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! # Chunk Store
//! A simple, non-persistent, disk-based key-value store.

#[cfg(test)]
mod tests;

use hex::{self, FromHex};
use log::info;
use maidsafe_utilities::serialisation::{self, SerialisationError};
use quick_error::quick_error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cmp;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

const CHUNK_STORE_DIR: &str = "safe_vault_chunk_store";
const DEFAULT_MAX_CAPACITY: u64 = 2 * 1024 * 1024 * 1024;

/// The max name length for a chunk file.
const MAX_CHUNK_FILE_NAME_LENGTH: usize = 104;

quick_error! {
    /// `ChunkStore` error.
    #[derive(Debug)]
    pub enum Error {
        /// Error during filesystem IO operations.
        Io(error: io::Error) {
            description("IO error")
            display("IO error: {}", error)
            cause(error)
            from()
        }
        /// Error during serialisation or deserialisation of keys or values.
        Serialisation(error: SerialisationError) {
            description("Serialisation error")
            display("Serialisation error: {}", error)
            cause(error)
            from()
        }
        /// Not enough space in `ChunkStore` to perform `put`.
        NotEnoughSpace {
            description("Not enough space")
            display("Not enough space")
        }
        /// Key, Value pair not found in `ChunkStore`.
        NotFound {
            description("Key, Value not found")
            display("Key, Value not found")
        }
    }
}

pub trait Chunk<K>: Serialize + DeserializeOwned {
    type Id: ChunkId<K>;
}

pub trait ChunkId<K>: Serialize {
    type Chunk: Chunk<K>;
    fn to_key(&self) -> K;
}

/// `ChunkStore` is a store of data held as serialised files on disk, implementing a maximum disk
/// usage to restrict storage.
///
/// The data chunks are deleted when the `ChunkStore` goes out of scope.
pub struct ChunkStore<K> {
    root_dir: TempDir,
    max_space: u64,
    used_space: u64,
    phantom: PhantomData<K>,
}

impl<K: DeserializeOwned + Serialize> ChunkStore<K> {
    /// Creates a new `ChunkStore`.
    ///
    /// The maximum storage space is defined by `capacity`, or `DEFAULT_MAX_CAPACITY` if this is
    /// `None`.
    ///
    /// The data is stored in a temporary directory which is deleted when the process exits.  This
    /// directory is named as per `CHUNK_STORE_DIR` with a random suffix.  If `root` is `Some`, then
    /// `root` is created and the directory is created inside it.  If `root` is `None`, then the
    /// directory is created inside [`env::temp_dir()`][1].
    ///
    /// If the directory cannot be created, or if a test chunk cannot be created therein, the
    /// function returns an error.
    ///
    /// [1]: https://doc.rust-lang.org/std/env/fn.temp_dir.html
    #[allow(clippy::new_ret_no_self)]
    pub fn new(root: Option<String>, capacity: Option<u64>) -> Result<Self, Error> {
        let root_dir = match root {
            Some(path) => {
                fs::create_dir_all(&path)?;
                TempDir::new_in(&path, CHUNK_STORE_DIR)
            }
            None => TempDir::new(CHUNK_STORE_DIR),
        }?;
        let max_space = capacity.unwrap_or(DEFAULT_MAX_CAPACITY);

        // Verify that chunk files can be created.
        let name: String = (0..MAX_CHUNK_FILE_NAME_LENGTH).map(|_| '0').collect();
        let _ = File::create(root_dir.path().join(name.clone()))?;
        let _ = fs::remove_file(root_dir.path().join(name));

        info!(
            "Created chunk store at {} with capacity of {} bytes.",
            root_dir.path().display(),
            max_space
        );

        Ok(ChunkStore {
            root_dir,
            max_space,
            used_space: 0,
            phantom: PhantomData,
        })
    }

    /// Stores a new data chunk.
    ///
    /// If there is not enough storage space available, returns `Error::NotEnoughSpace`.  In case of
    /// an IO error, it returns `Error::Io`.
    ///
    /// If a data with the same id already exists, it will be overwritten.
    pub fn put<T: Chunk<K>>(&mut self, id: &T::Id, value: &T) -> Result<(), Error> {
        let serialised_value = serialisation::serialise(value)?;
        if self.used_space + serialised_value.len() as u64 > self.max_space {
            return Err(Error::NotEnoughSpace);
        }

        // If a file corresponding to the chunk id already exists, delete it.
        let file_path = self.file_path(id)?;
        let _ = self.do_delete(&file_path);

        // Write the file.
        File::create(&file_path)
            .and_then(|mut file| {
                file.write_all(&serialised_value)
                    .and_then(|()| file.sync_all())
                    .and_then(|()| file.metadata())
                    .map(|metadata| {
                        self.used_space += metadata.len();
                    })
            })
            .map_err(From::from)
    }

    /// Deletes the data chunk stored under `id`.
    ///
    /// If the data doesn't exist, it does nothing and returns `Ok`.  In the case of an IO error, it
    /// returns `Error::Io`.
    pub fn delete<I: ChunkId<K>>(&mut self, id: &I) -> Result<(), Error> {
        let file_path = self.file_path(id)?;
        self.do_delete(&file_path)
    }

    /// Returns a data chunk previously stored under `id`.
    ///
    /// If the data file can't be accessed, it returns `Error::ChunkNotFound`.
    pub fn get<I: ChunkId<K>>(&self, id: &I) -> Result<I::Chunk, Error> {
        match File::open(self.file_path(id)?) {
            Ok(mut file) => {
                let mut contents = Vec::<u8>::new();
                let _ = file.read_to_end(&mut contents)?;
                Ok(serialisation::deserialise(&contents)?)
            }
            Err(_) => Err(Error::NotFound),
        }
    }

    /// Tests if a data chunk has been previously stored under `id`.
    pub fn has<I: ChunkId<K>>(&self, id: &I) -> bool {
        let file_path = if let Ok(path) = self.file_path(id) {
            path
        } else {
            return false;
        };
        if let Ok(metadata) = fs::metadata(file_path) {
            return metadata.is_file();
        } else {
            false
        }
    }

    /// Lists all keys of currently stored data.
    pub fn keys(&self) -> Vec<K> {
        fs::read_dir(self.root_dir.path())
            .and_then(|dir_entries| {
                let dir_entry_to_routing_name = |dir_entry: io::Result<fs::DirEntry>| {
                    dir_entry
                        .ok()
                        .and_then(|entry| entry.file_name().into_string().ok())
                        .and_then(|hex_name| Vec::from_hex(hex_name).ok())
                        .and_then(|bytes| serialisation::deserialise(&*bytes).ok())
                };
                Ok(dir_entries.filter_map(dir_entry_to_routing_name).collect())
            })
            .unwrap_or_else(|_| Vec::new())
    }

    /// Returns the maximum amount of storage space available for this `ChunkStore`.
    pub fn max_space(&self) -> u64 {
        self.max_space
    }

    /// Returns the amount of storage space already used by this `ChunkStore`.
    pub fn used_space(&self) -> u64 {
        self.used_space
    }

    fn do_delete(&mut self, file_path: &Path) -> Result<(), Error> {
        if let Ok(metadata) = fs::metadata(file_path) {
            self.used_space -= cmp::min(metadata.len(), self.used_space);
            fs::remove_file(file_path).map_err(From::from)
        } else {
            Ok(())
        }
    }

    fn file_path<I: ChunkId<K>>(&self, id: &I) -> Result<PathBuf, Error> {
        let filename = hex::encode(serialisation::serialise(&id.to_key())?);
        let path_name = Path::new(&filename);
        Ok(self.root_dir.path().join(path_name))
    }
}
