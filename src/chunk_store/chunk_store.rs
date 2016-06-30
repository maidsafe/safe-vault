// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::{cmp, fs};
use std::io::{self, ErrorKind, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use error::InternalError;
use maidsafe_utilities::serialisation::{self, SerialisationError};
use rustc_serialize::{Decodable, Encodable};
use rustc_serialize::hex::{FromHex, ToHex};

/// The interval for print status log.
const MAX_CHUNK_FILE_NAME_U8_LENGTH: usize = 52;

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



/// `ChunkStore` is a store of data held as serialised files on disk, implementing a maximum disk
/// usage to restrict storage.
///
/// The data chunks are deleted when the `ChunkStore` goes out of scope.
pub struct ChunkStore<Key, Value> {
    rootdir: PathBuf,
    max_space: u64,
    used_space: u64,
    phantom: PhantomData<(Key, Value)>,
}

impl<Key, Value> ChunkStore<Key, Value>
    where Key: Decodable + Encodable,
          Value: Decodable + Encodable
{
    /// Creates new ChunkStore with `max_space` allowed storage space.
    ///
    /// The data is stored in a root directory. If `root` doesn't exist, it will be created.
    pub fn new(root: PathBuf, max_space: u64) -> Result<ChunkStore<Key, Value>, Error> {
        match fs::create_dir_all(&root) {
            Ok(_) => {}
            // when multiple chunk_stores being created concurrently under the same root directory
            // there is chance more than one instance tests the root dir as non-exists and trying
            // to create it, which will cause one of them raise AlreadyExists error during
            // fs::create_dir_all. A re-attempt needs to be carried out in that case.
            Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
                try!(fs::create_dir_all(&root));
            }
            Err(e) => return Err(From::from(e)),
        }
        try!(Self::verify_workable(&root));
        Ok(ChunkStore {
            rootdir: root,
            max_space: max_space,
            used_space: 0,
            phantom: PhantomData,
        })
    }

    fn verify_workable(root: &PathBuf) -> Result<(), Error> {
        let file_name: Vec<u8> = vec![0; MAX_CHUNK_FILE_NAME_U8_LENGTH];
        let file_path = root.join(file_name.to_hex());
        // Write the testing file.
        try!(fs::File::create(&file_path)
            .and_then(|file| file.sync_all() ));
        // Verify the testing file exists.
        if let Ok(metadata) = fs::metadata(file_path.clone()) {
            if !metadata.is_file() {
                return Err(Error::NotFound);
            }
        } else {
            return Err(Error::NotFound);
        }
        // remove the testing file.
        fs::remove_file(file_path).map_err(From::from)
    }

    /// Stores a new data chunk under `key`.
    ///
    /// If there is not enough storage space available, returns `Error::NotEnoughSpace`.  In case of
    // an IO error, it returns `Error::Io`.
    ///
    /// If the key already exists, it will be overwritten.
    pub fn put(&mut self, key: &Key, value: &Value) -> Result<(), Error> {
        let serialised_value = try!(serialisation::serialise(value));
        if self.used_space + serialised_value.len() as u64 > self.max_space {
            return Err(Error::NotEnoughSpace);
        }

        // If a file corresponding to 'key' already exists, delete it.
        let file_path = try!(self.file_path(key));
        let _ = self.do_delete(&file_path);

        // Write the file.
        fs::File::create(&file_path)
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

    /// Deletes the data chunk stored under `key`.
    ///
    /// If the data doesn't exist, it does nothing and returns `Ok`.  In the case of an IO error, it
    /// returns `Error::Io`.
    pub fn delete(&mut self, key: &Key) -> Result<(), Error> {
        let file_path = try!(self.file_path(key));
        self.do_delete(&file_path)
    }

    /// Returns a data chunk previously stored under `key`.
    ///
    /// If the data file can't be accessed, it returns `Error::ChunkNotFound`.
    pub fn get(&self, key: &Key) -> Result<Value, Error> {
        match fs::File::open(try!(self.file_path(key))) {
            Ok(mut file) => {
                let mut contents = Vec::<u8>::new();
                let _ = try!(file.read_to_end(&mut contents));
                Ok(try!(serialisation::deserialise::<Value>(&contents)))
            }
            Err(_) => Err(Error::NotFound),
        }
    }

    /// Tests if a data chunk has been previously stored under `key`.
    pub fn has(&self, key: &Key) -> bool {
        let file_path = if let Ok(path) = self.file_path(key) {
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

    /// Lists all keys of currently-data stored.
    pub fn keys(&self) -> Vec<Key> {
        fs::read_dir(&self.rootdir)
            .and_then(|dir_entries| {
                let dir_entry_to_routing_name = |dir_entry: io::Result<fs::DirEntry>| {
                    dir_entry.ok()
                        .and_then(|entry| entry.file_name().into_string().ok())
                        .and_then(|hex_name| hex_name.from_hex().ok())
                        .and_then(|bytes| serialisation::deserialise::<Key>(&*bytes).ok())
                };
                Ok(dir_entries.filter_map(dir_entry_to_routing_name).collect())
            })
            .unwrap_or_else(|_| Vec::new())
    }

    /// Returns the maximum amount of storage space available for this ChunkStore.
    pub fn max_space(&self) -> u64 {
        self.max_space
    }

    /// Returns the amount of storage space already used by this ChunkStore.
    pub fn used_space(&self) -> u64 {
        self.used_space
    }

    /// Cleans up the chunk_store dir.
    pub fn reset_store(&self) -> Result<(), InternalError> {
        try!(fs::remove_dir_all(&self.rootdir));
        try!(fs::create_dir_all(&self.rootdir));
        Ok(())
    }

    fn do_delete(&mut self, file_path: &Path) -> Result<(), Error> {
        if let Ok(metadata) = fs::metadata(file_path) {
            self.used_space -= cmp::min(metadata.len(), self.used_space);
            fs::remove_file(file_path).map_err(From::from)
        } else {
            Ok(())
        }
    }

    fn file_path(&self, key: &Key) -> Result<PathBuf, Error> {
        let filename = try!(serialisation::serialise(key)).to_hex();
        let path_name = Path::new(&filename);
        Ok(self.rootdir.join(path_name))
    }
}

impl<Key, Value> Drop for ChunkStore<Key, Value> {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.rootdir);
    }
}
