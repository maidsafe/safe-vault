// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A simple, persistent, disk-based key-value store.

mod chunk;
mod immutable;
mod mutable;
mod sequence;
#[cfg(test)]
mod tests;
mod used_space;

use crate::error::{Error, Result};
use crate::utils;
use chunk::{Chunk, ChunkId};
use log::{info, trace};
use sn_data_types::{Blob, Map, Sequence};
use std::{
    fs::{self, DirEntry, File, Metadata},
    io::{Read, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};
use used_space::StoreId;
pub use used_space::UsedSpace;

const CHUNK_STORE_DIR: &str = "chunks";

/// The max name length for a chunk file.
const MAX_CHUNK_FILE_NAME_LENGTH: usize = 104;

pub(crate) type BlobChunkStore = ChunkStore<Blob>;
pub(crate) type MapChunkStore = ChunkStore<Map>;
pub(crate) type SequenceChunkStore = ChunkStore<Sequence>;

/// `ChunkStore` is a store of data held as serialised files on disk, implementing a maximum disk
/// usage to restrict storage.
pub(crate) struct ChunkStore<T: Chunk> {
    dir: PathBuf,
    // Maximum space allowed for all `ChunkStore`s to consume.
    used_space: UsedSpace,
    id: StoreId,
    _phantom: PhantomData<T>,
}

impl<T> ChunkStore<T>
where
    T: Chunk,
    Self: Subdir,
{
    /// Creates a new `ChunkStore` at location `root/CHUNK_STORE_DIR/<chunk type>`.
    ///
    /// If the location specified already exists, the previous ChunkStore there is opened, otherwise
    /// the required folder structure is created.
    ///
    /// The maximum storage space is defined by `max_capacity`.  This specifies the max usable by
    /// _all_ `ChunkStores`, not per `ChunkStore`.
    pub async fn new<P: AsRef<Path>>(root: P, used_space: UsedSpace) -> Result<Self> {
        let dir = root.as_ref().join(CHUNK_STORE_DIR).join(Self::subdir());

        if fs::read(&dir).is_ok() {
            // trace!("Loading ChunkStore at {}", dir.display());
        } else {
            Self::create_new_root(&dir)?
        }

        let id = used_space.add_local_store(&dir).await?;
        Ok(ChunkStore {
            dir,
            used_space,
            id,
            _phantom: PhantomData,
        })
    }
}

impl<T: Chunk> ChunkStore<T> {
    fn create_new_root(root: &Path) -> Result<()> {
        //trace!("Creating ChunkStore at {}", root.display());
        fs::create_dir_all(root)?;

        // Verify that chunk files can be created.
        let temp_file_path = root.join("0".repeat(MAX_CHUNK_FILE_NAME_LENGTH));
        let _ = File::create(&temp_file_path)?;
        fs::remove_file(temp_file_path)?;

        Ok(())
    }

    /// Stores a new data chunk.
    ///
    /// If there is not enough storage space available, returns `Error::NotEnoughSpace`.  In case of
    /// an IO error, it returns `Error::Io`.
    ///
    /// If a chunk with the same id already exists, it will be overwritten.
    pub async fn put(&mut self, chunk: &T) -> Result<()> {
        info!("Writing chunk");
        let serialised_chunk = utils::serialise(chunk)?;
        let consumed_space = serialised_chunk.len() as u64;

        info!("consumed space: {:?}", consumed_space);
        info!("max : {:?}", self.used_space.max_capacity().await);
        info!("use space total : {:?}", self.used_space.total().await);

        let file_path = self.file_path(chunk.id())?;
        self.do_delete(&file_path).await?;

        // pre-reserve space
        self.used_space.increase(self.id, consumed_space).await?;
        trace!(
            "use space total after add: {:?}",
            self.used_space.total().await
        );

        let res = File::create(&file_path).and_then(|mut file| {
            file.write_all(&serialised_chunk)?;
            file.sync_all()
        });

        match res {
            Ok(_) => {
                info!("Writing chunk succeeded!");
                Ok(())
            }
            Err(e) => {
                info!("Writing chunk failed!");
                self.used_space.decrease(self.id, consumed_space).await?;
                Err(e.into())
            }
        }
    }

    /// Deletes the data chunk stored under `id`.
    ///
    /// If the data doesn't exist, it does nothing and returns `Ok`.  In the case of an IO error, it
    /// returns `Error::Io`.
    pub async fn delete(&mut self, id: &T::Id) -> Result<()> {
        self.do_delete(&self.file_path(id)?).await
    }

    /// Used space to max space ratio.
    pub async fn used_space_ratio(&self) -> f64 {
        let used = self.total_used_space().await;
        let total = self.used_space.max_capacity().await;
        let used_space_ratio = used as f64 / total as f64;
        info!("Used space: {:?}", used);
        info!("Total space: {:?}", total);
        info!("Used space ratio: {:?}", used_space_ratio);
        used_space_ratio
    }

    /// Returns a data chunk previously stored under `id`.
    ///
    /// If the data file can't be accessed, it returns `Error::NoSuchChunk`.
    pub fn get(&self, id: &T::Id) -> Result<T> {
        let mut file = File::open(self.file_path(id)?).map_err(|_| Error::NoSuchChunk)?;
        let mut contents = vec![];
        let _ = file.read_to_end(&mut contents)?;
        let chunk = bincode::deserialize::<T>(&contents)?;
        // Check it's the requested chunk variant.
        if chunk.id() == id {
            Ok(chunk)
        } else {
            Err(Error::NoSuchChunk)
        }
    }

    pub async fn total_used_space(&self) -> u64 {
        self.used_space.total().await
    }

    /// Tests if a data chunk has been previously stored under `id`.
    pub fn has(&self, id: &T::Id) -> bool {
        if let Ok(path) = self.file_path(id) {
            fs::metadata(path)
                .as_ref()
                .map(Metadata::is_file)
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Lists all keys of currently stored data.
    #[cfg_attr(not(test), allow(unused))]
    pub fn keys(&self) -> Vec<T::Id> {
        fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .filter_map(|entry| to_chunk_id(&entry.ok()?))
                    .collect()
            })
            .unwrap_or_else(|_| Vec::new())
    }

    async fn do_delete(&mut self, file_path: &Path) -> Result<()> {
        if let Ok(metadata) = fs::metadata(file_path) {
            self.used_space.decrease(self.id, metadata.len()).await?;
            fs::remove_file(file_path).map_err(From::from)
        } else {
            Ok(())
        }
    }

    fn file_path(&self, id: &T::Id) -> Result<PathBuf> {
        Ok(self.dir.join(&hex::encode(utils::serialise(id)?)))
    }
}

pub(crate) trait Subdir {
    fn subdir() -> &'static Path;
}

impl Subdir for BlobChunkStore {
    fn subdir() -> &'static Path {
        Path::new("immutable")
    }
}

impl Subdir for MapChunkStore {
    fn subdir() -> &'static Path {
        Path::new("mutable")
    }
}

impl Subdir for SequenceChunkStore {
    fn subdir() -> &'static Path {
        Path::new("sequence")
    }
}

fn to_chunk_id<T: ChunkId>(entry: &DirEntry) -> Option<T> {
    let file_name = entry.file_name();
    let file_name = file_name.into_string().ok()?;
    let bytes = hex::decode(file_name).ok()?;
    bincode::deserialize(&bytes).ok()
}
