// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A simple, persistent, disk-based key-value store.

mod chunk;
pub(super) mod error;
mod immutable;
mod login_packet;
mod mutable;
mod sequence;
#[cfg(test)]
mod tests;
mod used_space;

use crate::{node::state_db::Init, utils};
use chunk::{Chunk, ChunkId};
use error::{Error, Result};
use log::trace;
use sn_data_types::{Account, Blob, Map, Sequence};
use std::{
    fs::Metadata,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs::{self, DirEntry, File},
    io::{AsyncReadExt, AsyncWriteExt},
    stream::StreamExt,
    sync::RwLock,
};
use used_space::UsedSpace;

const CHUNK_STORE_DIR: &str = "chunks";

/// The max name length for a chunk file.
const MAX_CHUNK_FILE_NAME_LENGTH: usize = 104;

pub(crate) type BlobChunkStoreApi = ChunkStoreApi<Blob>;
pub(crate) type MapChunkStoreApi = ChunkStoreApi<Map>;
pub(crate) type SequenceChunkStoreApi = ChunkStoreApi<Sequence>;
pub(crate) type AccountChunkStoreApi = ChunkStoreApi<Account>;


/// `ChunkStore` is a store of data held as serialised files on disk, implementing a maximum disk
/// usage to restrict storage.
pub(crate) struct ChunkStoreApi<T: Chunk> {
    inner: Arc<RwLock<ChunkStore<T>>>,
    total_used: Arc<RwLock<u64>>,
}

impl<T> ChunkStoreApi<T>
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
    pub async fn new<P: AsRef<Path>>(
        total_used: Arc<RwLock<u64>>,
        root: P,
        max_capacity: u64,
        init_mode: Init,
    ) -> Result<Self> {
        let dir = root.as_ref().join(CHUNK_STORE_DIR).join(Self::subdir());

        match init_mode {
            Init::New => Self::create_new_root(&dir).await?,
            Init::Load => trace!("Loading ChunkStore at {}", dir.display()),
        }

        let used_space = UsedSpace::new(&dir, init_mode).await?;
        let inner = ChunkStore {
            dir,
            max_capacity,
            used_space,
            _phantom: PhantomData,
        };
        Ok( Self{
            inner: Arc::new(RwLock::new(inner)),
            total_used: total_used,
        })
    }
}

impl<T: Chunk> ChunkStoreApi<T> {
    async fn create_new_root(root: &Path) -> Result<()> {
        trace!("Creating ChunkStore at {}", root.display());
        fs::create_dir_all(root).await?;

        // Verify that chunk files can be created.
        let temp_file_path = root.join("0".repeat(MAX_CHUNK_FILE_NAME_LENGTH));
        let _ = File::create(&temp_file_path).await?;
        fs::remove_file(temp_file_path).await?;

        Ok(())
    }

    /// Stores a new data chunk.
    ///
    /// If there is not enough storage space available, returns `Error::NotEnoughSpace`.  In case of
    /// an IO error, it returns `Error::Io`.
    ///
    /// If a chunk with the same id already exists, it will be overwritten.
    pub async fn put(&mut self, chunk: &T) -> Result<()> {

        let serialised_chunk = utils::serialise(chunk);
        let consumed_space = serialised_chunk.len() as u64;

        // reserve the space first and back it out if needed later
        {
            let max_capacity = self.inner.read().await.max_capacity;
            let mut total = self.total_used.write().await;
            let new_total = total.saturating_add(consumed_space);
            if new_total > max_capacity {
                return Err(Error::NotEnoughSpace);
            }
            *total = new_total;
        }

        // allow ourselves to back out on failure
        let total_used_clone = self.total_used.clone();
        let back_out = || async move {
            let mut total = total_used_clone.write().await;
            *total = *total - consumed_space;
        };

        // run the function in one block
        let total_used_clone_two = self.total_used.clone();
        let try_write = async move {

            let file_path = Self::file_path(self.inner.clone(), chunk.id()).await?;
            let _ = Self::do_delete(self.inner.clone(), &file_path).await?;

            let mut file = File::create(&file_path).await?;
            file.write_all(&serialised_chunk).await?;
            file.sync_data().await?;

            let res : Result<()> = Ok(()); //need return type explicit
            res
        };

        // finally await
        match tokio::try_join!( try_write ) {
            Ok(_) => Ok(()),
            Err(e) => { 
                back_out();
                Err(e)
            },
        }
    }

    /// Deletes the data chunk stored under `id`.
    ///
    /// If the data doesn't exist, it does nothing and returns `Ok`.  In the case of an IO error, it
    /// returns `Error::Io`.
    pub async fn delete(&mut self, id: &T::Id) -> Result<()> {
        let file_path = Self::file_path(self.inner.clone(), id).await?;
        Self::do_delete(self.inner.clone(), &file_path).await
    }


    async fn do_delete(inner: Arc<RwLock<ChunkStore<T>>>, file_path: &Path) -> Result<()> {
        if let Ok(metadata) = fs::metadata(file_path).await {
            {
                inner.write().await.used_space.decrease(metadata.len());
                fs::remove_file(file_path).await.map_err(From::from)
            }
        } else {
            Ok(())
        }
    }

    pub async fn get(&self, id: &T::Id) -> Result<T> {
        Self::__get(self.inner.clone(), &id).await
    }

    pub async fn has(&self, id: &T::Id) -> bool {
        Self::__has(self.inner.clone(), &id).await
    }

    pub async fn keys(&self) -> Vec<T::Id> {
        Self::__keys(self.inner.clone()).await
    }
    
    /// Returns a data chunk previously stored under `id`.
    ///
    /// If the data file can't be accessed, it returns `Error::NoSuchChunk`.
    async fn __get(cs: Arc<RwLock<ChunkStore<T>>>, id: &T::Id) -> Result<T> {
        let mut file = File::open(Self::file_path(cs.clone(), id).await?)
            .await
            .map_err(|_| Error::NoSuchChunk)?;
        let mut contents = vec![];
        let _ = file.read_to_end(&mut contents).await?;
        let chunk = bincode::deserialize::<T>(&contents)?;
        // Check it's the requested chunk variant.
        if chunk.id() == id {
            Ok(chunk)
        } else {
            Err(Error::NoSuchChunk)
        }
    }

    /// Tests if a data chunk has been previously stored under `id`.
    async fn __has(cs: Arc<RwLock<ChunkStore<T>>>, id: &T::Id) -> bool {
        if let Ok(path) = Self::file_path(cs.clone(), id).await {
            fs::metadata(path)
                .await
                .as_ref()
                .map(Metadata::is_file)
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Lists all keys of currently stored data.
    #[cfg_attr(not(test), allow(unused))]
    async fn __keys(cs: Arc<RwLock<ChunkStore<T>>>) -> Vec<T::Id> {
        let cs_rlock = cs.read().await;
        match fs::read_dir(&cs_rlock.dir).await {
            Ok(entries) => {
                entries
                    .filter_map(|entry| to_chunk_id(&entry.ok()?))
                    .collect()
                    .await
            }
            Err(_) => Vec::new(),
        }
    }

    async fn file_path(cs: Arc<RwLock<ChunkStore<T>>>, id: &T::Id) -> Result<PathBuf> {
        let cs_rlock = cs.read().await;
        Ok(cs_rlock.dir.join(&hex::encode(utils::serialise(id))))
    }
}

pub(crate) trait Subdir {
    fn subdir() -> &'static Path;
}

impl Subdir for BlobChunkStoreApi {
    fn subdir() -> &'static Path {
        Path::new("immutable")
    }
}

impl Subdir for MapChunkStoreApi {
    fn subdir() -> &'static Path {
        Path::new("mutable")
    }
}

impl Subdir for SequenceChunkStoreApi {
    fn subdir() -> &'static Path {
        Path::new("sequence")
    }
}

impl Subdir for AccountChunkStoreApi {
    fn subdir() -> &'static Path {
        Path::new("login_packets")
    }
}

fn to_chunk_id<T: ChunkId>(entry: &DirEntry) -> Option<T> {
    let file_name = entry.file_name();
    let file_name = file_name.into_string().ok()?;
    let bytes = hex::decode(file_name).ok()?;
    bincode::deserialize(&bytes).ok()
}

struct ChunkStore<T:Chunk> {
    pub dir: PathBuf,
    // Maximum space allowed for all `ChunkStore`s to consume.
    pub max_capacity: u64,
    // local used space in this chunk store
    pub used_space: UsedSpace,
    pub _phantom: PhantomData<T>,
}