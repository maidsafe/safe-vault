// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use log::warn;
use std::{path::Path, sync::Arc};
use tokio::{io::AsyncSeekExt, sync::Mutex};

const USED_SPACE_FILENAME: &str = "used_space";

/// This holds a record (in-memory and on-disk) of the space used by a single `ChunkStore`, and also
/// an in-memory record of the total space used by all `ChunkStore`s.
#[derive(Debug, Clone)]
pub struct UsedSpace {
    inner: Arc<Mutex<inner::UsedSpace>>,
}

/// Identifies a `ChunkStore` within the larger
/// used space tracking
pub type StoreId = u64;

impl UsedSpace {
    /// construct a new used space instance
    /// NOTE: this constructs a new async-safe instance,
    /// If you intend to create a new local `ChunkStore` tracking,
    /// then use `clone()` and `add_local_store()` to ensure
    /// consistency across local `ChunkStore`s
    pub fn new(max_capacity: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner::UsedSpace::new(max_capacity))),
        }
    }

    /// Clears the entire storage and sets total_value back to zero
    /// while removing all local stores
    pub async fn reset(&self) {
        inner::UsedSpace::reset(self.inner.clone()).await
    }

    /// Returns the maximum capacity (e.g. the maximum
    /// value that total() can return)
    pub async fn max_capacity(&self) -> u64 {
        inner::UsedSpace::max_capacity(self.inner.clone()).await
    }

    /// Returns the total used space as a snapshot
    /// Note, due to the async nature of this, the value
    /// may be stale by the time it is read if there are multiple
    /// writers
    pub async fn total(&self) -> u64 {
        inner::UsedSpace::total(self.inner.clone()).await
    }

    /// Returns the used space of a local store as a snapshot
    /// Note, due to the async nature of this, the value
    /// may be stale by the time it is read if there are multiple
    /// writers
    #[allow(unused)]
    pub async fn local(&self, id: StoreId) -> u64 {
        inner::UsedSpace::local(self.inner.clone(), id).await
    }

    /// Add an object and file store to track used space of a single
    /// `ChunkStore`
    pub async fn add_local_store<T: AsRef<Path>>(&self, dir: T) -> Result<StoreId> {
        inner::UsedSpace::add_local_store(self.inner.clone(), dir).await
    }

    /// Increase the used amount of a single chunk store and the global used value
    pub async fn increase(&self, id: StoreId, consumed: u64) -> Result<()> {
        inner::UsedSpace::increase(self.inner.clone(), id, consumed).await
    }

    /// Decrease the used amount of a single chunk store and the global used value
    pub async fn decrease(&self, id: StoreId, released: u64) -> Result<()> {
        inner::UsedSpace::decrease(self.inner.clone(), id, released).await
    }
}

mod inner {

    use super::*;
    use std::{collections::HashMap, io::SeekFrom};
    use tokio::{
        fs::{File, OpenOptions},
        io::{AsyncReadExt, AsyncWriteExt},
    };

    /// Tracks the Used Space of all `ChunkStore` objects
    /// registered with it, as well as the combined amount
    #[derive(Debug)]
    pub struct UsedSpace {
        /// the maximum value (inclusive) that `total_value` can attain
        max_capacity: u64,
        /// Total space consumed across all `ChunkStore`s, including this one
        total_value: u64,
        /// the used space tracking for each chunk store
        local_stores: HashMap<StoreId, LocalUsedSpace>,
        /// next local `ChunkStore` id to use
        next_id: StoreId,
    }

    /// An entry used to track the used space of a single `ChunkStore`
    #[derive(Debug)]
    struct LocalUsedSpace {
        // Space consumed by this one `ChunkStore`.
        pub local_value: u64,
        // File used to maintain on-disk record of `local_value`.
        // TODO: maybe a good idea to maintain a journal that is only flushed occasionally
        // to ensure stale entries aren't recorded, and to avoid holding the lock for the
        // whole inner::UsedSpace struct during the entirety of the file write.
        pub local_record: File,
    }

    impl UsedSpace {
        pub fn new(max_capacity: u64) -> Self {
            Self {
                max_capacity,
                total_value: 0u64,
                local_stores: HashMap::new(),
                next_id: 0u64,
            }
        }

        /// Clears the storage, setting total value ot zero
        /// and dropping local stores, but leaves
        /// the capacity and next_id unchanged
        pub async fn reset(used_space: Arc<Mutex<UsedSpace>>) {
            let mut used_space_lock = used_space.lock().await;
            used_space_lock.total_value = 0;
            for (_id, local_used_space) in used_space_lock.local_stores.iter_mut() {
                local_used_space.local_value = 0;
                if let Err(err) =
                    Self::write_local_to_file(&mut local_used_space.local_record, 0).await
                {
                    warn!("Error updating used_space file on disk: {}", err);
                }
            }
        }

        /// Returns the maximum capacity (e.g. the maximum
        /// value that total() can return)
        pub async fn max_capacity(used_space: Arc<Mutex<UsedSpace>>) -> u64 {
            let used_space_lock = used_space.lock().await;
            used_space_lock.max_capacity
        }

        /// Returns the total used space as a snapshot
        /// Note, due to the async nature of this, the value
        /// may be stale by the time it is read if there are multiple
        /// writers
        pub async fn total(used_space: Arc<Mutex<UsedSpace>>) -> u64 {
            let used_space_lock = used_space.lock().await;
            used_space_lock.total_value
        }

        /// Returns the used space of a local store as a snapshot
        /// Note, due to the async nature of this, the value
        /// may be stale by the time it is read if there are multiple
        /// writers
        pub async fn local(used_space: Arc<Mutex<UsedSpace>>, id: StoreId) -> u64 {
            let used_space_lock = used_space.lock().await;
            used_space_lock
                .local_stores
                .get(&id)
                .map_or(0, |res| res.local_value)
        }

        /// Adds a new record for tracking the actions
        /// of a local chunk store as part of the global
        /// used amount tracking
        pub async fn add_local_store<T: AsRef<Path>>(
            used_space: Arc<Mutex<UsedSpace>>,
            dir: T,
        ) -> Result<StoreId> {
            let mut local_record = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(dir.as_ref().join(USED_SPACE_FILENAME))
                .await?;

            // try read
            let mut buffer = vec![];
            let could_read = local_record.read_to_end(&mut buffer).await.is_ok();
            let has_value = !buffer.is_empty();
            let local_value = if could_read && has_value {
                // TODO - if this can't be parsed, we should consider emptying `dir` of any chunks.
                bincode::deserialize::<u64>(&buffer)?
            } else {
                let mut bytes = Vec::<u8>::new();
                bincode::serialize_into(&mut bytes, &0_u64)?;
                local_record.write_all(&bytes).await?;
                0
            };

            let local_store = LocalUsedSpace {
                local_value,
                local_record,
            };
            let mut used_space_lock = used_space.lock().await;
            let id = used_space_lock.next_id;
            used_space_lock.next_id += 1;
            let _ = used_space_lock.local_stores.insert(id, local_store);
            Ok(id)
        }

        /// Asynchronous implementation to increase used space in a local store
        /// and globally at the same time
        pub async fn increase(
            used_space: Arc<Mutex<UsedSpace>>,
            id: StoreId,
            consumed: u64,
        ) -> Result<()> {
            let mut used_space_lock = used_space.lock().await;
            let new_total = used_space_lock
                .total_value
                .checked_add(consumed)
                .ok_or(Error::NotEnoughSpace)?;
            if new_total > used_space_lock.max_capacity {
                return Err(Error::NotEnoughSpace);
            }
            let new_local = used_space_lock
                .local_stores
                .get(&id)
                .ok_or(Error::NoStoreId)?
                .local_value
                .checked_add(consumed)
                .ok_or(Error::NotEnoughSpace)?;

            {
                let record = &mut used_space_lock
                    .local_stores
                    .get_mut(&id)
                    .ok_or(Error::NoStoreId)?
                    .local_record;
                Self::write_local_to_file(record, new_local).await?;
            }
            used_space_lock.total_value = new_total;
            used_space_lock
                .local_stores
                .get_mut(&id)
                .ok_or(Error::NoStoreId)?
                .local_value = new_local;

            Ok(())
        }

        /// Asynchronous implementation to decrease used space in a local store
        /// and globally at the same time
        pub async fn decrease(
            used_space: Arc<Mutex<UsedSpace>>,
            id: StoreId,
            released: u64,
        ) -> Result<()> {
            let mut used_space_lock = used_space.lock().await;
            let new_local = used_space_lock
                .local_stores
                .get_mut(&id)
                .ok_or(Error::NoStoreId)?
                .local_value
                .saturating_sub(released);
            let new_total = used_space_lock.total_value.saturating_sub(released);
            {
                let record = &mut used_space_lock
                    .local_stores
                    .get_mut(&id)
                    .ok_or(Error::NoStoreId)?
                    .local_record;
                Self::write_local_to_file(record, new_local).await?;
            }
            used_space_lock.total_value = new_total;
            used_space_lock
                .local_stores
                .get_mut(&id)
                .ok_or(Error::NoStoreId)?
                .local_value = new_local;
            Ok(())
        }

        /// helper to write the contents of local to file
        /// NOTE: For now, ou should hold the lock on the inner while doing this
        /// It's slow, but maintains behaviour from the previous implementation
        async fn write_local_to_file(record: &mut File, local: u64) -> Result<()> {
            record.set_len(0).await?;
            let _ = record.seek(SeekFrom::Start(0)).await?;

            let mut contents = Vec::<u8>::new();
            bincode::serialize_into(&mut contents, &local)?;
            record.write_all(&contents).await?;
            record.sync_all().await?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Result, UsedSpace};
    use tempdir::TempDir;

    const TEST_STORE_MAX_SIZE: u64 = u64::MAX;

    /// creates a temp dir for the root of all stores
    fn create_temp_root() -> Result<TempDir> {
        TempDir::new(&"temp_store_root").map_err(|e| Error::TempDirCreationFailed(e.to_string()))
    }

    /// create a temp dir for a store at a given temp store root
    fn create_temp_store(temp_root: &TempDir) -> Result<TempDir> {
        let path_str = temp_root.path().join(&"temp_store");
        let path_str = path_str.to_str().ok_or_else(|| {
            Error::TempDirCreationFailed("Could not parse path to string".to_string())
        })?;
        TempDir::new(path_str).map_err(|e| Error::TempDirCreationFailed(e.to_string()))
    }

    #[tokio::test]
    async fn used_space_multiwriter_test() -> Result<()> {
        const NUMS_TO_ADD: usize = 128;

        // alloc store
        let root_dir = create_temp_root()?;
        let store_dir = create_temp_store(&root_dir)?;
        let used_space = UsedSpace::new(TEST_STORE_MAX_SIZE);
        let id = used_space.add_local_store(&store_dir).await?;
        // get a random vec of u64 by adding u32 (avoid overflow)
        let mut rng = rand::thread_rng();
        let bytes = crate::utils::random_vec(&mut rng, std::mem::size_of::<u32>() * NUMS_TO_ADD);
        let mut nums = Vec::new();
        for chunk in bytes.as_slice().chunks_exact(std::mem::size_of::<u32>()) {
            let mut num = 0u32;
            for (i, component) in chunk.iter().enumerate() {
                num |= (*component as u32) << (i * 8);
            }
            nums.push(num as u64);
        }
        let total: u64 = nums.iter().sum();

        // check that multiwriter increase is consistent
        let mut tasks = Vec::new();
        for n in nums.iter() {
            tasks.push(used_space.increase(id, *n));
        }
        let _ = futures::future::try_join_all(tasks.into_iter()).await?;

        assert_eq!(total, used_space.total().await);
        assert_eq!(total, used_space.local(id).await);

        // check that multiwriter decrease is consistent
        let mut tasks = Vec::new();
        for n in nums.iter() {
            tasks.push(used_space.decrease(id, *n));
        }
        let _ = futures::future::try_join_all(tasks.into_iter()).await?;

        assert_eq!(0, used_space.total().await);
        assert_eq!(0, used_space.local(id).await);

        Ok(())
    }
}
