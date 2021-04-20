// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{path::Path, sync::Arc};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, SeekFrom};
use tokio::sync::RwLock;
use tokio::{io::AsyncSeekExt, io::AsyncWriteExt};

const USED_SPACE_FILENAME: &str = "used_space";

/// Identifies a `ChunkStore` within the larger
/// used space tracking
pub type StoreId = u64;

#[derive(Debug)]
/// This holds a record (in-memory and on-disk) of the space used by a single `ChunkStore`, and also
/// an in-memory record of the total space used by all `ChunkStore`s. It tracks the Used Space of all `ChunkStore` objects
/// registered with it, as well as the combined amount
pub struct UsedSpace {
    max_capacity: AtomicU64,
    total_value: AtomicU64,
    local_stores: Arc<RwLock<HashMap<StoreId, LocalUsedSpace>>>,
    next_id: AtomicU64,
}

// Atomic types do not implement Clone so this is a hack done by creating new atomic type from the
// inner value.
impl Clone for UsedSpace {
    fn clone(&self) -> Self {
        Self {
            max_capacity: AtomicU64::new(self.max_capacity.load(Ordering::SeqCst)),
            total_value: AtomicU64::new(self.max_capacity.load(Ordering::SeqCst)),
            local_stores: self.local_stores.clone(),
            next_id: AtomicU64::new(self.next_id.load(Ordering::SeqCst)),
        }
    }
}

impl UsedSpace {
    pub fn new(max_capacity: u64) -> UsedSpace {
        UsedSpace {
            max_capacity: AtomicU64::new(max_capacity),
            total_value: AtomicU64::default(),
            local_stores: Arc::new(RwLock::new(HashMap::<u64, LocalUsedSpace>::new())),
            next_id: Default::default(),
        }
    }

    /// Clears the storage, setting total value ot zero
    /// and dropping local stores, but leaves
    /// the capacity and next_id unchanged
    pub async fn reset(&self) -> Result<()> {
        self.total_value.store(0, Ordering::SeqCst);

        let store = &mut *self.local_stores.write().await;
        for (_, local_used_space) in store.iter_mut() {
            local_used_space.local_value = 0;
            write_local_to_file(&mut local_used_space.local_record, 0u64).await?;
        }

        Ok(())
    }

    #[inline]
    /// Returns the maximum capacity (e.g. the maximum
    /// value that total() can return)
    pub fn max_capacity(&self) -> u64 {
        self.max_capacity.load(Ordering::SeqCst)
    }

    #[inline]
    /// Returns the total used space
    pub fn total(&self) -> u64 {
        self.total_value.load(Ordering::SeqCst)
    }

    /// Returns the used space of a local store as a snapshot
    #[allow(dead_code)]
    pub async fn local(&self, id: StoreId) -> u64 {
        self.local_stores
            .read()
            .await
            .get(&id)
            .map_or(0, |res| res.local_value)
    }

    /// Adds a new record for tracking the actions
    /// of a local chunk store as part of the global
    /// used amount tracking
    pub async fn add_local_store<T: AsRef<Path>>(&mut self, dir: T) -> Result<StoreId> {
        let mut local_record = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(dir.as_ref().join(USED_SPACE_FILENAME))
            .await?;

        let mut buffer = Vec::<u8>::with_capacity(8);
        let read_byte = local_record.read_to_end(&mut buffer).await?;
        let local_value = if read_byte > 0 {
            bincode::deserialize::<u64>(&buffer)?
        } else {
            let mut bytes = Vec::<u8>::with_capacity(8);
            bincode::serialize_into(&mut bytes, &0_u64)?;
            local_record.write_all(&bytes).await?;
            0
        };

        let local_store = LocalUsedSpace::new(local_value, local_record);

        let mut store = self.local_stores.write().await;
        let _ = self.next_id.fetch_add(1u64, Ordering::SeqCst);
        let next = self.next_id.load(Ordering::SeqCst);
        let _ = store.insert(next, local_store);
        Ok(next)
    }

    /// Increase used space in a local store and globally at the same time
    pub async fn increase(&self, id: StoreId, consumed: u64) -> Result<()> {
        self.change_value(id, consumed, false).await
    }

    /// Decrease used space in a local store and globally at the same time
    pub async fn decrease(&self, id: StoreId, consumed: u64) -> Result<()> {
        self.change_value(id, consumed, true).await
    }

    async fn change_value(&self, id: u64, consumed: u64, reverse: bool) -> Result<()> {
        let total = self.total_value.load(Ordering::SeqCst);
        if total <= self.max_capacity.load(Ordering::SeqCst) {
            let _ = self
                .total_value
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |t| {
                    if reverse {
                        Some(t.saturating_sub(consumed))
                    } else {
                        t.checked_add(consumed)
                    }
                })
                .map_err(|_| Error::NotEnoughSpace)?;
        } else {
            return Err(Error::NotEnoughSpace);
        }
        let mut local_stores = self.local_stores.write().await;

        let local_used_space = local_stores.get(&id).ok_or(Error::NoStoreId)?;
        let new_local = if reverse {
            local_used_space.local_value.saturating_sub(consumed)
        } else {
            local_used_space
                .local_value
                .checked_add(consumed)
                .ok_or(Error::NotEnoughSpace)?
        };
        let record = &mut local_stores
            .get_mut(&id)
            .ok_or(Error::NoStoreId)?
            .local_record;

        write_local_to_file(record, new_local).await?;

        local_stores
            .get_mut(&id)
            .ok_or(Error::NoStoreId)?
            .local_value = new_local;

        Ok(())
    }
}

/// helper to write the contents of local to file
/// NOTE: For now, you should hold the lock on the inner while doing this
/// It's slow, but maintains behaviour from the previous implementation
async fn write_local_to_file(record: &mut File, local: u64) -> Result<()> {
    record.set_len(0).await?;
    let _ = record.seek(SeekFrom::Start(0u64)).await?;

    let mut contents = Vec::<u8>::with_capacity(8);
    bincode::serialize_into(&mut contents, &local)?;
    record.write_all(&contents).await?;
    record.sync_all().await?;

    Ok(())
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

impl LocalUsedSpace {
    pub fn new(value: u64, record: File) -> LocalUsedSpace {
        LocalUsedSpace {
            local_value: value,
            local_record: record,
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
        let mut used_space = UsedSpace::new(TEST_STORE_MAX_SIZE);
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
        let tasks = nums
            .iter()
            .map(|n| used_space.increase(id, *n))
            .collect::<Vec<_>>();

        let _ = futures::future::try_join_all(tasks.into_iter()).await?;

        assert_eq!(total, used_space.total());
        assert_eq!(total, used_space.local(id).await);

        // check that multiwriter decrease is consistent
        let mut tasks = Vec::new();
        for n in nums.iter() {
            tasks.push(used_space.decrease(id, *n));
        }
        let _ = futures::future::try_join_all(tasks.into_iter()).await?;

        assert_eq!(0u64, used_space.total());
        assert_eq!(0u64, used_space.local(id).await);

        Ok(())
    }
}
