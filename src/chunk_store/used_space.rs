// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::error::{Error, Result};
use crate::utils::Init;
// use crate::node::Init;
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;

const USED_SPACE_FILENAME: &str = "used_space";

/// This holds a record (in-memory and on-disk) of the space used by a single `ChunkStore`, and also
/// an in-memory record of the total space used by all `ChunkStore`s.
#[derive(Debug)]
pub struct UsedSpace {
    inner: Arc<Mutex<inner::UsedSpace>>,
}

/// Identifies a `ChunkStore` within the larger
/// used space tracking
pub type StoreId = u64;

impl Clone for UsedSpace {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl UsedSpace {
    /// construct a new used space instance
    /// NOTE: this constructs a new async-safe instance,
    /// If you intend to create a new local `ChunkStore` tracking,
    /// then use `clone()` and `add_local_store()` to ensure
    /// consistentcy across local `ChunkStore`s
    pub fn new(max_capacity: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner::UsedSpace::new(max_capacity))),
        }
    }

    /// Add an object and file store to track used space of a single
    /// `ChunkStore`
    pub async fn add_local_store<T: AsRef<Path>>(
        &self,
        dir: T,
        init_mode: Init,
    ) -> Result<StoreId> {
        inner::UsedSpace::add_local_store(self.inner.clone(), dir, init_mode).await
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
                max_capacity: max_capacity,
                total_value: 0u64,
                local_stores: HashMap::new(),
                next_id: 0u64,
            }
        }

        /// Adds a new record for tracking the actions
        /// of a local chunk store as part of the global
        /// used amount tracking
        pub async fn add_local_store<T: AsRef<Path>>(
            used_space: Arc<Mutex<UsedSpace>>,
            dir: T,
            init_mode: Init,
        ) -> Result<StoreId> {
            let mut local_record = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(dir.as_ref().join(USED_SPACE_FILENAME))
                .await?;
            let local_value = if init_mode == Init::Load {
                let mut buffer = vec![];
                let _ = local_record.read_to_end(&mut buffer).await?;
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
                .unwrap()
                .local_value
                .checked_add(consumed)
                .ok_or(Error::NotEnoughSpace)?;

            {
                let record = &mut used_space_lock
                    .local_stores
                    .get_mut(&id)
                    .unwrap()
                    .local_record;
                Self::write_local_to_file(record, new_local).await?;
            }
            used_space_lock.total_value = new_total;
            used_space_lock
                .local_stores
                .get_mut(&id)
                .unwrap()
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
                .unwrap()
                .local_value
                .saturating_sub(released);
            let new_total = used_space_lock.total_value.saturating_sub(released);
            {
                let record = &mut used_space_lock
                    .local_stores
                    .get_mut(&id)
                    .unwrap()
                    .local_record;
                Self::write_local_to_file(record, new_local).await?;
            }
            used_space_lock.total_value = new_total;
            used_space_lock
                .local_stores
                .get_mut(&id)
                .unwrap()
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

            Ok(())
        }
    }
}
