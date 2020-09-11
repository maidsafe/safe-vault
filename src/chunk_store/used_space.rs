// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::error::{Error, Result};
use crate::node::state_db::Init;
use std::{io::SeekFrom, path::Path, sync::Arc};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock
};

const USED_SPACE_FILENAME: &str = "used_space";

/// This holds a record (in-memory and on-disk) of the space used by a single `ChunkStore`, and also
/// an in-memory record of the total space used by all `ChunkStore`s.
#[derive(Debug)]
pub(super) struct LocalUsedSpace {
    // Space consumed by this one `ChunkStore`.
    local_value: u64,
    // File used to maintain on-disk record of `local_value`.
    local_record: File,
}

impl LocalUsedSpace {
    pub async fn new<T: AsRef<Path>>(
        dir: T,
        init_mode: Init,
    ) -> Result<Self> {
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
        Ok(Self {
            local_value,
            local_record,
        })
    }

    pub async fn increase(&mut self, consumed: u64) -> Result<()> {
        // let mut total = self.total_value.write().await;
        // let new_total = total
        //   .checked_add(consumed)
        //    .ok_or(Error::NotEnoughSpace)?;
        let new_local = self
            .local_value
            .checked_add(consumed)
            .ok_or(Error::NotEnoughSpace)?;

        // *total = new_total;
        // TODO: implement some monotonic version counter on local value
        // so old writes dont overwrite new ones
        self.local_value = new_local;
        self.record_new_values(new_local).await
    }

    pub async fn decrease(&mut self, released: u64) -> Result<()> {
        // let mut total = self.total_value.write().await;
        // let new_total = total.saturating_sub(released);
        let new_local = self.local_value.saturating_sub(released);

        //* total = new_total;
        // TODO: implement some monotonic version counter on local value
        // so old writes dont overwrite new ones
        self.local_value = new_local;
        self.record_new_values(new_local).await
    }

    async fn record_new_values(&mut self, local: u64) -> Result<()> {
        self.local_record.set_len(0).await?;
        let _ = self.local_record.seek(SeekFrom::Start(0)).await?;

        let mut contents = Vec::<u8>::new();
        bincode::serialize_into(&mut contents, &local)?;
        self.local_record.write_all(&contents).await?;

        //self.total_value.set(total);
        self.local_value = local;
        Ok(())
    }
}
