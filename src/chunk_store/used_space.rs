// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::error::{Error, Result};
use crate::vault::Init;
use bincode;
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

const USED_SPACE_FILENAME: &str = "used_space";

/// This holds a record (in-memory and on-disk) of the space used by a single `ChunkStore`, and also
/// an in-memory record of the total space used by all `ChunkStore`s.
#[derive(Debug)]
pub(super) struct UsedSpace {
    // Total space consumed by all `ChunkStore`s including this one.
    total_value: Rc<RefCell<u64>>,
    // Space consumed by this one `ChunkStore`.
    local_value: u64,
    // File used to maintain on-disk record of `local_value`.
    local_record: File,
}

impl UsedSpace {
    pub fn new<T: AsRef<Path>>(
        dir: T,
        total_used_space: Rc<RefCell<u64>>,
        init_mode: Init,
    ) -> Result<Self> {
        let mut local_record = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(dir.as_ref().join(USED_SPACE_FILENAME))?;
        let local_value = if init_mode == Init::Load {
            let mut buffer = vec![];
            let _ = local_record.read_to_end(&mut buffer)?;
            // TODO - if this can't be parsed, we should consider emptying `dir` of any chunks.
            bincode::deserialize::<u64>(&buffer)?
        } else {
            bincode::serialize_into(&mut local_record, &0_u64)?;
            0
        };
        Ok(Self {
            total_value: total_used_space,
            local_value,
            local_record,
        })
    }

    /// Returns the total space consumed by all `ChunkStore`s including this one.
    pub fn total(&self) -> u64 {
        *self.total_value.borrow()
    }

    pub fn increase(&mut self, consumed: u64) -> Result<()> {
        let new_total = self
            .total_value
            .borrow()
            .checked_add(consumed)
            .ok_or(Error::NotEnoughSpace)?;
        let new_local = self
            .local_value
            .checked_add(consumed)
            .ok_or(Error::NotEnoughSpace)?;
        self.record_new_values(new_total, new_local)
    }

    pub fn decrease(&mut self, released: u64) -> Result<()> {
        let new_total = self.total_value.borrow().saturating_sub(released);
        let new_local = self.local_value.saturating_sub(released);
        self.record_new_values(new_total, new_local)
    }

    fn record_new_values(&mut self, total: u64, local: u64) -> Result<()> {
        self.local_record.set_len(0)?;
        let _ = self.local_record.seek(SeekFrom::Start(0))?;
        bincode::serialize_into(&self.local_record, &local)?;
        *self.total_value.borrow_mut() = total;
        self.local_value = local;
        Ok(())
    }
}
