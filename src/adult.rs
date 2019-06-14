// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{chunk_store::ImmutableChunkStore, vault::Init, Result};
use std::{cell::RefCell, path::Path, rc::Rc};

pub(crate) struct Adult {
    immutable_chunks: ImmutableChunkStore,
}

impl Adult {
    pub fn new<P: AsRef<Path>>(root_dir: P, max_capacity: u64, init_mode: Init) -> Result<Self> {
        let total_used_space = Rc::new(RefCell::new(0));
        let immutable_chunks = ImmutableChunkStore::new(
            root_dir,
            max_capacity,
            Rc::clone(&total_used_space),
            init_mode,
        )?;
        Ok(Self { immutable_chunks })
    }
}
