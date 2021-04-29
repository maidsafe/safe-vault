// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Result};
use futures::lock::Mutex;
use pickledb::PickleDb;
use std::path::Path;
use std::sync::Arc;

const FULL_ADULTS_DB_NAME: &str = "full_adults.db";

#[derive(Clone)]
pub struct ChunkHolderDbs {
    pub full_adults: Arc<Mutex<PickleDb>>,
}

impl ChunkHolderDbs {
    ///
    pub fn new(path: &Path) -> Result<Self> {
        let full_adults = utils::new_auto_dump_db(path, FULL_ADULTS_DB_NAME)?;
        Ok(Self {
            full_adults: Arc::new(Mutex::new(full_adults)),
        })
    }
}
