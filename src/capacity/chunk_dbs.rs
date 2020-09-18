// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Result};
use pickledb::PickleDb;
use std::{cell::RefCell, path::Path, rc::Rc};

const BLOB_META_DB_NAME: &str = "immutable_data.db";
const HOLDER_META_DB_NAME: &str = "holder_data.db";
const FULL_ADULTS_DB_NAME: &str = "full_adults.db";
// The number of separate copies of a blob chunk which should be maintained.

#[derive(Clone)]
pub struct ChunkHolderDbs {
    pub metadata: Rc<RefCell<PickleDb>>,
    pub holders: Rc<RefCell<PickleDb>>,
    pub full_adults: Rc<RefCell<PickleDb>>,
}

impl ChunkHolderDbs {
    ///
    pub fn new(path: &Path, init: utils::Init) -> Result<Self> {
        let metadata = utils::new_db(path, BLOB_META_DB_NAME, init)?;
        let holders = utils::new_db(path, HOLDER_META_DB_NAME, init)?;
        let full_adults = utils::new_db(path, FULL_ADULTS_DB_NAME, init)?;
        let metadata = Rc::new(RefCell::new(metadata));
        let holders = Rc::new(RefCell::new(holders));
        let full_adults = Rc::new(RefCell::new(full_adults));
        Ok(Self {
            metadata,
            holders,
            full_adults,
        })
    }
}
