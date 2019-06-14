// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, vault::Init, Result};
use pickledb::PickleDb;
use std::path::Path;

const COINS_DB_NAME: &str = "coins.db";

pub(crate) struct CoinsHandler {
    // The total safecoin farmed from this section.
    farmed: PickleDb,
}

impl CoinsHandler {
    pub fn new<P: AsRef<Path>>(root_dir: P, init_mode: Init) -> Result<Self> {
        let farmed = utils::new_db(root_dir, COINS_DB_NAME, init_mode)?;
        Ok(Self { farmed })
    }
}
