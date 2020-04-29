// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, vault::Init, Result, ToDbKey};
use pickledb::PickleDb;
use safe_nd::{Coins, PublicKey, XorName};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    path::Path,
};

const BALANCES_DB_NAME: &str = "balances.db";

#[derive(Serialize, Deserialize)]
pub struct Balance {
    pub coins: Coins,
}

pub struct BalancesDb {
    db: PickleDb,
    index: HashMap<XorName, PublicKey>,
}

impl BalancesDb {
    pub fn new<R: AsRef<Path>>(root_dir: R, init_mode: Init) -> Result<Self> {
        let db = utils::new_db(root_dir, BALANCES_DB_NAME, init_mode)?;
        let index = db
            .get_all()
            .into_iter()
            .filter_map(|key| {
                base64::decode(&key)
                    .ok()
                    .and_then(|key| bincode::deserialize::<PublicKey>(&key).ok())
            })
            .map(|public_key| (public_key.into(), public_key))
            .collect();

        Ok(Self { db, index })
    }

    pub fn exists<K: Key>(&self, key: &K) -> bool {
        key.to_public_key(&self.index)
            .map(|public_key| self.db.exists(&public_key.to_db_key()))
            .unwrap_or(false)
    }

    pub fn get<K: Key>(&self, key: &K) -> Option<Balance> {
        let public_key = key.to_public_key(&self.index)?;
        self.db.get(&public_key.to_db_key())
    }

    pub fn get_key_value<K: Key>(&self, key: &K) -> Option<(PublicKey, Balance)> {
        let public_key = key.to_public_key(&self.index)?;
        self.db
            .get(&public_key.to_db_key())
            .map(|balance| (*public_key, balance))
    }

    pub fn set(&mut self, public_key: &PublicKey, balance: &Balance) -> Result<()> {
        let db_key = public_key.to_db_key();
        self.db.set(&db_key, &balance)?;
        let _ = self
            .index
            .entry(XorName::from(*public_key))
            .or_insert_with(|| *public_key);
        Ok(())
    }
}

pub trait Key {
    fn to_public_key<'a>(&'a self, index: &'a HashMap<XorName, PublicKey>)
        -> Option<&'a PublicKey>;
}

impl Key for PublicKey {
    fn to_public_key<'a>(&'a self, _: &'a HashMap<XorName, PublicKey>) -> Option<&'a PublicKey> {
        Some(&self)
    }
}

impl Key for XorName {
    fn to_public_key<'a>(
        &'a self,
        index: &'a HashMap<XorName, PublicKey>,
    ) -> Option<&'a PublicKey> {
        index.get(self)
    }
}

impl Display for Balance {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.coins)
    }
}
