// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, vault::Init, Result, ToDbKey};
use pickledb::PickleDb;
use safe_nd::{AppPermissions, ClientPublicId, Coins, PublicKey, XorName};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
use unwrap::unwrap;

const CLIENT_ACCOUNTS_DB_NAME: &str = "client_accounts.db";

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct ClientAccount {
    pub apps: HashMap<PublicKey, AppPermissions>,
    pub balance: Coins,
}

impl ClientAccount {
    // TODO: remove allow(unsued)
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            balance: unwrap!(Coins::from_nano(0)),
        }
    }
}

pub(super) struct ClientAccountDb {
    db: PickleDb,
    index: HashMap<XorName, ClientPublicId>,
}

impl ClientAccountDb {
    pub fn new<R: AsRef<Path>>(root_dir: R, init_mode: Init) -> Result<Self> {
        let db = utils::new_db(root_dir, CLIENT_ACCOUNTS_DB_NAME, init_mode)?;
        let index = db
            .get_all()
            .into_iter()
            .filter_map(|key| {
                base64::decode(&key)
                    .ok()
                    .and_then(|key| bincode::deserialize::<ClientPublicId>(&key).ok())
            })
            .map(|public_id| (*public_id.name(), public_id))
            .collect();

        Ok(Self { db, index })
    }

    pub fn exists<K: Key>(&self, key: &K) -> bool {
        key.to_public_id(&self.index)
            .map(|public_id| {
                let db_key = public_id.to_db_key();
                self.db.exists(&db_key)
            })
            .unwrap_or(false)
    }

    pub fn get<K: Key>(&self, key: &K) -> Option<ClientAccount> {
        let public_id = key.to_public_id(&self.index)?;
        self.db.get(&public_id.to_db_key())
    }

    pub fn put(&mut self, public_id: &ClientPublicId, account: ClientAccount) -> Result<()> {
        let db_key = public_id.to_db_key();
        self.db.set(&db_key, &account)?;
        let _ = self
            .index
            .entry(*public_id.name())
            .or_insert_with(|| public_id.clone());
        Ok(())
    }
}

pub(super) trait Key {
    fn to_public_id<'a>(
        &'a self,
        index: &'a HashMap<XorName, ClientPublicId>,
    ) -> Option<&'a ClientPublicId>;
}

impl Key for ClientPublicId {
    fn to_public_id<'a>(
        &'a self,
        _: &'a HashMap<XorName, ClientPublicId>,
    ) -> Option<&'a ClientPublicId> {
        Some(&self)
    }
}

impl Key for XorName {
    fn to_public_id<'a>(
        &'a self,
        index: &'a HashMap<XorName, ClientPublicId>,
    ) -> Option<&'a ClientPublicId> {
        index.get(self)
    }
}

impl Key for PublicKey {
    fn to_public_id<'a>(
        &'a self,
        index: &'a HashMap<XorName, ClientPublicId>,
    ) -> Option<&'a ClientPublicId> {
        let name = XorName::from(*self);
        index.get(&name)
    }
}
