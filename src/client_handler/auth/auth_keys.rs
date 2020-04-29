// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, vault::Init, Result, ToDbKey};
use log::{trace, warn};
use pickledb::PickleDb;
use safe_nd::{
    AppPermissions, AppPublicId, ClientPublicId, Error as NdError, PublicKey, Result as NdResult,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

type AuthKeysAsTuple = (BTreeMap<PublicKey, AppPermissions>, u64);

const AUTH_KEYS_DB_NAME: &str = "auth_keys.db";

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct AuthKeys {
    apps: HashMap<PublicKey, AppPermissions>,
    version: u64,
}

impl AuthKeys {
    fn into_tuple(self) -> AuthKeysAsTuple {
        (self.apps.into_iter().collect(), self.version)
    }
}

pub struct AuthKeysDb {
    db: PickleDb,
}

impl AuthKeysDb {
    pub fn new<R: AsRef<Path>>(root_dir: R, init_mode: Init) -> Result<Self> {
        Ok(Self {
            db: utils::new_db(root_dir, AUTH_KEYS_DB_NAME, init_mode)?,
        })
    }

    pub fn app_permissions(&self, app_public_id: &AppPublicId) -> Option<AppPermissions> {
        self.db
            .get(&app_public_id.owner().to_db_key())
            .and_then(|auth_keys: AuthKeys| auth_keys.apps.get(app_public_id.public_key()).cloned())
    }

    /// If the specified auth_key doesn't exist, a default `AuthKeysAsTuple` is returned.
    pub fn list_keys_and_version(&self, client_id: &ClientPublicId) -> AuthKeysAsTuple {
        let db_key = client_id.to_db_key();
        self.db
            .get::<AuthKeys>(&db_key)
            .map(AuthKeys::into_tuple)
            .unwrap_or_default()
    }

    /// Inserts `key` and `permissions` into the specified auth_key, creating the auth_key if it
    /// doesn't already exist.
    pub fn insert(
        &mut self,
        client_id: &ClientPublicId,
        key: PublicKey,
        new_version: u64,
        permissions: AppPermissions,
    ) -> NdResult<()> {
        let db_key = client_id.to_db_key();
        let mut auth_keys = self.get_keys_and_increment_version(&db_key, new_version)?;

        // TODO - should we assert the `key` is an App type?

        let _ = auth_keys.apps.insert(key, permissions);
        if let Err(error) = self.db.set(&db_key, &auth_keys) {
            warn!("Failed to write AuthKey to DB: {:?}", error);
            return Err(NdError::from("Failed to insert authorised key."));
        }

        Ok(())
    }

    /// Deletes `key` from the specified auth_key.  Returns `NoSuchKey` if the auth_keys or key doesn't
    /// exist.
    pub fn delete(
        &mut self,
        client_id: &ClientPublicId,
        key: PublicKey,
        new_version: u64,
    ) -> NdResult<()> {
        let db_key = client_id.to_db_key();
        let mut auth_keys = self.get_keys_and_increment_version(&db_key, new_version)?;
        if auth_keys.apps.remove(&key).is_none() {
            trace!("Failed to delete non-existent authorised key {}", key);
            return Err(NdError::NoSuchKey);
        }
        if let Err(error) = self.db.set(&db_key, &auth_keys) {
            warn!("Failed to write AuthKey to DB: {:?}", error);
            return Err(NdError::from("Failed to insert authorised key."));
        }

        Ok(())
    }

    fn get_keys_and_increment_version(&self, db_key: &str, new_version: u64) -> NdResult<AuthKeys> {
        let mut auth_keys = self.db.get::<AuthKeys>(&db_key).unwrap_or_default();

        if auth_keys.version + 1 != new_version {
            trace!(
                "Failed to mutate authorised key.  Current version: {}  New version: {}",
                auth_keys.version,
                new_version
            );
            return Err(NdError::InvalidSuccessor(auth_keys.version));
        }
        auth_keys.version = new_version;
        Ok(auth_keys)
    }
}
