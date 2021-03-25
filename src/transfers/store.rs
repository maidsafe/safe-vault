// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Error, Result, ToDbKey};
use log::{debug, trace};
use pickledb::PickleDb;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt::Debug,
    marker::PhantomData,
    path::{Path, PathBuf},
};
use xor_name::XorName;

const TRANSFERS_DIR_NAME: &str = "transfers";
const DB_EXTENSION: &str = ".db";

/// Disk storage for transfers.
pub struct TransferStore<TEvent: Debug + Serialize + DeserializeOwned> {
    id: XorName,
    db: PickleDb,
    _phantom: PhantomData<TEvent>,
}

impl<'a, TEvent: Debug + Serialize + DeserializeOwned> TransferStore<TEvent>
where
    TEvent: 'a,
{
    pub fn new(id: XorName, root_dir: &PathBuf) -> Result<Self> {
        let db_dir = root_dir.join(Path::new(TRANSFERS_DIR_NAME));
        let db_name = format!("{}{}", id.to_db_key()?, DB_EXTENSION);
        Ok(Self {
            id,
            db: utils::new_auto_dump_db(db_dir.as_path(), db_name)?,
            _phantom: PhantomData::default(),
        })
    }

    ///
    pub fn id(&self) -> XorName {
        self.id
    }

    ///
    pub fn get_all(&self) -> Vec<TEvent> {
        let keys = self.db.get_all();

        let mut events: Vec<(usize, TEvent)> = keys
            .iter()
            .filter_map(|key| {
                let value = self.db.get::<TEvent>(key);
                let key = key.parse::<usize>();
                match value {
                    Some(v) => match key {
                        Ok(k) => Some((k, v)),
                        _ => None,
                    },
                    None => None,
                }
            })
            .collect();

        events.sort_by(|(key_a, _), (key_b, _)| key_a.partial_cmp(key_b).unwrap());

        let events: Vec<TEvent> = events.into_iter().map(|(_, val)| val).collect();

        events
    }

    ///
    pub fn try_insert(&mut self, event: TEvent) -> Result<()> {
        debug!("Inserting replica event: {:?}", event);
        let key = &self.db.total_keys().to_string();
        if self.db.exists(key) {
            return Err(Error::Logic(format!(
                "Key exists: {}. Event: {:?}",
                key, event
            )));
        }
        self.db.set(key, &event).map_err(Error::PickleDb)
    }
}

#[cfg(test)]
mod test {
    use super::super::test_utils::get_genesis;
    use super::*;
    use crate::Result;
    use bls::SecretKey;
    use bls::SecretKeySet;
    use sn_data_types::{PublicKey, ReplicaEvent, TransferPropagated};
    use tempdir::TempDir;

    #[test]
    fn history() -> Result<()> {
        let id = xor_name::XorName::random();
        let tmp_dir = TempDir::new("root")?;
        let root_dir = tmp_dir.into_path();
        let mut store = TransferStore::new(id, &root_dir)?;
        let wallet_id = get_random_pk();
        let mut rng = rand::thread_rng();
        let bls_secret_key = SecretKeySet::random(0, &mut rng);
        let genesis_credit_proof = get_genesis(
            10,
            wallet_id,
            bls_secret_key.public_keys(),
            bls_secret_key.secret_key_share(0),
        )?;
        store.try_insert(ReplicaEvent::TransferPropagated(TransferPropagated {
            credit_proof: genesis_credit_proof.clone(),
        }))?;

        let events = store.get_all();
        assert_eq!(events.len(), 1);

        match &events[0] {
            ReplicaEvent::TransferPropagated(TransferPropagated { credit_proof, .. }) => {
                assert_eq!(credit_proof, &genesis_credit_proof)
            }
            other => {
                return Err(Error::Logic(format!(
                    "Incorrect Replica event: {:?}",
                    other
                )))
            }
        }

        Ok(())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
