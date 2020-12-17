// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, utils::Init, Error, Result, ToDbKey};
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
    pub fn new(id: XorName, root_dir: &PathBuf, init_mode: Init) -> Result<Self> {
        let db_dir = root_dir.join(Path::new(TRANSFERS_DIR_NAME));
        let db_name = format!("{}{}", id.to_db_key()?, DB_EXTENSION);
        Ok(Self {
            id,
            db: utils::new_auto_dump_db(db_dir.as_path(), db_name, init_mode)?,
            //db: utils::new_periodic_dump_db(db_dir.as_path(), db_name, init_mode)?,
            _phantom: PhantomData::default(),
        })
    }

    ///
    pub fn id(&self) -> XorName {
        self.id
    }

    ///
    pub fn get_all(&self) -> Vec<TEvent> {
        trace!(
            "Getting all events from transfer store w/id: {:?}",
            self.id()
        );
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

        trace!("all events {:?} ", events);
        events
    }

    ///
    pub fn try_insert(&mut self, event: TEvent) -> Result<()> {
        debug!("Trying to insert replica event: {:?}", event);
        let key = &self.db.total_keys().to_string();
        if self.db.exists(key) {
            return Err(Error::Logic(format!(
                "Key exists: {}. Event: {:?}",
                key, event
            )));
        }
        self.db.set(key, &event).map_err(Error::PickleDb)
        // match event {
        //     ReplicaEvent::KnownGroupAdded(_e) => unimplemented!("to be deprecated"),
        //     ReplicaEvent::TransferPropagated(e) => {
        //         if self.db.exists(key) {
        //             return Err(Error::Logic(format!("Key exists: {}. Event: {:?}", key, e)));
        //         }
        //         self.db
        //             .set(key, &ReplicaEvent::TransferPropagated(e))
        //             .map_err(Error::PickleDb)
        //     }
        //     ReplicaEvent::TransferValidated(e) => {
        //         if self.db.exists(key) {
        //             return Err(Error::Logic(format!("Key exists: {}. Event: {:?}", key, e)));
        //         }
        //         self.db
        //             .set(key, &ReplicaEvent::TransferValidated(e))
        //             .map_err(Error::PickleDb)
        //     }
        //     ReplicaEvent::TransferRegistered(e) => {
        //         if self.db.exists(key) {
        //             return Err(Error::Logic(format!("Key exists: {}. Event: {:?}", key, e)));
        //         }
        //         self.db
        //             .set(key, &ReplicaEvent::TransferRegistered(e))
        //             .map_err(Error::PickleDb)
        //     }
        // }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;
    use bls::SecretKey;
    use sn_data_types::{PublicKey, ReplicaEvent, TransferPropagated};
    use sn_transfers::get_genesis;
    use tempdir::TempDir;

    #[test]
    fn history() -> Result<()> {
        let id = xor_name::XorName::random();
        let tmp_dir = TempDir::new("root")?;
        let root_dir = tmp_dir.into_path();
        let mut store = TransferStore::new(id, &root_dir, Init::New)?;
        let wallet_id = get_random_pk();
        let genesis_credit_proof = get_genesis(10, wallet_id)?;
        store.try_insert(ReplicaEvent::TransferPropagated(TransferPropagated {
            credit_proof: genesis_credit_proof.clone(),
            crediting_replica_keys: get_random_pk(),
            crediting_replica_sig: dummy_sig(),
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

    use bls::SecretKeyShare;
    use sn_data_types::SignatureShare;
    fn dummy_sig() -> SignatureShare {
        let dummy_shares = SecretKeyShare::default();
        let dummy_sig = dummy_shares.sign("DUMMY MSG");
        SignatureShare {
            index: 0,
            share: dummy_sig,
        }
    }
}
