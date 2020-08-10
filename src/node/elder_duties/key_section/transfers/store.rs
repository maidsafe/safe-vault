// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::state_db::Init, to_db_key::from_db_key, utils, Error, Result, ToDbKey};
use pickledb::PickleDb;
use safe_nd::{AccountId, ReplicaEvent};
use std::{collections::BTreeSet, path::Path};

const TRANSFERS_DB_NAME: &str = "transfers.db";
const GROUP_CHANGES: &str = "group_changes";

/// Disk storage for transfers.
pub struct TransferStore {
    db: PickleDb,
}

impl TransferStore {
    pub fn new<R: AsRef<Path>>(root_dir: R, init_mode: Init) -> Result<Self> {
        Ok(Self {
            db: utils::new_db(root_dir, TRANSFERS_DB_NAME, init_mode)?,
        })
    }

    pub fn all_stream_keys(&self) -> Option<Vec<AccountId>> {
        let keys = self
            .db
            .get_all()
            .iter()
            .filter_map(|key| from_db_key(key))
            .collect();

        Some(keys)
    }

    pub fn history(&self, id: &AccountId) -> Option<Vec<ReplicaEvent>> {
        let list: Vec<ReplicaEvent> = self
            .db
            .liter(&id.to_db_key())
            .filter_map(|c| c.get_item::<ReplicaEvent>())
            .collect();
        Some(list)
    }

    pub fn try_load(&self) -> Result<Vec<ReplicaEvent>> {
        // Only the order within the streams is important, not between streams.
        let keys = self.db.get_all();
        let events: Vec<ReplicaEvent> = keys
            .iter()
            //.filter(|key| self.db.lexists(&key)) 
            // not all keys are necessarily lists..,
            // in which case we would get an exception at liter below
            // but in current impl, they all are, so no need to filter, yet.
            .map(|key| {
                self.db
                    .liter(&key)
                    .filter_map(|c| c.get_item::<ReplicaEvent>())
                    .collect::<Vec<ReplicaEvent>>()
            })
            .flatten()
            .collect();
        Ok(events)
    }

    pub fn drop(&mut self, streams: &BTreeSet<AccountId>) -> Result<()> {
        for stream in streams {
            let _ = self.db.lrem_list(&stream.to_db_key());
        }
        Ok(())
    }

    pub fn init(&mut self, events: Vec<ReplicaEvent>) -> Result<()> {
        for event in events {
            self.try_append(event)?;
        }
        Ok(())
    }

    pub fn try_append(&mut self, event: ReplicaEvent) -> Result<()> {
        match event {
            ReplicaEvent::KnownGroupAdded(e) => {
                if !self.db.lexists(GROUP_CHANGES) {
                    // Creates if not exists.
                    match self.db.lcreate(GROUP_CHANGES) {
                        Ok(_) => (),
                        Err(error) => return Err(Error::PickleDb(error)),
                    };
                }
                match self
                    .db
                    .ladd(GROUP_CHANGES, &ReplicaEvent::KnownGroupAdded(e))
                {
                    Some(_) => Ok(()),
                    None => Err(Error::NetworkData("Failed to write event to db.".into())),
                }
            }
            ReplicaEvent::TransferPropagated(e) => {
                let key = &e.to().to_db_key();
                if !self.db.lexists(key) {
                    // Creates if not exists. A stream always starts with a credit.
                    match self.db.lcreate(key) {
                        Ok(_) => (),
                        Err(error) => return Err(Error::PickleDb(error)),
                    };
                }
                match self.db.ladd(key, &ReplicaEvent::TransferPropagated(e)) {
                    Some(_) => Ok(()),
                    None => Err(Error::NetworkData("Failed to write event to db.".into())),
                }
            }
            ReplicaEvent::TransferValidated(e) => {
                let id = e.from();
                match self
                    .db
                    .ladd(&id.to_db_key(), &ReplicaEvent::TransferValidated(e))
                {
                    Some(_) => Ok(()),
                    None => Err(Error::NetworkData("Failed to write event to db.".into())), // A stream always starts with a credit, so not existing when debiting is simply invalid.
                }
            }
            ReplicaEvent::TransferRegistered(e) => {
                let id = e.from();
                match self
                    .db
                    .ladd(&id.to_db_key(), &ReplicaEvent::TransferRegistered(e))
                {
                    Some(_) => Ok(()),
                    None => Err(Error::NetworkData("Failed to write event to db.".into())), // A stream always starts with a credit, so not existing when debiting is simply invalid.
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;
    use bls::SecretKey;
    use safe_nd::{PublicKey, TransferPropagated};
    use safe_transfers::get_genesis;
    use tempdir::TempDir;

    #[test]
    fn history() -> Result<()> {
        let tmp_dir = TempDir::new("history")?;
        let root_dir = tmp_dir.path();
        let mut store = TransferStore::new(root_dir, Init::New)?;
        let account_id = get_random_pk();
        let debit_proof = get_genesis(10, account_id)?;
        store.try_append(ReplicaEvent::TransferPropagated(TransferPropagated {
            debit_proof,
            debiting_replicas: get_random_pk(),
            crediting_replica_sig: dummy_sig(),
        }))?;
        if let Some(history) = store.history(&account_id) {
            assert_eq!(history.len(), 1);
        } else {
            panic!();
        }
        Ok(())
    }

    #[test]
    fn all_stream_keys() -> Result<()> {
        let tmp_dir = TempDir::new("all_stream_keys")?;
        let root_dir = tmp_dir.path();
        let mut store = TransferStore::new(root_dir, Init::New)?;
        let account_id = get_random_pk();
        let debit_proof = get_genesis(10, account_id)?;
        store.try_append(ReplicaEvent::TransferPropagated(TransferPropagated {
            debit_proof,
            debiting_replicas: get_random_pk(),
            crediting_replica_sig: dummy_sig(),
        }))?;
        if let Some(list) = store.all_stream_keys() {
            assert_eq!(list.len(), 1);
        } else {
            panic!();
        }
        Ok(())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }

    use bls::SecretKeyShare;
    use safe_nd::SignatureShare;
    fn dummy_sig() -> SignatureShare {
        let dummy_shares = SecretKeyShare::default();
        let dummy_sig = dummy_shares.sign("DUMMY MSG");
        SignatureShare {
            index: 0,
            share: dummy_sig,
        }
    }
}
