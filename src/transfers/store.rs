// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{to_db_key::ToDbKey, utils, Error, Result};
use pickledb::PickleDb;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, marker::PhantomData, path::Path};
use xor_name::XorName;

const TRANSFERS_DIR_NAME: &str = "transfers";
const DB_EXTENSION: &str = ".db";

/// Disk storage for transfers.
pub struct TransferStore<TEvent: Debug + Serialize + DeserializeOwned> {
    db: PickleDb,
    _phantom: PhantomData<TEvent>,
}

impl<'a, TEvent: Debug + Serialize + DeserializeOwned> TransferStore<TEvent>
where
    TEvent: 'a,
{
    pub fn new(id: XorName, root_dir: &Path) -> Result<Self> {
        let db_dir = root_dir.join(Path::new(TRANSFERS_DIR_NAME));
        let db_name = format!("{}{}", id.to_db_key()?, DB_EXTENSION);
        Ok(Self {
            db: utils::new_auto_dump_db(db_dir.as_path(), db_name)?,
            _phantom: PhantomData::default(),
        })
    }

    ///
    pub fn get_all(&self) -> Vec<TEvent> {
        let mut events = self
            .db
            .iter()
            .filter_map(
                |entry| match (entry.get_key().parse::<usize>(), entry.get_value()) {
                    (Ok(k), Some(v)) => Some((k, v)),
                    _ => None,
                },
            )
            .collect::<Vec<(usize, TEvent)>>();

        let _ = &events[..].sort_by(|(left_key, _), (right_key, _)| left_key.cmp(right_key));
        events.into_iter().map(|(k, v)| v).collect()
    }

    ///
    pub fn try_insert(&mut self, event: TEvent) -> Result<()> {
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
    use super::TransferStore;
    use crate::{Error, Result};
    use bls::SecretKeySet;
    use bls::{PublicKeySet, SecretKey, SecretKeyShare};
    use sn_data_types::{
        Credit, CreditAgreementProof, CreditId, PublicKey, ReplicaEvent, SignedCredit, Token,
        TransferPropagated,
    };
    use std::collections::BTreeMap;
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
        let genesis_credit_proof = get_credit(
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

    /// Produces a genesis balance for a new network.
    fn get_credit(
        balance: u64,
        id: PublicKey,
        peer_replicas: PublicKeySet,
        secret_key_share: SecretKeyShare,
    ) -> Result<CreditAgreementProof> {
        let credit = Credit {
            id: CreditId::default(),
            amount: Token::from_nano(balance),
            recipient: id,
            msg: "genesis".to_string(),
        };

        // actor instances' signatures over > credit <

        let serialised_credit = bincode::serialize(&credit).map_err(Error::Bincode)?;

        let mut credit_sig_shares = BTreeMap::new();
        let credit_sig_share = secret_key_share.sign(serialised_credit);
        let _ = credit_sig_shares.insert(0, credit_sig_share);

        println!("Aggregating actor signature..");

        // Combine shares to produce the main signature.
        let actor_signature = sn_data_types::Signature::Bls(
            peer_replicas
                .combine_signatures(&credit_sig_shares)
                .map_err(|_| Error::CouldNotCombineSignatures)?,
        );

        let signed_credit = SignedCredit {
            credit,
            actor_signature,
        };

        // replicas signatures over > signed_credit <

        let serialised_credit = bincode::serialize(&signed_credit).map_err(Error::Bincode)?;

        let mut credit_sig_shares = BTreeMap::new();
        let credit_sig_share = secret_key_share.sign(serialised_credit);
        let _ = credit_sig_shares.insert(0, credit_sig_share);

        println!("Aggregating replica signature..");

        let debiting_replicas_sig = sn_data_types::Signature::Bls(
            peer_replicas
                .combine_signatures(&credit_sig_shares)
                .map_err(|_| Error::CouldNotCombineSignatures)?,
        );

        Ok(CreditAgreementProof {
            signed_credit,
            debiting_replicas_sig,
            debiting_replicas_keys: peer_replicas,
        })
    }
}
