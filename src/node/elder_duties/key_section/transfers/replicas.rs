// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::genesis::get_genesis;
use super::store::TransferStore;
use crate::{utils::Init, Error, ReplicaInfo, Result};
use bls::PublicKeySet;
use dashmap::DashMap;
use futures::lock::Mutex;
use log::info;
use sn_data_types::{
    CreditAgreementProof, Error as NdError, Money, PublicKey, ReplicaEvent, SignedTransfer,
    TransferAgreementProof, TransferPropagated, TransferRegistered, TransferValidated,
};
use sn_transfers::WalletReplica;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use xor_name::Prefix;

#[cfg(feature = "simulated-payouts")]
use {
    crate::node::node_ops::NodeMessagingDuty,
    bls::{SecretKey, SecretKeySet, SecretKeyShare},
    log::debug,
    rand::thread_rng,
    sn_data_types::{Signature, SignatureShare, SignedCredit, SignedDebit, Transfer},
};

type WalletLocks = DashMap<PublicKey, Arc<Mutex<TransferStore>>>;

#[derive(Clone)]
pub struct Replicas {
    root_dir: PathBuf,
    info: ReplicaInfo,
    locks: WalletLocks,
    self_lock: Arc<Mutex<usize>>,
}

impl Replicas {
    pub(crate) fn new(root_dir: PathBuf, info: ReplicaInfo) -> Result<Self> {
        Ok(Self {
            root_dir,
            info,
            locks: Default::default(),
            self_lock: Arc::new(Mutex::new(0)),
        })
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// All keys' histories
    pub async fn all_events(&self) -> Result<Vec<ReplicaEvent>> {
        let events = self
            .locks
            .iter()
            .map(|r| *r.key())
            // TODO: This presupposes a dump has occured...
            .filter_map(|id| TransferStore::new(id.into(), &self.root_dir, Init::Load).ok())
            .map(|store| store.get_all())
            .flatten()
            .collect();
        Ok(events)
    }

    /// History of events
    pub async fn history(&self, id: PublicKey) -> Result<Vec<ReplicaEvent>> {
        debug!("Replica history get");
        let store = TransferStore::new(id.into(), &self.root_dir, Init::Load);

        if let Err(error) = store {
            // uugh.. iffy string comparison, we need to handle this in a better way
            let err_string = error.to_string();
            let err_type_0 = "PickleDb error: No such file or directory";
            let err_type_1 =
                "PickleDb error: The system cannot find the file specified. (os error 2)";
            if err_string == err_type_0 || err_string == err_type_1 {
                // we have no history yet, so lets report that.
                return Ok(vec![]);
            }

            return Err(error);
        };

        let store = store?;

        Ok(store.get_all())
    }

    ///
    pub async fn balance(&self, id: PublicKey) -> Result<Money> {
        debug!("Replica: Getting balance of: {:?}", id);
        let store = TransferStore::new(id.into(), &self.root_dir, Init::Load)?;
        let wallet = self.load_wallet(&store, id).await?;
        Ok(wallet.balance())
    }

    /// Get the replica's PK set
    pub fn replicas_pk_set(&self) -> PublicKeySet {
        self.info.peer_replicas.clone()
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    pub async fn initiate(&self, events: &[ReplicaEvent]) -> Result<()> {
        use ReplicaEvent::*;
        if events.is_empty() {
            info!("Events are empty. Initiating Genesis replica.");
            let credit_proof = self.create_genesis().await?;
            let genesis_source = Ok(PublicKey::Bls(credit_proof.replica_keys().public_key()));
            return self.store_genesis(&credit_proof, || genesis_source).await;
        }
        for e in events {
            let id = match e {
                TransferValidated(e) => e.sender(),
                TransferRegistered(e) => e.sender(),
                TransferPropagated(e) => e.recipient(),
                KnownGroupAdded(_) => unimplemented!(),
            };

            // Acquire lock of the wallet.
            let key_lock = self.load_key_lock(id).await?;
            let mut store = key_lock.lock().await;

            // Access to the specific wallet is now serialised!
            store.try_insert(e.to_owned())?;
        }
        Ok(())
    }

    ///
    pub fn update_replica_keys(&mut self, info: ReplicaInfo) {
        self.info = info;
    }

    pub async fn keep_keys_of(&self, prefix: Prefix) -> Result<()> {
        // Removes keys that are no longer our section responsibility.
        let keys: Vec<PublicKey> = self.locks.iter().map(|r| *r.key()).collect();
        for key in keys.into_iter() {
            if !prefix.matches(&key.into()) {
                let key_lock = self.load_key_lock(key).await?;
                let _store = key_lock.lock().await;
                let _ = self.locks.remove(&key);
                // todo: remove db from disk
            }
        }
        Ok(())
    }

    /// Step 1. Main business logic validation of a debit.
    pub async fn validate(&self, signed_transfer: SignedTransfer) -> Result<TransferValidated> {
        debug!("Replica validating transfer: {:?}", signed_transfer);
        let id = signed_transfer.sender();
        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, id).await?;

        debug!("******************&&&&&swallet loadded");
        let result = wallet.validate(&signed_transfer.debit, &signed_transfer.credit);

        debug!("validation sezzzz: {:?}", result);

        let _ = result?;
        debug!("wallet valid");
        // signing will be serialised
        if let Some((replica_debit_sig, replica_credit_sig)) = self
            .info
            .signing
            .lock()
            .await
            .sign_transfer(&signed_transfer)?
        {
            // release lock and update state
            let event = TransferValidated {
                signed_credit: signed_transfer.credit,
                signed_debit: signed_transfer.debit,
                replica_debit_sig,
                replica_credit_sig,
                replicas: self.info.peer_replicas.clone(),
            };
            store.try_insert(ReplicaEvent::TransferValidated(event.clone()))?;
            Ok(event)
        } else {
            Err(Error::InvalidMessage)
        }
    }

    /// Step 2. Validation of agreement, and order at debit source.
    pub async fn register(
        &self,
        transfer_proof: &TransferAgreementProof,
    ) -> Result<TransferRegistered> {
        let id = transfer_proof.sender();
        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, id).await?;
        match wallet.register(transfer_proof, || {
            self.find_past_key(&transfer_proof.replica_keys())
        })? {
            None => {
                info!("transfer already registered!");
                Err(Error::NetworkData(NdError::NetworkOther(
                    "transfer already registered!".to_string(),
                )))
            }
            Some(event) => {
                store.try_insert(ReplicaEvent::TransferRegistered(event.clone()))?;
                Ok(event)
            }
        }
    }

    /// Step 3. Validation of DebitAgreementProof, and credit idempotency at credit destination.
    /// (Since this leads to a credit, there is no requirement on order.)
    pub async fn receive_propagated(
        &self,
        credit_proof: &CreditAgreementProof,
    ) -> Result<TransferPropagated> {
        // Acquire lock of the wallet.
        let id = credit_proof.recipient();

        // Only when propagated is there a risk that the store doesn't exist,
        // and that we want to create it. All other write operations require that
        // a propagation has occurred first. Read ops simply return error when it doesn't exist.
        let key_lock = match self.load_key_lock(id).await {
            Ok(key_lock) => key_lock,
            Err(_) => {
                // lock on us, but only when store doesn't exist
                let self_lock = self.self_lock.lock().await;
                match self.load_key_lock(id).await {
                    Ok(store) => store,
                    Err(_) => {
                        // no key lock (hence no store), so we create one
                        let store = TransferStore::new(id.into(), &self.root_dir, Init::New)?;
                        let locked_store = Arc::new(Mutex::new(store));
                        let _ = self.locks.insert(id, locked_store.clone());
                        let _ = self_lock.overflowing_add(0); // resolve: is a usage at end of block necessary to actually engage the lock?
                        locked_store
                    }
                }
            }
        };

        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, id).await?;
        let propagation_result = wallet.receive_propagated(credit_proof, || {
            self.find_past_key(&credit_proof.replica_keys())
        });

        if propagation_result.is_ok() {
            // sign + update state
            if let Some(crediting_replica_sig) = self
                .info
                .signing
                .lock()
                .await
                .sign_credit_proof(credit_proof)?
            {
                let event = TransferPropagated {
                    credit_proof: credit_proof.clone(),
                    crediting_replica_keys: PublicKey::Bls(self.info.peer_replicas.public_key()),
                    crediting_replica_sig,
                };
                // only add it locally i we don't know about it... (this prevents SimulatedPayouts being reapplied due to varied sigs.)
                if propagation_result?.is_some() {
                    store.try_insert(ReplicaEvent::TransferPropagated(event.clone()))?;
                }
                return Ok(event);
            }
        }
        Err(Error::InvalidMessage)
    }

    async fn load_key_lock(&self, id: PublicKey) -> Result<Arc<Mutex<TransferStore>>> {
        match self.locks.get(&id) {
            Some(val) => Ok(val.clone()),
            None => Err(Error::Logic("Key does not exist among locks.".to_string())),
        }
    }

    async fn load_wallet(&self, store: &TransferStore, id: PublicKey) -> Result<WalletReplica> {
        let events = store.get_all();
        let wallet = WalletReplica::from_history(
            id,
            self.info.id,
            self.info.key_index,
            self.info.peer_replicas.clone(),
            events,
        )
        .map_err(Error::NetworkData)?;
        Ok(wallet)
    }

    fn find_past_key(&self, keyset: &PublicKeySet) -> Result<PublicKey, NdError> {
        let section_keys = self.info.section_proof_chain.clone();
        let key = section_keys
            .keys()
            .find(|&key_in_chain| key_in_chain == &keyset.public_key());
        if let Some(key_in_chain) = key {
            Ok(PublicKey::Bls(*key_in_chain))
        } else {
            Err(NdError::NetworkOther("PublicKey provided by the transfer was never a part of the Section retrospectively".to_string()))
        }
    }

    // ------------------------------------------------------------------
    //  ------------------------- Genesis ------------------------------
    // ------------------------------------------------------------------

    async fn create_genesis(&self) -> Result<CreditAgreementProof> {
        // This means we are the first node in the network.
        let balance = u32::MAX as u64 * 1_000_000_000;
        let signed_credit = get_genesis(
            balance,
            PublicKey::Bls(self.info.peer_replicas.public_key()),
        )?;
        let replica_credit_sig = self
            .info
            .signing
            .lock()
            .await
            .sign_validated_credit(&signed_credit)?
            .unwrap();
        let mut credit_sig_shares = BTreeMap::new();
        let _ = credit_sig_shares.insert(0, replica_credit_sig.share);

        let debiting_replicas_sig = sn_data_types::Signature::Bls(
            self.info
                .peer_replicas
                .combine_signatures(&credit_sig_shares)
                .map_err(|e| Error::Logic(e.to_string()))?,
        );

        Ok(CreditAgreementProof {
            signed_credit,
            debiting_replicas_sig,
            debiting_replicas_keys: self.info.peer_replicas.clone(),
        })
    }

    /// This is the one and only infusion of money to the system. Ever.
    /// It is carried out by the first node in the network.
    async fn store_genesis<F: FnOnce() -> Result<PublicKey, NdError>>(
        &self,
        credit_proof: &CreditAgreementProof,
        past_key: F,
    ) -> Result<()> {
        let id = credit_proof.recipient();
        // Acquire lock on self.
        let self_lock = self.self_lock.lock().await;
        // We expect nothing to exist before this transfer.
        if self.load_key_lock(id).await.is_ok() {
            return Err(Error::NetworkData(NdError::BalanceExists));
        }
        // No key lock (hence no store), so we create one
        let store = TransferStore::new(id.into(), &self.root_dir, Init::New)?;
        let locked_store = Arc::new(Mutex::new(store));
        let _ = self.locks.insert(id, locked_store.clone());
        // Acquire lock of the wallet.
        let mut store = locked_store.lock().await;
        // last usage of self lock (we want to let go of the lock on self here)
        let _ = self_lock.overflowing_add(0); // resolve: is a usage at end of block necessary to actually engage the lock?

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, id).await?;
        let _ = wallet.genesis(credit_proof, past_key)?;
        // sign + update state
        if let Some(crediting_replica_sig) = self
            .info
            .signing
            .lock()
            .await
            .sign_credit_proof(credit_proof)?
        {
            // Q: are we locked on `info.signing` here? (we don't want to be)
            store.try_insert(ReplicaEvent::TransferPropagated(TransferPropagated {
                credit_proof: credit_proof.clone(),
                crediting_replica_sig,
                crediting_replica_keys: PublicKey::Bls(self.info.peer_replicas.public_key()),
            }))?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    //  --------------------  Simulated Payouts ------------------------
    // ------------------------------------------------------------------

    #[cfg(feature = "simulated-payouts")]
    pub async fn credit_without_proof(&self, transfer: Transfer) -> Result<NodeMessagingDuty> {
        debug!("Performing credit without proof");

        let debit = transfer.debit();

        debug!("provided debit {:?}", debit);
        let credit = transfer.credit()?;

        debug!("provided credit {:?}", credit);

        // Acquire lock of the wallet.
        let id = transfer.to;

        let store = self.get_load_or_create_store(id).await?;
        let mut store = store.lock().await;

        let mut wallet = self.load_wallet(&store, id).await?;

        debug!("wallet loaded");
        wallet.credit_without_proof(credit.clone())?;

        // let debit_store = self.get_load_or_create_store(debit.id().actor).await?;
        // let mut debit_store = debit_store.lock().await;
        // // Access to the specific wallet is now serialised!
        // let mut debit_wallet = self.load_wallet(&debit_store, debit.id().actor).await?;
        // debit_wallet.debit_without_proof(debit.clone())?;

        let dummy_msg = "DUMMY MSG";
        let mut rng = thread_rng();
        let sec_key_set = SecretKeySet::random(7, &mut rng);
        let replica_keys = sec_key_set.public_keys();
        let sec_key = SecretKey::random();
        let pub_key = sec_key.public_key();
        let dummy_shares = SecretKeyShare::default();

        let dummy_sig = dummy_shares.sign(dummy_msg);
        let sig = sec_key.sign(dummy_msg);
        let transfer_proof = TransferAgreementProof {
            signed_credit: SignedCredit {
                credit,
                actor_signature: Signature::from(sig.clone()),
            },
            signed_debit: SignedDebit {
                debit,
                actor_signature: Signature::from(sig.clone()),
            },
            debit_sig: Signature::from(sig.clone()),
            credit_sig: Signature::from(sig),
            debiting_replicas_keys: replica_keys,
        };

        store.try_insert(ReplicaEvent::TransferPropagated(TransferPropagated {
            credit_proof: transfer_proof.credit_proof(),
            crediting_replica_keys: PublicKey::from(pub_key),
            crediting_replica_sig: SignatureShare {
                index: 0,
                share: dummy_sig,
            },
        }))?;

        Ok(NodeMessagingDuty::NoOp)
    }

    #[cfg(feature = "simulated-payouts")]
    pub async fn debit_without_proof(&self, transfer: Transfer) -> Result<()> {
        // Acquire lock of the wallet.
        let debit = transfer.debit();
        let id = debit.sender();
        let key_lock = self.load_key_lock(id).await?;
        let store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let mut wallet = self.load_wallet(&store, id).await?;
        wallet.debit_without_proof(debit)?;
        Ok(())
    }

    #[cfg(feature = "simulated-payouts")]
    async fn get_load_or_create_store(&self, id: PublicKey) -> Result<Arc<Mutex<TransferStore>>> {
        let self_lock = self.self_lock.lock().await;
        // get or create the store for PK.
        let key_lock = match self.load_key_lock(id).await {
            Ok(lock) => lock,
            Err(_) => {
                let store = match TransferStore::new(id.into(), &self.root_dir, Init::Load) {
                    Ok(store) => store,
                    // no key lock, so we create one for this simulated payout...
                    Err(_e) => TransferStore::new(id.into(), &self.root_dir, Init::New)?,
                };
                debug!("store retrieved..");
                let locked_store = Arc::new(Mutex::new(store));
                let _ = self.locks.insert(id, locked_store.clone());
                locked_store
            }
        };
        let _ = self_lock.overflowing_add(0); // resolve: is a usage at end of block necessary to actually engage the lock?

        Ok(key_lock)
    }

    /// For now, with test money there is no from wallet.., money is created from thin air.
    #[allow(unused)] // TODO: Can this be removed?
    #[cfg(feature = "simulated-payouts")]
    pub async fn test_validate_transfer(&self, signed_transfer: SignedTransfer) -> Result<()> {
        let id = signed_transfer.sender();
        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, id).await?;
        let _ = wallet.test_validate_transfer(&signed_transfer.debit, &signed_transfer.credit)?;
        // sign + update state
        if let Some((replica_debit_sig, replica_credit_sig)) = self
            .info
            .signing
            .lock()
            .await
            .sign_transfer(&signed_transfer)?
        {
            store.try_insert(ReplicaEvent::TransferValidated(TransferValidated {
                signed_credit: signed_transfer.credit,
                signed_debit: signed_transfer.debit,
                replica_debit_sig,
                replica_credit_sig,
                replicas: self.info.peer_replicas.clone(),
            }))?;
        }
        Ok(())
    }
}
