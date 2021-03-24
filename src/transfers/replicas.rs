// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{replica_signing::ReplicaSigning, store::TransferStore};
use crate::{Error, Result};
use bls::PublicKeySet;
use dashmap::DashMap;
use futures::lock::Mutex;
use log::info;
use sn_data_types::{
    ActorHistory, CreditAgreementProof, OwnerType, PublicKey, ReplicaEvent, SignedTransfer, Token,
    TransferAgreementProof, TransferPropagated, TransferRegistered, TransferValidated,
};
use sn_transfers::WalletReplica;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use xor_name::Prefix;

#[cfg(feature = "simulated-payouts")]
use {
    crate::node_ops::NodeDuty,
    bls::{SecretKey, SecretKeySet},
    log::debug,
    rand::thread_rng,
    sn_data_types::{Signature, SignedCredit, SignedDebit, Transfer},
};

type WalletLocks = DashMap<PublicKey, Arc<Mutex<TransferStore<ReplicaEvent>>>>;
///
#[derive(Clone, Debug)]
pub struct ReplicaInfo<T>
where
    T: ReplicaSigning,
{
    pub id: bls::PublicKeyShare,
    pub key_index: usize,
    pub peer_replicas: PublicKeySet,
    pub section_chain: sn_routing::SectionChain,
    pub signing: T,
}

#[derive(Clone)]
pub struct Replicas<T>
where
    T: ReplicaSigning,
{
    root_dir: PathBuf,
    info: ReplicaInfo<T>,
    locks: WalletLocks,
    self_lock: Arc<Mutex<usize>>,
}

impl<T: ReplicaSigning> Replicas<T> {
    pub(crate) async fn new(
        root_dir: PathBuf,
        info: ReplicaInfo<T>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    ) -> Result<Self> {
        let instance = Self {
            root_dir,
            info,
            locks: DashMap::new(),
            self_lock: Arc::new(Mutex::new(0)),
        };
        instance.setup(user_wallets).await?;
        Ok(instance)
    }

    pub async fn merge(&mut self, user_wallets: BTreeMap<PublicKey, ActorHistory>) -> Result<()> {
        self.setup(user_wallets).await // TODO: fix this!!!! (this duplciates entries in db)
    }

    async fn setup(&self, user_wallets: BTreeMap<PublicKey, ActorHistory>) -> Result<()> {
        use ReplicaEvent::*;
        if user_wallets.is_empty() {
            return Ok(());
        }
        // TODO: parallel
        for (node, wallet) in user_wallets {
            let valid_owners = wallet.credits.iter().all(|c| node == c.recipient())
                && wallet.debits.iter().all(|d| node == d.sender());
            if !valid_owners {
                return Err(Error::InvalidActorHistory);
            }
            for credit_proof in wallet.credits {
                let id = credit_proof.recipient();
                let e = TransferPropagated(sn_data_types::TransferPropagated { credit_proof });
                // Acquire lock of the wallet.
                let key_lock = self.get_load_or_create_store(id).await?;
                let mut store = key_lock.lock().await;
                // Access to the specific wallet is now serialised!
                store.try_insert(e.to_owned())?;
            }
            for transfer_proof in wallet.debits {
                let id = transfer_proof.sender();
                let e = TransferRegistered(sn_data_types::TransferRegistered { transfer_proof });
                // Acquire lock of the wallet.
                let key_lock = self.get_load_or_create_store(id).await?;
                let mut store = key_lock.lock().await;
                // Access to the specific wallet is now serialised!
                store.try_insert(e.to_owned())?;
            }
        }
        Ok(())
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Queries ----------------------------------
    /// -----------------------------------------------------------------

    /// The total amount in wallets managed
    /// by the replicas in this section.
    pub async fn managed_amount(&self) -> Result<Token> {
        let mut amount = 0;
        for entry in &self.locks {
            let key = *entry.key();
            amount += self.balance(key).await?.as_nano();
        }
        Ok(Token::from_nano(amount))
    }

    ///
    pub fn user_wallets(&self) -> BTreeMap<PublicKey, ActorHistory> {
        let wallets = self
            .locks
            .iter()
            .map(|r| *r.key())
            .filter_map(|id| self.history(id).ok().map(|history| Some((id, history))))
            .flatten()
            .collect();
        wallets
    }

    /// All keys' histories
    pub async fn all_events(&self) -> Result<Vec<ReplicaEvent>> {
        let events = self
            .locks
            .iter()
            .map(|r| *r.key())
            .filter_map(|id| TransferStore::new(id.into(), &self.root_dir).ok())
            .map(|store| store.get_all())
            .flatten()
            .collect();
        Ok(events)
    }

    /// History of actor
    pub fn history(&self, id: PublicKey) -> Result<ActorHistory> {
        let store = TransferStore::new(id.into(), &self.root_dir);

        if let Err(error) = store {
            // hmm.. can we handle this in a better way?
            let err_string = error.to_string();
            let no_such_file_or_dir = err_string.contains("No such file or directory");
            let system_cannot_find_file =
                err_string.contains("The system cannot find the file specified");
            if no_such_file_or_dir || system_cannot_find_file {
                // we have no history yet, so lets report that.
                return Ok(ActorHistory::empty());
            }

            return Err(error);
        };

        let store = store?;
        let events = store.get_all();

        if events.is_empty() {
            return Ok(ActorHistory::empty());
        }

        let history = ActorHistory {
            credits: self.get_credits(&events),
            debits: self.get_debits(events),
        };

        Ok(history)
    }

    fn get_credits(&self, events: &[ReplicaEvent]) -> Vec<CreditAgreementProof> {
        use itertools::Itertools;
        events
            .iter()
            .filter_map(|e| match e {
                ReplicaEvent::TransferPropagated(e) => Some(e.credit_proof.clone()),
                _ => None,
            })
            .unique_by(|e| *e.id())
            .collect()
    }

    fn get_debits(&self, events: Vec<ReplicaEvent>) -> Vec<TransferAgreementProof> {
        use itertools::Itertools;
        let mut debits: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ReplicaEvent::TransferRegistered(e) => Some(e),
                _ => None,
            })
            .unique_by(|e| e.id())
            .map(|e| e.transfer_proof.clone())
            .collect();

        debits.sort_by_key(|t| t.id().counter);

        debits
    }

    ///
    pub async fn balance(&self, id: PublicKey) -> Result<Token> {
        debug!("Replica: Getting balance of: {:?}", id);
        let store = match TransferStore::new(id.into(), &self.root_dir) {
            Ok(store) => store,
            // store load failed, so we return 0 balance
            Err(_) => return Ok(Token::from_nano(0)),
        };

        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        Ok(wallet.balance())
    }

    /// Get the replica's PK set
    pub fn replicas_pk_set(&self) -> PublicKeySet {
        self.info.peer_replicas.clone()
    }

    /// -----------------------------------------------------------------
    /// ---------------------- Cmds -------------------------------------
    /// -----------------------------------------------------------------

    ///
    pub fn update_replica_info(&mut self, info: ReplicaInfo<T>) {
        self.info = info;
    }

    #[allow(unused)]
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
        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;

        debug!("Wallet loaded");
        let _ = wallet.validate(&signed_transfer.debit, &signed_transfer.credit)?;

        debug!("wallet valid");
        // signing will be serialised
        let (replica_debit_sig, replica_credit_sig) =
            self.info.signing.sign_transfer(&signed_transfer).await?;
        // release lock and update state
        let event = TransferValidated {
            signed_credit: signed_transfer.credit,
            signed_debit: signed_transfer.debit,
            replica_debit_sig,
            replica_credit_sig,
            replicas: self.info.peer_replicas.clone(),
        };

        // first store to disk
        store.try_insert(ReplicaEvent::TransferValidated(event.clone()))?;
        let mut wallet = wallet;
        // then apply to inmem state
        wallet.apply(ReplicaEvent::TransferValidated(event.clone()))?;

        Ok(event)
    }

    /// Step 2. Validation of agreement, and order at debit source.
    pub async fn register(
        &self,
        transfer_proof: &TransferAgreementProof,
    ) -> Result<TransferRegistered> {
        let id = transfer_proof.sender();

        // should only have been signed by our section
        let known_key = self.exists_in_chain(&transfer_proof.replica_keys().public_key());
        if !known_key {
            return Err(Error::Transfer(sn_transfers::Error::SectionKeyNeverExisted));
        }

        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        match wallet.register(transfer_proof)? {
            None => {
                info!("transfer already registered!");
                Err(Error::TransferAlreadyRegistered)
            }
            Some(event) => {
                // first store to disk
                store.try_insert(ReplicaEvent::TransferRegistered(event.clone()))?;
                let mut wallet = wallet;
                // then apply to inmem state
                wallet.apply(ReplicaEvent::TransferRegistered(event.clone()))?;
                Ok(event)
            }
        }
    }

    /// Step 3. Validation of DebitAgreementProof, and credit idempotency at credit destination.
    /// (Since this leads to a credit, there is no requirement on order.)
    pub async fn receive_propagated(
        &self,
        _debiting_replicas_name: xor_name::XorName,
        credit_proof: &CreditAgreementProof,
    ) -> Result<TransferPropagated> {
        // Acquire lock of the wallet.
        let id = credit_proof.recipient();
        let _debiting_replicas_key = credit_proof.replica_keys().public_key();

        // TODO: check the debiting_replicas_key, needs reverse AE implemented

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
                        let store = TransferStore::new(id.into(), &self.root_dir)?;
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
        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        let propagation_result = wallet.receive_propagated(credit_proof);
        if propagation_result.is_ok() {
            // update state
            let event = TransferPropagated {
                credit_proof: credit_proof.clone(),
            };
            // only add it locally if we don't know about it... (this prevents SimulatedPayouts being reapplied due to varied sigs.)
            if propagation_result?.is_some() {
                // first store to disk
                store.try_insert(ReplicaEvent::TransferPropagated(event.clone()))?;
                let mut wallet = wallet;
                // then apply to inmem state
                wallet.apply(ReplicaEvent::TransferPropagated(event.clone()))?;
            }
            return Ok(event);
        }
        Err(Error::InvalidPropagatedTransfer(credit_proof.clone()))
    }

    async fn load_key_lock(
        &self,
        id: PublicKey,
    ) -> Result<Arc<Mutex<TransferStore<ReplicaEvent>>>> {
        match self.locks.get(&id) {
            Some(val) => Ok(val.clone()),
            None => Err(Error::Logic("Key does not exist among locks.".to_string())),
        }
    }

    async fn load_wallet(
        &self,
        store: &TransferStore<ReplicaEvent>,
        id: OwnerType,
    ) -> Result<WalletReplica> {
        let events = store.get_all();
        let wallet = WalletReplica::from_history(
            id,
            self.info.id,
            self.info.key_index,
            self.info.peer_replicas.clone(),
            events,
        )?;
        Ok(wallet)
    }

    fn exists_in_chain(&self, key: &bls::PublicKey) -> bool {
        self.info
            .section_chain
            .keys()
            .any(|key_in_chain| key_in_chain == key)
    }

    async fn get_load_or_create_store(
        &self,
        id: PublicKey,
    ) -> Result<Arc<Mutex<TransferStore<ReplicaEvent>>>> {
        let self_lock = self.self_lock.lock().await;
        // get or create the store for PK.
        let key_lock = match self.load_key_lock(id).await {
            Ok(lock) => lock,
            Err(_) => {
                let store = match TransferStore::new(id.into(), &self.root_dir) {
                    Ok(store) => store,
                    // no key lock, so we create one for this payout...
                    Err(_e) => TransferStore::new(id.into(), &self.root_dir)?,
                };
                let locked_store = Arc::new(Mutex::new(store));
                let _ = self.locks.insert(id, locked_store.clone());
                locked_store
            }
        };
        let _ = self_lock.overflowing_add(0); // resolve: is a usage at end of block necessary to actually engage the lock?

        Ok(key_lock)
    }

    // ------------------------------------------------------------------
    //  --------------------  Simulated Payouts ------------------------
    // ------------------------------------------------------------------

    #[cfg(feature = "simulated-payouts")]
    pub async fn credit_without_proof(&self, transfer: Transfer) -> Result<NodeDuty> {
        debug!("Performing credit without proof");

        let debit = transfer.debit();

        debug!("provided debit {:?}", debit);
        let credit = transfer.credit()?;

        debug!("provided credit {:?}", credit);

        // Acquire lock of the wallet.
        let id = transfer.to;

        let store = self.get_load_or_create_store(id).await?;
        let mut store = store.lock().await;

        let mut wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;

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
        }))?;

        Ok(NodeDuty::NoOp)
    }
}
