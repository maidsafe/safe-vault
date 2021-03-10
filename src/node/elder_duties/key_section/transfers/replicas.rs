// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{replica_signing::ReplicaSigning, store::TransferStore, ReplicaInfo};
use crate::{Error, Result};
use bls::PublicKeySet;
use dashmap::DashMap;
use futures::lock::Mutex;
use log::info;
use sn_data_types::{
    ActorHistory, CreditAgreementProof, OwnerType, PublicKey, ReplicaEvent, SignedTransfer,
    SignedTransferShare, Token, TransferAgreementProof, TransferPropagated, TransferRegistered,
    TransferValidated,
};
use sn_transfers::{Error as TransfersError, WalletReplica};
use std::path::PathBuf;
use std::sync::Arc;
use xor_name::Prefix;

#[cfg(feature = "simulated-payouts")]
use {
    crate::node::node_ops::NodeMessagingDuty,
    bls::{SecretKey, SecretKeySet},
    log::debug,
    rand::thread_rng,
    sn_data_types::{Signature, SignedCredit, SignedDebit, Transfer},
};

type WalletLocks = DashMap<PublicKey, Arc<Mutex<TransferStore<ReplicaEvent>>>>;

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
    pub(crate) fn new(root_dir: PathBuf, info: ReplicaInfo<T>) -> Self {
        Self {
            root_dir,
            info,
            locks: Default::default(),
            self_lock: Arc::new(Mutex::new(0)),
        }
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
            .filter_map(|id| TransferStore::new(id.into(), &self.root_dir).ok())
            .map(|store| store.get_all())
            .flatten()
            .collect();
        Ok(events)
    }

    /// History of actor
    pub async fn history(&self, id: PublicKey) -> Result<ActorHistory> {
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
                TransferValidationProposed(e) => e.sender(),
                TransferValidated(e) => e.sender(),
                TransferRegistered(e) => e.sender(),
                TransferPropagated(e) => e.recipient(),
            };

            // Acquire lock of the wallet.
            let key_lock = self.get_load_or_create_store(id).await?;
            let mut store = key_lock.lock().await;
            // Access to the specific wallet is now serialised!
            store.try_insert(e.to_owned())?;
        }
        Ok(())
    }

    ///
    pub fn update_replica_info(&mut self, info: ReplicaInfo<T>) {
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
        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        match wallet.register(transfer_proof, || {
            self.find_past_key(&transfer_proof.replica_keys())
        })? {
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
        let propagation_result = wallet.receive_propagated(credit_proof, || {
            self.find_past_key(&credit_proof.replica_keys())
        });

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

    fn find_past_key(&self, keyset: &PublicKeySet) -> Result<PublicKey, TransfersError> {
        let section_keys = self.info.section_proof_chain.clone();
        let key = section_keys
            .keys()
            .find(|&key_in_chain| key_in_chain == &keyset.public_key());
        if let Some(key_in_chain) = key {
            Ok(PublicKey::Bls(*key_in_chain))
        } else {
            Err(TransfersError::SectionKeyNeverExisted)
        }
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
                debug!("store retrieved..");
                let locked_store = Arc::new(Mutex::new(store));
                let _ = self.locks.insert(id, locked_store.clone());
                locked_store
            }
        };
        let _ = self_lock.overflowing_add(0); // resolve: is a usage at end of block necessary to actually engage the lock?

        Ok(key_lock)
    }

    // ------------------------------------------------------------------
    //  ------------------------- Genesis ------------------------------
    // ------------------------------------------------------------------

    async fn create_genesis(&self) -> Result<CreditAgreementProof> {
        // This means we are the first node in the network.
        let balance = u32::MAX as u64 * 1_000_000_000;
        let signed_credit = self.info.signing.try_genesis(balance).await?;
        Ok(signed_credit)
    }

    /// This is the one and only infusion of tokens to the system. Ever.
    /// It is carried out by the first node in the network.
    async fn store_genesis<F: FnOnce() -> Result<PublicKey, TransfersError>>(
        &self,
        credit_proof: &CreditAgreementProof,
        past_key: F,
    ) -> Result<()> {
        let id = credit_proof.recipient();
        // Acquire lock on self.
        let self_lock = self.self_lock.lock().await;
        // We expect nothing to exist before this transfer.
        if self.load_key_lock(id).await.is_ok() {
            return Err(Error::BalanceExists);
        }
        // No key lock (hence no store), so we create one
        let store = TransferStore::new(id.into(), &self.root_dir)?;
        let locked_store = Arc::new(Mutex::new(store));
        let _ = self.locks.insert(id, locked_store.clone());
        // Acquire lock of the wallet.
        let mut store = locked_store.lock().await;
        // last usage of self lock (we want to let go of the lock on self here)
        let _ = self_lock.overflowing_add(0); // resolve: is a usage at end of block necessary to actually engage the lock?

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        let _ = wallet.genesis(credit_proof, past_key)?;

        // update state
        // Q: are we locked on `info.signing` here? (we don't want to be)
        store.try_insert(ReplicaEvent::TransferPropagated(TransferPropagated {
            credit_proof: credit_proof.clone(),
        }))
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
        let mut wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        wallet.debit_without_proof(debit)?;
        Ok(())
    }

    /// For now, with test tokens there is no from wallet.., tokens is created from thin air.
    #[allow(unused)] // TODO: Can this be removed?
    #[cfg(feature = "simulated-payouts")]
    pub async fn test_validate_transfer(&self, signed_transfer: SignedTransfer) -> Result<()> {
        let id = signed_transfer.sender();
        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let wallet = self.load_wallet(&store, OwnerType::Single(id)).await?;
        let _ = wallet.test_validate_transfer(&signed_transfer.debit, &signed_transfer.credit)?;
        // sign + update state
        let (replica_debit_sig, replica_credit_sig) =
            self.info.signing.sign_transfer(&signed_transfer).await?;
        store.try_insert(ReplicaEvent::TransferValidated(TransferValidated {
            signed_credit: signed_transfer.credit,
            signed_debit: signed_transfer.debit,
            replica_debit_sig,
            replica_credit_sig,
            replicas: self.info.peer_replicas.clone(),
        }))
    }
}

impl<T: ReplicaSigning> Replicas<T> {
    /// Used with multisig replicas.
    pub async fn propose_validation(
        &self,
        signed_transfer: &SignedTransferShare,
    ) -> Result<Option<TransferValidated>> {
        debug!("MultisigReplica validating transfer: {:?}", signed_transfer);
        let id = signed_transfer.sender();
        let actors = OwnerType::Multi(signed_transfer.actors().clone());
        // Acquire lock of the wallet.
        let key_lock = self.load_key_lock(id).await?;
        let mut store = key_lock.lock().await;

        // Access to the specific wallet is now serialised!
        let mut wallet = self.load_wallet(&store, actors.clone()).await?;
        debug!("MultisigReplica wallet loaded: {:?}", id);
        if let Some(proposal) = wallet.propose_validation(signed_transfer)? {
            debug!("TransferValidationProposed!");
            // apply the event
            let event = ReplicaEvent::TransferValidationProposed(proposal.clone());
            wallet.apply(event.clone())?;
            // see if any agreement accumulated
            if let Some(agreed_transfer) = proposal.agreed_transfer {
                let (replica_debit_sig, replica_credit_sig) =
                    self.info.signing.sign_transfer(&agreed_transfer).await?;
                let event = TransferValidated {
                    signed_credit: agreed_transfer.credit,
                    signed_debit: agreed_transfer.debit,
                    replica_debit_sig,
                    replica_credit_sig,
                    replicas: self.info.peer_replicas.clone(),
                };
                store.try_insert(ReplicaEvent::TransferValidated(event.clone()))?;
                // return agreed_transfer to requesting _section_
                return Ok(Some(event));
            } else {
                // save the propagation event for later
                store.try_insert(event)?;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{test_utils::*, ReplicaInfo},
        Replicas,
    };
    use crate::{Error, Result};
    use bls::{PublicKeySet, SecretKeySet};
    use futures::executor::block_on as run;
    use sn_data_types::{Keypair, OwnerType, PublicKey, SignedTransferShare, Token};
    use sn_routing::SectionChain;
    use sn_transfers::{ActorEvent, TransferActor as Actor, Wallet};
    use tempdir::TempDir;

    #[test]
    fn section_actor_transition() -> Result<()> {
        let (mut section, peer_replicas) = get_section(1);

        let (genesis_replicas, mut genesis_actor) = section.remove(0);
        run(genesis_replicas.initiate(&[]))?;

        let section_key = PublicKey::Bls(genesis_replicas.replicas_pk_set().public_key());

        // make sure all keys are the same
        assert_eq!(peer_replicas, genesis_actor.owner().public_key_set()?);
        assert_eq!(section_key, PublicKey::Bls(peer_replicas.public_key()));

        // we are genesis, we should get the genesis event via this call
        let events = run(genesis_replicas.history(section_key))?;
        match genesis_actor.from_history(events)? {
            Some(event) => genesis_actor.apply(ActorEvent::TransfersSynched(event))?,
            None => {
                return Err(Error::Logic(
                    "We should be able to synch genesis event here.".to_string(),
                ))
            }
        }

        // Elders changed!
        let (section, peer_replicas) = get_section(2);
        let recipient = PublicKey::Bls(peer_replicas.public_key());

        // transfer the section funds to new section actor
        let init = match genesis_actor.transfer(
            genesis_actor.balance(),
            recipient,
            "Transition to next section actor".to_string(),
        )? {
            Some(init) => init,
            None => {
                return Err(Error::Logic(
                    "We should be able to transfer here.".to_string(),
                ))
            }
        };
        // the new elder will not partake in this operation (hence only one doing it here)
        genesis_actor.apply(ActorEvent::TransferInitiated(init.clone()))?;

        let signed_transfer = SignedTransferShare::new(
            init.signed_debit.as_share()?,
            init.signed_credit.as_share()?,
            genesis_actor.owner().public_key_set()?,
        )?;

        let validation = match run(genesis_replicas.propose_validation(&signed_transfer))? {
            Some(validation) => validation,
            None => {
                return Err(Error::Logic(
                    "We should be able to propose validation here.".to_string(),
                ))
            }
        };

        // accumulate validations
        let event = match genesis_actor.receive(validation)? {
            Some(event) => event,
            None => {
                return Err(Error::Logic(
                    "We should be able to receive validation here.".to_string(),
                ))
            }
        };
        match event.proof {
            Some(transfer_proof) => {
                let _registered = run(genesis_replicas.register(&transfer_proof))?;
                let _propagated =
                    run(genesis_replicas.receive_propagated(&transfer_proof.credit_proof()))?;
            }
            None => return Err(Error::Logic("We should have a proof here.".to_string())),
        }

        let genesis_history = run(genesis_replicas.history(section_key))?;
        match genesis_actor.from_history(genesis_history)? {
            Some(event) => genesis_actor.apply(ActorEvent::TransfersSynched(event))?,
            None => {
                return Err(Error::Logic(
                    "We should be able to synch genesis_actor here.".to_string(),
                ))
            }
        }
        assert_eq!(genesis_actor.balance(), Token::zero());
        assert_eq!(
            genesis_actor.balance(),
            run(genesis_replicas.balance(genesis_actor.id()))?
        );

        let replica_events = run(genesis_replicas.all_events())?;

        for (elder_replicas, mut next_section_actor_share) in section {
            run(elder_replicas.initiate(&replica_events))?;
            let history = run(elder_replicas.history(next_section_actor_share.id()))?;
            match next_section_actor_share.from_history(history.clone())? {
                Some(event) => {
                    next_section_actor_share.apply(ActorEvent::TransfersSynched(event))?
                }
                None => {
                    return Err(Error::Logic(
                        "We should be able to synch actor_instance here.".to_string(),
                    ))
                }
            }
            assert_eq!(
                next_section_actor_share.balance(),
                Token::from_nano(u32::MAX as u64 * 1_000_000_000)
            );
            assert_eq!(
                next_section_actor_share.balance(),
                run(elder_replicas.balance(next_section_actor_share.id()))?
            );
        }

        Ok(())
    }

    fn temp_dir() -> Result<TempDir> {
        TempDir::new("test").map_err(|e| Error::TempDirCreationFailed(e.to_string()))
    }

    type Section = Vec<(Replicas<TestReplicaSigning>, Actor<Validator, Keypair>)>;
    fn get_section(count: u8) -> (Section, PublicKeySet) {
        let mut rng = rand::thread_rng();
        let threshold = count as usize - 1;
        let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
        let peer_replicas = bls_secret_key.public_keys();

        let section = (0..count as usize)
            .map(|key_index| get_replica(key_index, bls_secret_key.clone()))
            .filter_map(|res| res.ok())
            .collect();

        (section, peer_replicas)
    }

    fn get_replica(
        key_index: usize,
        bls_secret_key: SecretKeySet,
    ) -> Result<(Replicas<TestReplicaSigning>, Actor<Validator, Keypair>)> {
        let peer_replicas = bls_secret_key.public_keys();
        let secret_key_share = bls_secret_key.secret_key_share(key_index);
        let id = secret_key_share.public_key_share();
        let signing = TestReplicaSigning::new(secret_key_share, key_index, peer_replicas.clone());
        let info = ReplicaInfo {
            id,
            key_index,
            peer_replicas: peer_replicas.clone(),
            section_proof_chain: SectionChain::new(peer_replicas.public_key()),
            signing,
            initiating: true,
        };
        let root_dir = temp_dir()?;
        let replicas = Replicas::new(root_dir.path().to_path_buf(), info);

        let keypair =
            Keypair::new_bls_share(0, bls_secret_key.secret_key_share(0), peer_replicas.clone());
        let owner = OwnerType::Multi(peer_replicas.clone());
        let wallet = Wallet::new(owner);
        let actor = Actor::from_snapshot(wallet, keypair, peer_replicas, Validator {});

        Ok((replicas, actor))
    }
}
