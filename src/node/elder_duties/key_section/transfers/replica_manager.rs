// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_nd::{
    AccountId, DebitAgreementProof, Error, KnownGroupAdded, Money, PublicKey as NdPublicKey,
    ReplicaEvent, Result, SignedTransfer, TransferPropagated, TransferRegistered,
    TransferValidated,
};
use safe_transfers::TransferReplica as Replica;
use std::collections::HashMap;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

use routing::SectionProofChain;
#[cfg(feature = "simulated-payouts")]
use {
    crate::node::node_ops::MessagingDuty,
    rand::thread_rng,
    safe_nd::{
        Address, MessageId, PublicId, PublicKey, Signature, SignatureShare, Transfer, XorName,
    },
    threshold_crypto::{SecretKey, SecretKeySet},
};

pub struct ReplicaManager {
    store: EventStore,
    replica: Replica,
    section_proof_chain: SectionProofChain,
}

#[allow(unused)]
impl ReplicaManager {
    pub(crate) fn new(
        secret_key: &SecretKeyShare,
        key_index: usize,
        peer_replicas: &PublicKeySet,
        events: Vec<ReplicaEvent>,
        section_proof_chain: SectionProofChain,
    ) -> Result<Self> {
        let mut store = EventStore {
            streams: Default::default(),
            group_changes: Default::default(),
        };
        /// OKs on empty vec as well, only errors from underlying storage.
        match store.init(events.clone()) {
            Ok(()) => {
                let mut replica = Replica::from_history(
                    secret_key.clone(),
                    key_index,
                    peer_replicas.clone(),
                    events,
                )?;
                Ok(Self {
                    store,
                    replica,
                    section_proof_chain,
                })
            }
            Err(e) => Err(Error::InvalidOperation), // todo: storage error
        }
    }

    pub(crate) fn history(&self, id: &AccountId) -> Option<&Vec<ReplicaEvent>> {
        self.store.history(id)
    }

    pub(crate) fn balance(&self, id: &AccountId) -> Option<Money> {
        self.replica.balance(id)
    }

    pub(crate) fn churn(
        &mut self,
        secret_key: SecretKeyShare,
        index: usize,
        peer_replicas: PublicKeySet,
        section_proof_chain: SectionProofChain,
    ) -> Result<()> {
        match self.store.try_load() {
            Ok(events) => {
                self.replica = Replica::from_history(secret_key, index, peer_replicas, events)?;
                self.section_proof_chain = section_proof_chain;
                //info!("Successfully updated Replica details on churn");
                Ok(())
            }
            Err(e) => Err(Error::InvalidOperation), // todo: storage error
        }
    }

    pub(crate) fn validate(
        &mut self,
        transfer: SignedTransfer,
    ) -> Result<Option<TransferValidated>> {
        let result = self.replica.validate(transfer);
        if let Ok(Some(event)) = result {
            match self.persist(ReplicaEvent::TransferValidated(event.clone())) {
                Ok(()) => Ok(Some(event)),
                Err(err) => Err(err),
            }
        } else {
            result
        }
    }

    pub(crate) fn register(
        &mut self,
        proof: &DebitAgreementProof,
    ) -> Result<Option<TransferRegistered>> {
        let serialized = bincode::serialize(&proof.signed_transfer)
            .map_err(|e| Error::NetworkOther(e.to_string()))?;
        let sig = proof
            .debiting_replicas_sig
            .clone()
            .into_bls()
            .ok_or_else(|| {
                Error::NetworkOther("Error retrieving threshold::Signature from DAP ".to_string())
            })?;
        let section_keys = self.section_proof_chain.clone();

        let result = self.replica.clone().register(proof, move || {
            let key = section_keys
                .keys()
                .find(|&key_in_chain| key_in_chain == &proof.replica_key.public_key());
            if let Some(key_in_chain) = key {
                key_in_chain.verify(&sig, serialized)
            } else {
                // PublicKey provided by the transfer was never a part of the Section retrospectively.
                false
            }
        });

        if let Ok(Some(event)) = result {
            match self.persist(ReplicaEvent::TransferRegistered(event.clone())) {
                Ok(()) => Ok(Some(event)),
                Err(err) => Err(err),
            }
        } else {
            result
        }
    }

    pub(crate) fn receive_propagated(
        &mut self,
        proof: &DebitAgreementProof,
    ) -> Result<Option<TransferPropagated>> {
        let serialized = bincode::serialize(&proof.signed_transfer)
            .map_err(|e| Error::NetworkOther(e.to_string()))?;
        let section_keys = self.section_proof_chain.clone();
        let sig = proof
            .debiting_replicas_sig
            .clone()
            .into_bls()
            .ok_or_else(|| {
                Error::NetworkOther("Error retrieving threshold::Signature from DAP ".to_string())
            })?;

        let result = self.replica.receive_propagated(proof, move || {
            let key = section_keys
                .keys()
                .find(|&key_in_chain| key_in_chain == &proof.replica_key.public_key());
            if let Some(key_in_chain) = key {
                if key_in_chain.verify(&sig, serialized) {
                    Some(NdPublicKey::from(*key_in_chain))
                } else {
                    None
                }
            } else {
                // PublicKey provided by the transfer was never a part of the Section retrospectively.
                None
            }
        });

        if let Ok(Some(event)) = result {
            match self.persist(ReplicaEvent::TransferPropagated(event.clone())) {
                Ok(()) => Ok(Some(event)),
                Err(err) => Err(err),
            }
        } else {
            result
        }
    }

    fn persist(&mut self, event: ReplicaEvent) -> Result<()> {
        self.store.try_append(event.clone())?;
        self.replica.apply(event);
        Ok(())
    }

    /// Get the replica's PK set
    pub fn replicas_pk_set(&self) -> Option<PublicKeySet> {
        self.replica.replicas_pk_set()
    }
}

#[cfg(feature = "simulated-payouts")]
impl ReplicaManager {
    pub fn credit_without_proof(&mut self, transfer: Transfer) -> Option<MessagingDuty> {
        self.replica.credit_without_proof(transfer.clone());
        let dummy_msg = "DUMMY MSG";
        let mut rng = thread_rng();
        let sec_key_set = SecretKeySet::random(7, &mut rng);
        let replica_key = sec_key_set.public_keys();
        let sec_key = SecretKey::random();
        let pub_key = sec_key.public_key();
        let dummy_shares = SecretKeyShare::default();
        let dummy_sig = dummy_shares.sign(dummy_msg);
        let sig = sec_key.sign(dummy_msg);
        let debit_proof = DebitAgreementProof {
            signed_transfer: SignedTransfer {
                transfer,
                actor_signature: Signature::from(sig.clone()),
            },
            debiting_replicas_sig: Signature::from(sig),
            replica_key,
        };
        self.store
            .try_append(ReplicaEvent::TransferPropagated(TransferPropagated {
                debit_proof,
                debiting_replicas: PublicKey::from(pub_key),
                crediting_replica_sig: SignatureShare {
                    index: 0,
                    share: dummy_sig,
                },
            }))
            .ok()?;
        None
    }

    pub fn debit_without_proof(&mut self, transfer: Transfer) {
        self.replica.debit_without_proof(transfer)
    }
}

/// Disk storage
struct EventStore {
    streams: HashMap<AccountId, Vec<ReplicaEvent>>,
    group_changes: Vec<KnownGroupAdded>,
}

/// In memory store lacks transactionality
impl EventStore {
    fn history(&self, id: &AccountId) -> Option<&Vec<ReplicaEvent>> {
        self.streams.get(id)
    }

    fn try_load(&self) -> Result<Vec<ReplicaEvent>> {
        // Only the order within the streams is important, not between streams.
        Ok(self
            .streams
            .values()
            .cloned()
            .flatten()
            .collect::<Vec<ReplicaEvent>>())
    }

    fn init(&mut self, events: Vec<ReplicaEvent>) -> Result<()> {
        for event in events {
            self.try_append(event)?;
        }
        Ok(())
    }

    fn try_append(&mut self, event: ReplicaEvent) -> Result<()> {
        match event.clone() {
            ReplicaEvent::KnownGroupAdded(e) => {
                self.group_changes.push(e);
            }
            ReplicaEvent::TransferPropagated(e) => {
                let id = e.to();
                match self.streams.get_mut(&id) {
                    Some(stream) => stream.push(event),
                    None => {
                        // Creates if not exists. A stream always starts with a credit.
                        let _ = self.streams.insert(id, vec![event]);
                    }
                }
            }
            ReplicaEvent::TransferValidated(e) => {
                let id = e.from();
                match self.streams.get_mut(&id) {
                    Some(stream) => stream.push(event),
                    None => return Err(Error::InvalidOperation), // A stream cannot start with a debit.
                }
            }
            ReplicaEvent::TransferRegistered(e) => {
                let id = e.from();
                match self.streams.get_mut(&id) {
                    Some(stream) => stream.push(event),
                    None => return Err(Error::InvalidOperation), // A stream cannot start with a debit.
                }
            }
        };
        Ok(())
    }
}
