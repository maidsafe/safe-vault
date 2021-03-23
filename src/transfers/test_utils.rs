// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::replica_signing::ReplicaSigning;
use crate::{Error, Result};
use async_trait::async_trait;
use bls::{PublicKeySet, PublicKeyShare, SecretKeySet, SecretKeyShare};
use sn_data_types::{
    Credit, CreditAgreementProof, PublicKey, SignatureShare, SignedCredit, SignedDebit,
    SignedTransfer, Token,
};
use sn_transfers::ReplicaValidator;
use std::collections::BTreeMap;

/// Should be validating
/// other replica groups, i.e.
/// make sure they are run at Elders
/// of sections we know of.
/// TBD.
pub struct Validator {}

impl ReplicaValidator for Validator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}

/// An impl of ReplicaSigningTrait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReplicaSigning {
    /// The public key share of this Replica.
    id: PublicKeyShare,
    /// Secret key share.
    secret_key: SecretKeyShare,
    /// The index of this Replica key share, in the group set.
    key_index: usize,
    /// The PK set of our peer Replicas.
    peer_replicas: PublicKeySet,
}

#[allow(unused)]
impl TestReplicaSigning {
    /// A new instance
    pub fn new(secret_key: SecretKeyShare, key_index: usize, peer_replicas: PublicKeySet) -> Self {
        let id = secret_key.public_key_share();
        Self {
            secret_key,
            id,
            key_index,
            peer_replicas,
        }
    }
}

#[async_trait]
impl ReplicaSigning for TestReplicaSigning {
    /// Get the replica's PK set
    async fn replicas_pk_set(&self) -> Result<PublicKeySet> {
        Ok(self.peer_replicas.clone())
    }

    async fn try_genesis(&self, balance: u64) -> Result<CreditAgreementProof> {
        get_genesis(
            balance,
            PublicKey::Bls(self.peer_replicas.public_key()),
            self.peer_replicas.clone(),
            self.secret_key.clone(),
        )
    }

    async fn sign_transfer(
        &self,
        signed_transfer: &SignedTransfer,
    ) -> Result<(SignatureShare, SignatureShare)> {
        let replica_debit_sig = self.sign_validated_debit(&signed_transfer.debit).await?;
        let replica_credit_sig = self.sign_validated_credit(&signed_transfer.credit).await?;
        Ok((replica_debit_sig, replica_credit_sig))
    }

    async fn sign_validated_debit(&self, debit: &SignedDebit) -> Result<SignatureShare> {
        match bincode::serialize(debit) {
            Err(_) => Err(Error::Logic("Could not serialise debit".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    async fn sign_validated_credit(&self, credit: &SignedCredit) -> Result<SignatureShare> {
        match bincode::serialize(credit) {
            Err(_) => Err(Error::Logic("Could not serialise credit".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    async fn sign_credit_proof(&self, proof: &CreditAgreementProof) -> Result<SignatureShare> {
        match bincode::serialize(proof) {
            Err(_) => Err(Error::Logic("Could not serialise proof".into())),
            Ok(data) => Ok(SignatureShare {
                index: self.key_index,
                share: self.secret_key.sign(data),
            }),
        }
    }

    async fn known_replicas(
        &self,
        _wallet_name: &sn_routing::XorName,
        _section_key: bls::PublicKey,
    ) -> bool {
        true
    }
}

/// Produces a genesis balance for a new network.
#[allow(unused)]
pub fn get_random_genesis(balance: u64, id: PublicKey) -> Result<CreditAgreementProof> {
    let threshold = 0;
    // Nothing comes before genesis, it is a paradox
    // that it comes from somewhere. In other words, it is
    // signed over from a "ghost", the keys generated are "ghost" keys,
    // they come from nothing and can't be verified.
    // They are unimportant and will be thrown away,
    // thus the source of random is also unimportant.
    let mut rng = rand::thread_rng();
    let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
    get_genesis(
        balance,
        id,
        bls_secret_key.public_keys(),
        bls_secret_key.secret_key_share(threshold),
    )
}

/// Produces a genesis balance for a new network.
pub fn get_genesis(
    balance: u64,
    id: PublicKey,
    peer_replicas: PublicKeySet,
    secret_key_share: SecretKeyShare,
) -> Result<CreditAgreementProof> {
    let credit = Credit {
        id: Default::default(),
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
