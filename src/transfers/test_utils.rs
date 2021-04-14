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
use bls::{PublicKeySet, PublicKeyShare, SecretKeyShare};
use sn_data_types::{
    CreditAgreementProof, SignatureShare, SignedCredit, SignedDebit, SignedTransfer,
};

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
