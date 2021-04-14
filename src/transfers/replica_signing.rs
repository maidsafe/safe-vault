// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{network::Network, Result};
use async_trait::async_trait;
use bls::PublicKeySet;
use sn_data_types::{
    CreditAgreementProof, SignatureShare, SignedCredit, SignedDebit, SignedTransfer,
};

#[async_trait]
pub trait ReplicaSigning {
    /// Get the replica's PK set
    async fn replicas_pk_set(&self) -> Result<PublicKeySet>;

    async fn sign_transfer(
        &self,
        signed_transfer: &SignedTransfer,
    ) -> Result<(SignatureShare, SignatureShare)>;

    async fn sign_validated_debit(&self, debit: &SignedDebit) -> Result<SignatureShare>;

    async fn sign_validated_credit(&self, credit: &SignedCredit) -> Result<SignatureShare>;

    async fn sign_credit_proof(&self, proof: &CreditAgreementProof) -> Result<SignatureShare>;

    async fn known_replicas(
        &self,
        wallet_name: &sn_routing::XorName,
        section_key: bls::PublicKey,
    ) -> bool;
}

/// The Replica is the part of an AT2 system
/// that forms validating groups, and signs
/// individual transfers between wallets.
/// Replicas validate requests to debit an wallet, and
/// apply operations that has a valid "debit agreement proof"
/// from the group, i.e. signatures from a quorum of its peers.
/// Replicas don't initiate transfers or drive the algo - only Actors do.
#[derive(Clone)]
pub struct ReplicaSigningImpl {
    network: Network,
}

impl ReplicaSigningImpl {
    /// A new instance
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}

#[async_trait]
impl ReplicaSigning for ReplicaSigningImpl {
    /// Get the replica's PK set
    async fn replicas_pk_set(&self) -> Result<PublicKeySet> {
        Ok(self.network.our_public_key_set().await?)
    }

    async fn sign_transfer(
        &self,
        signed_transfer: &SignedTransfer,
    ) -> Result<(SignatureShare, SignatureShare)> {
        let replica_debit_sig = self.sign_validated_debit(&signed_transfer.debit).await?;
        let replica_credit_sig = self.sign_validated_credit(&signed_transfer.credit).await?;
        Ok((replica_debit_sig, replica_credit_sig))
    }

    // TODO is this not the same as our elder signing?
    async fn sign_validated_debit(&self, debit: &SignedDebit) -> Result<SignatureShare> {
        Ok(self.network.sign_as_elder(&debit).await?)
    }

    async fn sign_validated_credit(&self, credit: &SignedCredit) -> Result<SignatureShare> {
        Ok(self.network.sign_as_elder(&credit).await?)
    }

    async fn sign_credit_proof(&self, proof: &CreditAgreementProof) -> Result<SignatureShare> {
        Ok(self.network.sign_as_elder(&proof).await?)
    }

    /// Brittle validation of provided section key (once) being
    /// a valid section, since the query returns the current key..
    async fn known_replicas(
        &self,
        wallet_name: &sn_routing::XorName,
        section_key: bls::PublicKey,
    ) -> bool {
        if let Some(key) = self.network.matching_section(wallet_name).await {
            key == section_key
        } else {
            false
        }
    }
}
