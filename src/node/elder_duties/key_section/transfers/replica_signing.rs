// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::genesis::get_genesis;
use crate::{ElderState, Result};
use async_trait::async_trait;
use bls::PublicKeySet;
use sn_data_types::{
    CreditAgreementProof, SignatureShare, SignedCredit, SignedDebit, SignedTransfer,
};

#[async_trait]
pub trait ReplicaSigning {
    /// Get the replica's PK set
    fn replicas_pk_set(&self) -> &PublicKeySet;

    async fn try_genesis(&self, balance: u64) -> Result<CreditAgreementProof>;

    async fn sign_transfer(
        &self,
        signed_transfer: &SignedTransfer,
    ) -> Result<(SignatureShare, SignatureShare)>;

    async fn sign_validated_debit(&self, debit: &SignedDebit) -> Result<SignatureShare>;

    async fn sign_validated_credit(&self, credit: &SignedCredit) -> Result<SignatureShare>;

    async fn sign_credit_proof(&self, proof: &CreditAgreementProof) -> Result<SignatureShare>;
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
    /// ElderState.
    elder_state: ElderState,
}

impl ReplicaSigningImpl {
    /// A new instance
    pub fn new(elder_state: ElderState) -> Self {
        Self { elder_state }
    }
}

#[async_trait]
impl ReplicaSigning for ReplicaSigningImpl {
    /// Get the replica's PK set
    fn replicas_pk_set(&self) -> &PublicKeySet {
        self.elder_state.public_key_set()
    }

    async fn try_genesis(&self, balance: u64) -> Result<CreditAgreementProof> {
        get_genesis(balance, &self.elder_state).await
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
        self.elder_state.sign_as_elder(&debit).await
    }

    async fn sign_validated_credit(&self, credit: &SignedCredit) -> Result<SignatureShare> {
        self.elder_state.sign_as_elder(&credit).await
    }

    async fn sign_credit_proof(&self, proof: &CreditAgreementProof) -> Result<SignatureShare> {
        self.elder_state.sign_as_elder(&proof).await
    }
}
