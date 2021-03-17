// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use log::info;
use sn_data_types::{
    Credit, CreditAgreementProof, ReplicaPublicKeySet, SignatureShare, SignedCredit,
    TransferPropagated,
};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct WalletProposal {
    pub proposal: Credit,
    pub pk_set: ReplicaPublicKeySet,
    pub signatures: BTreeMap<usize, bls::SignatureShare>,
    pub pending_agreement: Option<SignedCredit>,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum WalletStage {
    None,
    AwaitingWalletThreshold,
    ProposingWallet(WalletProposal),
    AccumulatingWallet(WalletAccumulation),
    Completed(CreditAgreementProof),
}

#[derive(Clone)]
pub struct WalletAccumulation {
    pub agreed_proposal: SignedCredit,
    pub pk_set: ReplicaPublicKeySet,
    pub signatures: BTreeMap<usize, bls::SignatureShare>,
    pub pending_agreement: Option<CreditAgreementProof>,
}

impl WalletProposal {
    pub(crate) fn add(&mut self, sig: SignatureShare) -> Result<()> {
        if self.signatures.contains_key(&sig.index) {
            return Ok(());
        }
        let mut signatures = self.signatures.clone();
        let _ = signatures.insert(sig.index, sig.share);
        let min_count = 1 + self.pk_set.threshold();
        if signatures.len() >= min_count {
            info!("Aggregating actor signature..");

            // Combine shares to produce the main signature.
            let actor_signature = sn_data_types::Signature::Bls(
                self.pk_set
                    .combine_signatures(&signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            self.signatures = signatures;

            self.pending_agreement = Some(SignedCredit {
                credit: self.proposal.clone(),
                actor_signature,
            });
        }

        Ok(())
    }
}

impl WalletAccumulation {
    pub(crate) fn add(&mut self, sig: SignatureShare) -> Result<()> {
        if self.signatures.contains_key(&sig.index) {
            return Ok(());
        }
        let mut signatures = self.signatures.clone();
        let _ = signatures.insert(sig.index, sig.share);
        let min_count = 1 + self.pk_set.threshold();
        if signatures.len() >= min_count {
            info!("Aggregating replica signature..");
            // Combine shares to produce the main signature.
            let debiting_replicas_sig = sn_data_types::Signature::Bls(
                self.pk_set
                    .combine_signatures(&signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            self.signatures = signatures;

            self.pending_agreement = Some(CreditAgreementProof {
                signed_credit: self.agreed_proposal.clone(),
                debiting_replicas_sig,
                debiting_replicas_keys: self.pk_set.clone(),
            });
        }

        Ok(())
    }
}
