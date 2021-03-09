// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::RewardsAndWallets, Error, Result};
use log::info;
use sn_data_types::{
    Credit, CreditAgreementProof, ReplicaPublicKeySet, SignatureShare, SignedCredit,
};
use std::collections::BTreeMap;

pub(crate) struct GenesisProposal {
    // pub rewards_and_wallets: RewardsAndWallets,
    pub proposal: Credit,
    pub signatures: BTreeMap<usize, bls::SignatureShare>,
    pub pending_agreement: Option<SignedCredit>,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum GenesisStage {
    None,
    AwaitingGenesisThreshold,
    ProposingGenesis(GenesisProposal),
    AccumulatingGenesis(GenesisAccumulation),
}

pub(crate) struct GenesisAccumulation {
    // pub rewards_and_wallets: RewardsAndWallets,
    pub agreed_proposal: SignedCredit,
    pub signatures: BTreeMap<usize, bls::SignatureShare>,
    pub pending_agreement: Option<CreditAgreementProof>,
}

impl GenesisProposal {
    pub(crate) fn add(&mut self, sig: SignatureShare, pk_set: ReplicaPublicKeySet) -> Result<()> {
        let _ = self.signatures.insert(sig.index, sig.share);
        let min_count = 1 + pk_set.threshold();
        if self.signatures.len() >= min_count {
            info!("Aggregating actor signature..");

            // Combine shares to produce the main signature.
            let actor_signature = sn_data_types::Signature::Bls(
                pk_set
                    .combine_signatures(&self.signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            info!("We got a sig?");

            let signed_credit = SignedCredit {
                credit: self.proposal.clone(),
                actor_signature,
            };

            self.pending_agreement = Some(signed_credit);
        }

        Ok(())
    }
}

impl GenesisAccumulation {
    pub(crate) fn add(&mut self, sig: SignatureShare, pk_set: ReplicaPublicKeySet) -> Result<()> {
        let _ = self.signatures.insert(sig.index, sig.share);
        let min_count = 1 + pk_set.threshold();
        if self.signatures.len() >= min_count {
            info!("Aggregating replica signature..");
            // Combine shares to produce the main signature.
            let debiting_replicas_sig = sn_data_types::Signature::Bls(
                pk_set
                    .combine_signatures(&self.signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            self.pending_agreement = Some(CreditAgreementProof {
                signed_credit: self.agreed_proposal.clone(),
                debiting_replicas_sig,
                debiting_replicas_keys: pk_set.clone(),
            });
        }

        Ok(())
    }
}
