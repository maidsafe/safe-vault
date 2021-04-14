// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use log::{debug, warn};
use sn_data_types::{
    Credit, CreditAgreementProof, CreditId, PublicKey, ReplicaPublicKeySet, SignatureShare,
    SignedCredit, SignedCreditShare,
};
use std::collections::BTreeMap;

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RewardStage {
    AwaitingThreshold,
    ProposingCredits(RewardProposalDetails),
    AccumulatingCredits(RewardAccumulationDetails),
    Completed(BTreeMap<CreditId, CreditAgreementProof>),
}

#[derive(Clone, Debug)]
pub struct RewardProposalDetails {
    pub pk_set: ReplicaPublicKeySet,
    pub rewards: BTreeMap<CreditId, CreditProposal>,
}

#[derive(Clone, Debug)]
pub struct CreditProposal {
    pub proposal: Credit,
    pub signatures: BTreeMap<usize, bls::SignatureShare>,
    pub pending_agreement: Option<SignedCredit>,
}

impl CreditProposal {
    pub fn id(&self) -> &CreditId {
        self.proposal.id()
    }
}

#[derive(Clone)]
pub struct RewardAccumulationDetails {
    pub pk_set: ReplicaPublicKeySet,
    pub rewards: BTreeMap<CreditId, CreditAccumulation>,
}

#[derive(Clone)]
pub struct CreditAccumulation {
    pub agreed_proposal: SignedCredit,
    pub signatures: BTreeMap<usize, bls::SignatureShare>,
    pub pending_agreement: Option<CreditAgreementProof>,
}

impl CreditAccumulation {
    pub fn id(&self) -> &CreditId {
        self.agreed_proposal.id()
    }
}

impl RewardProposalDetails {
    pub(crate) fn pending_agreements(&self) -> Option<BTreeMap<CreditId, SignedCredit>> {
        let rewards: BTreeMap<CreditId, SignedCredit> = self
            .rewards
            .values()
            .map(|proposal| proposal.pending_agreement.clone())
            .flatten()
            .map(|credit| (*credit.id(), credit))
            .collect();
        if rewards.len() == self.rewards.len() {
            Some(rewards)
        } else {
            debug!(
                "Rewards len {}, self.rewards len {}",
                rewards.len(),
                self.rewards.len()
            );
            None
        }
    }

    pub(crate) fn get_proposal(
        &self,
        section_key: PublicKey,
        index: usize,
    ) -> sn_data_types::RewardProposal {
        sn_data_types::RewardProposal {
            section_key,
            rewards: self
                .rewards
                .iter()
                .map(|(_, credit)| {
                    let share = credit.signatures.get(&index)?;
                    Some(SignedCreditShare {
                        credit: credit.proposal.clone(),
                        actor_signature: SignatureShare {
                            share: share.clone(),
                            index,
                        },
                    })
                })
                .flatten()
                .collect(),
        }
    }

    pub(crate) fn add_sig(&mut self, id: &CreditId, sig: &SignatureShare) -> Result<()> {
        let credit = self
            .rewards
            .get_mut(id)
            .ok_or_else(|| Error::Logic("logic error..".to_string()))?;
        if let Some(true) = check(&sig, &credit.signatures) {
            return Ok(());
        }
        let _ = credit.signatures.insert(sig.index, sig.share.clone());
        let min_count = 1 + self.pk_set.threshold();
        if credit.signatures.len() >= min_count {
            // Combine shares to produce the main signature.
            let actor_signature = sn_data_types::Signature::Bls(
                self.pk_set
                    .combine_signatures(&credit.signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            credit.pending_agreement = Some(SignedCredit {
                credit: credit.proposal.clone(),
                actor_signature,
            });
        }

        Ok(())
    }
}

fn check(sig: &SignatureShare, signatures: &BTreeMap<usize, bls::SignatureShare>) -> Option<bool> {
    match signatures.get(&sig.index) {
        Some(share) => {
            if share == &sig.share {
                Some(true)
            } else {
                warn!(
                    "####### CreditProposal adding different sig!?? contains {:?}, but adding {:?}..",
                    share,
                    sig.share,
                );
                Some(false)
            }
        }
        None => None,
    }
}

impl RewardAccumulationDetails {
    pub(crate) fn pending_agreements(&self) -> Option<BTreeMap<CreditId, CreditAgreementProof>> {
        let rewards: BTreeMap<CreditId, CreditAgreementProof> = self
            .rewards
            .values()
            .map(|proposal| proposal.pending_agreement.clone())
            .flatten()
            .map(|credit| (*credit.id(), credit))
            .collect();
        if rewards.len() == self.rewards.len() {
            Some(rewards)
        } else {
            None
        }
    }

    pub(crate) fn get_accumulation(
        &self,
        section_key: PublicKey,
        index: usize,
    ) -> sn_data_types::RewardAccumulation {
        sn_data_types::RewardAccumulation {
            section_key,
            rewards: self
                .rewards
                .iter()
                .map(|(_, credit)| {
                    let share = credit.signatures.get(&index)?;
                    Some(sn_data_types::AccumulatingReward {
                        signed_credit: credit.agreed_proposal.clone(),
                        sig: SignatureShare {
                            share: share.clone(),
                            index,
                        },
                    })
                })
                .flatten()
                .collect(),
        }
    }

    pub(crate) fn add_sig(&mut self, id: &CreditId, sig: &SignatureShare) -> Result<()> {
        let credit = self
            .rewards
            .get_mut(id)
            .ok_or_else(|| Error::Logic("".to_string()))?;
        if let Some(true) = check(sig, &credit.signatures) {
            return Ok(());
        }
        let _ = credit.signatures.insert(sig.index, sig.share.clone());
        let min_count = 1 + self.pk_set.threshold();
        if credit.signatures.len() >= min_count {
            // Combine shares to produce the main signature.
            let debiting_replicas_sig = sn_data_types::Signature::Bls(
                self.pk_set
                    .combine_signatures(&credit.signatures)
                    .map_err(|_| Error::CouldNotCombineSignatures)?,
            );

            credit.pending_agreement = Some(CreditAgreementProof {
                signed_credit: credit.agreed_proposal.clone(),
                debiting_replicas_sig,
                debiting_replicas_keys: self.pk_set.clone(),
            });
        }

        Ok(())
    }
}
