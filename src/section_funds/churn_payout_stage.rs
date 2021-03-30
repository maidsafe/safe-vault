// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use log::{debug, info, warn};
use sn_data_types::{
    Credit, CreditAgreementProof, CreditId, ReplicaPublicKeySet, SignatureShare, SignedCredit,
    SignedCreditShare, Token, TransferPropagated,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ChurnPayoutStage {
    None,
    AwaitingThreshold,
    ProposingCredits(ChurnProposalDetails),
    AccumulatingCredits(ChurnAccumulationDetails),
    Completed(AccumulatedAgreements),
}

#[derive(Clone, Debug)]
pub struct ChurnProposalDetails {
    pub pk_set: ReplicaPublicKeySet,
    pub section_wallet: CreditProposal,
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

    pub fn amount(&self) -> Token {
        self.proposal.amount
    }
}

#[derive(Clone)]
pub struct ChurnAccumulationDetails {
    pub pk_set: ReplicaPublicKeySet,
    pub section_wallet: CreditAccumulation,
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

    // pub fn amount(&self) -> Token {
    //     self.agreed_proposal.amount
    // }
}

pub struct PendingAgreements {
    pub section_wallet: SignedCredit,
    pub rewards: BTreeMap<CreditId, SignedCredit>,
}

impl ChurnProposalDetails {
    pub(crate) fn pending_agreements(&self) -> Option<PendingAgreements> {
        let section_wallet = if let Some(wallet) = self.section_wallet.pending_agreement.clone() {
            wallet
        } else {
            debug!("No section wallet yet");
            return None;
        };
        let rewards: BTreeMap<CreditId, SignedCredit> = self
            .rewards
            .values()
            .map(|proposal| proposal.pending_agreement.clone())
            .flatten()
            .map(|credit| (*credit.id(), credit))
            .collect();
        if rewards.len() == self.rewards.len() {
            Some(PendingAgreements {
                rewards,
                section_wallet,
            })
        } else {
            debug!(
                "Rewards len {}, self.rewards len {}",
                rewards.len(),
                self.rewards.len()
            );
            None
        }
    }

    pub(crate) fn get_proposal(&self, index: usize) -> Option<sn_data_types::ChurnPayoutProposal> {
        let share = self.section_wallet.signatures.get(&index)?;
        Some(sn_data_types::ChurnPayoutProposal {
            section_wallet: SignedCreditShare {
                credit: self.section_wallet.proposal.clone(),
                actor_signature: SignatureShare {
                    share: share.clone(),
                    index,
                },
            },
            rewards: self
                .rewards
                .iter()
                .map(|(id, credit)| {
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
        })
    }

    pub(crate) fn add(&mut self, id: &CreditId, sig: &SignatureShare) -> Result<()> {
        let credit = if self.section_wallet.proposal.id() == id {
            &mut self.section_wallet
        } else {
            self.rewards
                .get_mut(id)
                .ok_or_else(|| Error::Logic("logic error..".to_string()))?
        };
        if let Some(true) = check(&sig, &credit.signatures) {
            return Ok(());
        }
        let _ = credit.signatures.insert(sig.index, sig.share.clone());
        let min_count = 1 + self.pk_set.threshold();
        if credit.signatures.len() >= min_count {
            info!("Aggregating actor signature..");

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

#[derive(Clone)]
pub struct AccumulatedAgreements {
    pub section_wallet: CreditAgreementProof,
    pub rewards: BTreeMap<CreditId, CreditAgreementProof>,
}

impl ChurnAccumulationDetails {
    pub(crate) fn pending_agreements(&self) -> Option<AccumulatedAgreements> {
        let section_wallet = self.section_wallet.pending_agreement.clone()?;
        let rewards: BTreeMap<CreditId, CreditAgreementProof> = self
            .rewards
            .values()
            .map(|proposal| proposal.pending_agreement.clone())
            .flatten()
            .map(|credit| (*credit.id(), credit))
            .collect();
        if rewards.len() == self.rewards.len() {
            Some(AccumulatedAgreements {
                rewards,
                section_wallet,
            })
        } else {
            None
        }
    }

    pub(crate) fn get_accumulation(
        &self,
        index: usize,
    ) -> Option<sn_data_types::ChurnPayoutAccumulation> {
        let share = self.section_wallet.signatures.get(&index)?;
        Some(sn_data_types::ChurnPayoutAccumulation {
            section_wallet: sn_data_types::AccumulatingProof {
                signed_credit: self.section_wallet.agreed_proposal.clone(),
                sig: SignatureShare {
                    share: share.clone(),
                    index,
                },
            },
            rewards: self
                .rewards
                .iter()
                .map(|(id, credit)| {
                    let share = credit.signatures.get(&index)?;
                    Some(sn_data_types::AccumulatingProof {
                        signed_credit: credit.agreed_proposal.clone(),
                        sig: SignatureShare {
                            share: share.clone(),
                            index,
                        },
                    })
                })
                .flatten()
                .collect(),
        })
    }

    pub(crate) fn add(&mut self, id: CreditId, sig: SignatureShare) -> Result<()> {
        let credit = if self.section_wallet.agreed_proposal.id() == &id {
            &mut self.section_wallet
        } else {
            self.rewards
                .get_mut(&id)
                .ok_or_else(|| Error::Logic("".to_string()))?
        };
        if let Some(true) = check(&sig, &credit.signatures) {
            return Ok(());
        }
        let _ = credit.signatures.insert(sig.index, sig.share);
        let min_count = 1 + self.pk_set.threshold();
        if credit.signatures.len() >= min_count {
            info!("Aggregating replica signature..");
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
