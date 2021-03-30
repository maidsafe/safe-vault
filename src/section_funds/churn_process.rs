// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Error, Result,
};
use bls::PublicKey as BlsPublicKey;
use log::{debug, info, warn};
use sn_data_types::{
    ChurnPayoutAccumulation, ChurnPayoutProposal, Credit, NodeAge, PublicKey, SectionElders,
    Signature, SignatureShare, SignedCredit, SignedCreditShare, Signing, Token, TransferPropagated,
};
use sn_messaging::{
    client::{NodeCmd, NodeQuery, NodeSystemCmd, NodeSystemQuery, ProcessMsg},
    Aggregation, DstLocation, MessageId,
};
use xor_name::{Prefix, XorName};

use super::{
    churn_payout_stage::{
        ChurnAccumulationDetails, ChurnPayoutStage, ChurnProposalDetails, CreditAccumulation,
        CreditProposal, PendingAgreements,
    },
    elder_signing::ElderSigning,
    reward_calc::distribute_rewards,
    section_wallet::SectionWallet,
};

///
#[derive(Clone)]
pub struct ChurnProcess {
    balance: Token,
    churn: Churn,
    stage: ChurnPayoutStage,
    signing: ElderSigning,
}

///
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Churn {
    /// Contains next section prefix + wallets.
    Regular {
        our_prefix: Prefix,

        our_key: PublicKey,
    },
    /// Contains the new children prefix + wallets.
    Split {
        our_prefix: Prefix,
        ///
        our_key: PublicKey,
        /// Neighbouring section Pk
        sibling_key: PublicKey,
    },
}

impl Churn {
    pub fn wallet_key(&self) -> PublicKey {
        match self {
            Self::Regular { our_key, .. } => *our_key,
            Self::Split { our_key, .. } => *our_key,
        }
    }

    /// Our elder's prefix name
    pub fn our_elders_address(&self) -> XorName {
        match self {
            Self::Regular { our_prefix, .. } => our_prefix.name(),
            Self::Split { our_prefix, .. } => our_prefix.name(),
        }
    }

    /// Our elders wallet key name. (XorName derived from PK)
    pub fn our_elders_name(&self) -> XorName {
        XorName::from(self.wallet_key())
    }
}

impl ChurnProcess {
    pub fn new(balance: Token, churn: Churn, signing: ElderSigning) -> Self {
        Self {
            balance,
            churn,
            signing,
            stage: ChurnPayoutStage::AwaitingThreshold,
        }
    }

    pub fn stage(&self) -> &ChurnPayoutStage {
        &self.stage
    }

    pub async fn reward_and_mint(
        &mut self,
        our_nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
    ) -> Result<NodeDuty> {
        let proposal = match self.churn.clone() {
            Churn::Regular { .. } => self.add_wallet_proposal(self.balance).await?,
            Churn::Split {
                our_prefix,
                our_key,
                sibling_key,
            } => {
                // Calculate our nodes' rewards;
                // the size being the sum of payments to parent section.
                let reward_credits = self.get_reward_proposals(our_prefix, our_key, our_nodes);
                let reward_sum: u64 = reward_credits.iter().map(|c| c.amount().as_nano()).sum();

                //  -----  MINTING  -----
                // This is the minting of new coins happening;
                // the size being the sum of payments to parent section.
                let half_balance = self.balance.as_nano() / 2;
                let remainder = self.balance.as_nano() % 2;

                // Setup two transfer amounts; one to each sibling wallet
                let t1_amount = Token::from_nano(half_balance + remainder);
                let t2_amount = Token::from_nano(half_balance);

                // Determine which transfer is first
                // (deterministic order is important for reaching consensus)
                let mut proposal = if our_key > sibling_key {
                    self.add_wallet_proposal(t1_amount).await?
                } else {
                    self.add_wallet_proposal(t2_amount).await?
                };

                self.sign_proposed_rewards(proposal, reward_credits)?
            }
        };

        let our_index = self.signing.our_index().await?;
        let to_send = proposal
            .get_proposal(our_index)
            .ok_or_else(|| Error::Logic("Could not get proposal".to_string()))?;

        self.stage = ChurnPayoutStage::ProposingCredits(proposal.clone());
        Ok(send_prop_msg(to_send, self.churn.our_elders_address()))
    }

    fn sign_proposed_rewards(
        &self,
        mut proposal: ChurnProposalDetails,
        rewards: Vec<CreditProposal>,
    ) -> Result<ChurnProposalDetails> {
        for credit in rewards {
            let _ = proposal.rewards.insert(*credit.id(), credit);
        }
        for (_, credit) in proposal.rewards.clone() {
            let share = match self.signing.sign(&credit.proposal)? {
                Signature::BlsShare(share) => share,
                _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
            };
            proposal.add(credit.id(), &share)?;
        }
        Ok(proposal)
    }

    fn sign_accumulating_rewards(
        &self,
        mut accumulation: ChurnAccumulationDetails,
        rewards: Vec<CreditAccumulation>,
    ) -> Result<ChurnAccumulationDetails> {
        for acc in rewards {
            let _ = accumulation.rewards.insert(*acc.id(), acc);
        }
        for (_, credit) in accumulation.rewards.clone() {
            let share = match self.signing.sign(&credit.agreed_proposal)? {
                Signature::BlsShare(share) => share,
                _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
            };
            accumulation.add(*credit.id(), share)?;
        }
        Ok(accumulation)
    }

    fn get_reward_proposals(
        &self,
        section_prefix: Prefix,
        section_key: PublicKey,
        nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
    ) -> Vec<CreditProposal> {
        // create reward distribution
        distribute_rewards(self.balance, nodes)
            .into_iter()
            .map(|(node, (age, wallet, amount))| {
                let id = MessageId::combine(vec![node, XorName::from(section_key)])
                    .0
                     .0;

                CreditProposal {
                    proposal: Credit {
                        id,
                        amount,
                        recipient: wallet,
                        msg: format!("Reward at age {}, from {}", age, section_key),
                    },
                    signatures: Default::default(),
                    pending_agreement: None,
                }
            })
            .collect()
    }

    /// Generates msgs for creation of new section wallet.
    async fn add_wallet_proposal(&mut self, amount: Token) -> Result<ChurnProposalDetails> {
        let id = MessageId::combine(vec![
            self.churn.our_elders_address(),
            self.churn.our_elders_name(),
        ])
        .0
         .0;

        let credit = Credit {
            id,
            amount,
            recipient: self.churn.wallet_key(),
            msg: "New section wallet".to_string(),
        };

        let mut churn_proposal = ChurnProposalDetails {
            section_wallet: CreditProposal {
                proposal: credit.clone(),
                signatures: Default::default(),
                pending_agreement: None,
            },
            rewards: BTreeMap::new(),
            pk_set: self.signing.public_key_set().await?,
        };

        match self.signing.sign(&credit)? {
            Signature::BlsShare(share) => {
                churn_proposal.add(&id, &share)?;
            }
            _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
        };

        Ok(churn_proposal)
    }

    // TODO: validate the credit...
    pub async fn receive_churn_proposal(
        &mut self,
        proposal: ChurnPayoutProposal,
    ) -> Result<NodeDuty> {
        if proposal.section_wallet.recipient() != self.churn.wallet_key() {
            return Err(Error::Transfer(sn_transfers::Error::CreditDoesNotBelong(
                self.churn.wallet_key(),
                proposal.section_wallet.credit,
            )));
        }
        match self.stage.clone() {
            ChurnPayoutStage::None | ChurnPayoutStage::AwaitingThreshold => {
                debug!("@ receive_churn_proposal when ChurnPayoutStage::None | ChurnPayoutStage::AwaitingThreshold");
                let amount = proposal.section_wallet.amount();
                let mut our_proposal = self.add_wallet_proposal(amount).await?;
                let our_proposal = self.sign_proposed_rewards(
                    our_proposal,
                    proposal
                        .rewards
                        .into_iter()
                        .map(|share| CreditProposal {
                            proposal: share.credit,
                            signatures: Default::default(),
                            pending_agreement: None,
                        })
                        .collect(),
                )?;

                let our_index = self.signing.our_index().await?;
                let to_send = our_proposal
                    .get_proposal(our_index)
                    .ok_or_else(|| Error::Logic("Could not get proposal".to_string()))?;

                self.stage = ChurnPayoutStage::ProposingCredits(our_proposal);

                Ok(send_prop_msg(to_send, self.churn.our_elders_address()))
            }
            ChurnPayoutStage::ProposingCredits(mut proposal_details) => {
                // Add section wallet proposal
                proposal_details.add(
                    proposal.section_wallet.id(),
                    &proposal.section_wallet.actor_signature,
                )?;

                if let Some(PendingAgreements {
                    section_wallet,
                    rewards,
                }) = proposal_details.pending_agreements()
                {
                    info!(
                        "******* there is an agreement for churn proposal (newbie?: {}).",
                        self.balance == Token::zero()
                    );
                    // replicas signatures over > signed_credit <
                    let mut our_acc = ChurnAccumulationDetails {
                        pk_set: proposal_details.pk_set,
                        section_wallet: CreditAccumulation {
                            agreed_proposal: section_wallet,
                            signatures: Default::default(),
                            pending_agreement: None,
                        },
                        rewards: Default::default(),
                    };

                    let rewards = rewards
                        .into_iter()
                        .map(|(_, signed_credit)| CreditAccumulation {
                            agreed_proposal: signed_credit,
                            signatures: Default::default(),
                            pending_agreement: None,
                        })
                        .collect();

                    let our_acc = self.sign_accumulating_rewards(our_acc, rewards)?;
                    let our_index = self.signing.our_index().await?;
                    let to_send = our_acc
                        .get_accumulation(our_index)
                        .ok_or_else(|| Error::Logic("Could not get proposal".to_string()))?;

                    self.stage = ChurnPayoutStage::AccumulatingCredits(our_acc);

                    Ok(send_acc_msg(to_send, self.churn.our_elders_address()))
                } else {
                    self.stage = ChurnPayoutStage::ProposingCredits(proposal_details);
                    Ok(NodeDuty::NoOp)
                }
            }
            ChurnPayoutStage::AccumulatingCredits(_) => Ok(NodeDuty::NoOp),
            ChurnPayoutStage::Completed(_) => Ok(NodeDuty::NoOp),
            ChurnPayoutStage::None => Err(Error::InvalidGenesisStage),
        }
    }

    /// Receive wallet accumulation
    pub async fn receive_wallet_accumulation(
        &mut self,
        new_acc: ChurnPayoutAccumulation,
    ) -> Result<NodeDuty> {
        if new_acc.section_wallet.signed_credit.recipient() != self.churn.wallet_key() {
            return Err(Error::Transfer(sn_transfers::Error::CreditDoesNotBelong(
                self.churn.wallet_key(),
                new_acc.section_wallet.signed_credit.credit,
            )));
        }
        match self.stage.clone() {
            ChurnPayoutStage::AwaitingThreshold => {
                // replicas signatures over > signed_credit <
                let mut our_acc = ChurnAccumulationDetails {
                    pk_set: self.signing.public_key_set().await?,
                    section_wallet: CreditAccumulation {
                        agreed_proposal: new_acc.section_wallet.signed_credit.clone(),
                        signatures: Default::default(),
                        pending_agreement: None,
                    },
                    rewards: Default::default(),
                };

                // add the incoming sig
                our_acc.add(*new_acc.section_wallet.id(), new_acc.section_wallet.sig);

                let rewards = new_acc
                    .rewards
                    .into_iter()
                    .map(|reward| CreditAccumulation {
                        agreed_proposal: reward.signed_credit,
                        signatures: Default::default(),
                        pending_agreement: None,
                    })
                    .collect();

                let our_acc = self.sign_accumulating_rewards(our_acc, rewards)?;
                let our_index = self.signing.our_index().await?;
                let to_send = our_acc
                    .get_accumulation(our_index)
                    .ok_or_else(|| Error::Logic("Could not get proposal".to_string()))?;

                self.stage = ChurnPayoutStage::AccumulatingCredits(our_acc);

                Ok(send_acc_msg(to_send, self.churn.our_elders_address()))
            }
            ChurnPayoutStage::ProposingCredits(proposal_details) => {
                // create our acc details
                let mut our_acc = ChurnAccumulationDetails {
                    pk_set: proposal_details.pk_set,
                    section_wallet: CreditAccumulation {
                        agreed_proposal: new_acc.section_wallet.signed_credit.clone(),
                        signatures: Default::default(),
                        pending_agreement: None,
                    },
                    rewards: Default::default(),
                };

                // add the incoming sig
                our_acc.add(*new_acc.section_wallet.id(), new_acc.section_wallet.sig);

                let rewards = new_acc
                    .rewards
                    .into_iter()
                    .map(|reward| CreditAccumulation {
                        agreed_proposal: reward.signed_credit,
                        signatures: Default::default(),
                        pending_agreement: None,
                    })
                    .collect();

                // sign all the rewards
                let our_acc = self.sign_accumulating_rewards(our_acc, rewards)?;
                let our_index = self.signing.our_index().await?;
                let to_send = our_acc
                    .get_accumulation(our_index)
                    .ok_or_else(|| Error::Logic("Could not get proposal".to_string()))?;

                self.stage = ChurnPayoutStage::AccumulatingCredits(our_acc);

                Ok(send_acc_msg(to_send, self.churn.our_elders_address()))
            }
            ChurnPayoutStage::AccumulatingCredits(mut our_acc) => {
                // add the incoming sig
                our_acc.add(*new_acc.section_wallet.id(), new_acc.section_wallet.sig);
                if let Some(credit_proofs) = our_acc.pending_agreements() {
                    info!(
                        "******* there is an agreement for wallet accumulation (newbie?: {}).",
                        self.balance == Token::zero()
                    );
                    self.stage = ChurnPayoutStage::Completed(credit_proofs);
                } else {
                    self.stage = ChurnPayoutStage::AccumulatingCredits(our_acc);
                }
                Ok(NodeDuty::NoOp)
            }
            ChurnPayoutStage::Completed(_) => Ok(NodeDuty::NoOp),
            ChurnPayoutStage::None => Err(Error::InvalidGenesisStage),
        }
    }
}

fn send_prop_msg(proposal: ChurnPayoutProposal, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: ProcessMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeChurnPayout(proposal)),
            id: MessageId::new(),
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}

fn send_acc_msg(accumulation: ChurnPayoutAccumulation, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: ProcessMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateChurnPayout(accumulation)),
            id: MessageId::new(),
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}
