// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    elder_signing::ElderSigning,
    reward_calc::distribute_rewards,
    reward_stage::{
        ChurnAccumulationDetails, ChurnProposalDetails, CreditAccumulation, CreditProposal,
        RewardStage,
    },
};
use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Error, Result,
};
use bls::PublicKey as BlsPublicKey;
use log::{debug, info, warn};
use sn_data_types::{
    Credit, NodeAge, PublicKey, RewardAccumulation, RewardProposal, SectionElders, Signature,
    SignatureShare, SignedCredit, SignedCreditShare, Signing, Token, TransferPropagated,
};
use sn_messaging::{
    client::{NodeCmd, NodeQuery, NodeSystemCmd, NodeSystemQuery, ProcessMsg},
    Aggregation, DstLocation, MessageId,
};
use std::collections::{BTreeMap, BTreeSet};
use xor_name::{Prefix, XorName};

///
#[derive(Clone)]
pub struct RewardProcess {
    balance: Token,
    section: OurSection,
    stage: RewardStage,
    signing: ElderSigning,
}

///
#[derive(Clone, Debug)]
pub struct OurSection {
    ///
    pub our_prefix: Prefix,
    ///
    pub our_key: PublicKey,
}

impl OurSection {
    // Our section wallet key
    pub fn wallet_key(&self) -> PublicKey {
        self.our_key
    }

    /// Our section's prefix name
    pub fn address(&self) -> XorName {
        self.our_prefix.name()
    }
}

impl RewardProcess {
    pub fn new(balance: Token, section: OurSection, signing: ElderSigning) -> Self {
        Self {
            balance,
            section,
            signing,
            stage: RewardStage::AwaitingThreshold,
        }
    }

    pub fn stage(&self) -> &RewardStage {
        &self.stage
    }

    pub async fn reward_and_mint(
        &mut self,
        our_nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
    ) -> Result<NodeDuty> {
        //  -----  MINTING  -----
        // This is the minting of new coins happening;
        // the size being the sum of payments to parent section.
        let minting = 2; // double the amount paid into section

        // Calculate our nodes' rewards;
        // the size being the sum of payments to parent section.
        let reward_credits = self.get_reward_proposals(minting, self.section.our_key, our_nodes);
        let reward_sum: u64 = reward_credits.iter().map(|c| c.amount().as_nano()).sum();

        let proposal = self.sign_proposed_rewards(reward_credits).await?;

        let to_send =
            proposal.get_proposal(self.section.wallet_key(), self.signing.our_index().await?);

        self.stage = RewardStage::ProposingCredits(proposal.clone());
        Ok(send_prop_msg(to_send, self.section.address()))
    }

    async fn sign_proposed_rewards(
        &self,
        rewards: Vec<CreditProposal>,
    ) -> Result<ChurnProposalDetails> {
        let mut proposal = ChurnProposalDetails {
            rewards: BTreeMap::new(),
            pk_set: self.signing.public_key_set().await?,
        };
        for credit in rewards {
            let _ = proposal.rewards.insert(*credit.id(), credit);
        }
        for (_, credit) in proposal.rewards.clone() {
            let share = match self.signing.sign(&credit.proposal)? {
                Signature::BlsShare(share) => share,
                _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
            };
            proposal.add_sig(credit.id(), &share)?;
        }
        Ok(proposal)
    }

    async fn sign_accumulating_rewards(
        &self,
        rewards: Vec<CreditAccumulation>,
    ) -> Result<ChurnAccumulationDetails> {
        let mut accumulation = ChurnAccumulationDetails {
            pk_set: self.signing.public_key_set().await?,
            rewards: Default::default(),
        };
        for acc in rewards {
            let _ = accumulation.rewards.insert(*acc.id(), acc);
        }
        for (_, credit) in accumulation.rewards.clone() {
            let share = match self.signing.sign(&credit.agreed_proposal)? {
                Signature::BlsShare(share) => share,
                _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
            };
            accumulation.add_sig(credit.id(), &share)?;
        }
        Ok(accumulation)
    }

    fn get_reward_proposals(
        &self,
        minting: u8,
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

    // TODO: validate the credit...
    pub async fn receive_churn_proposal(&mut self, proposal: RewardProposal) -> Result<NodeDuty> {
        if proposal.section_key != self.section.wallet_key() {
            return Err(Error::Transfer(sn_transfers::Error::InvalidOwner));
        }
        match self.stage.clone() {
            RewardStage::None | RewardStage::AwaitingThreshold => {
                debug!("@ receive_churn_proposal when RewardStage::None | RewardStage::AwaitingThreshold");
                let rewards = proposal
                    .rewards
                    .iter()
                    .map(|share| CreditProposal {
                        proposal: share.credit.clone(),
                        signatures: Default::default(),
                        pending_agreement: None,
                    })
                    .collect();

                let mut our_proposal = self.sign_proposed_rewards(rewards).await?;

                // Add sigs of incoming proposal
                for p in proposal.rewards {
                    our_proposal.add_sig(p.id(), &p.actor_signature)?
                }

                let to_send = our_proposal
                    .get_proposal(self.section.wallet_key(), self.signing.our_index().await?);

                self.stage = RewardStage::ProposingCredits(our_proposal);

                Ok(send_prop_msg(to_send, self.section.address()))
            }
            RewardStage::ProposingCredits(mut proposal_details) => {
                // Add proposals
                for p in proposal.rewards {
                    proposal_details.add_sig(p.id(), &p.actor_signature)?
                }

                if let Some(rewards) = proposal_details.pending_agreements() {
                    info!("******* there is an agreement for reward proposal.");
                    // replicas signatures over > signed_credit <
                    let mut our_acc = ChurnAccumulationDetails {
                        pk_set: proposal_details.pk_set,
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

                    let our_acc = self.sign_accumulating_rewards(rewards).await?;
                    let to_send = our_acc.get_accumulation(
                        self.section.wallet_key(),
                        self.signing.our_index().await?,
                    );

                    self.stage = RewardStage::AccumulatingCredits(our_acc);

                    Ok(send_acc_msg(to_send, self.section.address()))
                } else {
                    self.stage = RewardStage::ProposingCredits(proposal_details);
                    Ok(NodeDuty::NoOp)
                }
            }
            RewardStage::AccumulatingCredits(_) => Ok(NodeDuty::NoOp),
            RewardStage::Completed(_) => Ok(NodeDuty::NoOp),
            RewardStage::None => Err(Error::InvalidGenesisStage),
        }
    }

    /// Receive wallet accumulation
    pub async fn receive_wallet_accumulation(
        &mut self,
        new_acc: RewardAccumulation,
    ) -> Result<NodeDuty> {
        if new_acc.section_key != self.section.wallet_key() {
            return Err(Error::Transfer(sn_transfers::Error::InvalidOwner));
        }
        match self.stage.clone() {
            RewardStage::AwaitingThreshold => {
                let rewards = new_acc
                    .rewards
                    .iter()
                    .map(|reward| CreditAccumulation {
                        agreed_proposal: reward.signed_credit.clone(),
                        signatures: Default::default(),
                        pending_agreement: None,
                    })
                    .collect();

                let mut our_acc = self.sign_accumulating_rewards(rewards).await?;

                // Add sigs of incoming proposal
                for p in new_acc.rewards {
                    our_acc.add_sig(p.id(), &p.sig)?
                }

                let to_send = our_acc
                    .get_accumulation(self.section.wallet_key(), self.signing.our_index().await?);

                self.stage = RewardStage::AccumulatingCredits(our_acc);

                Ok(send_acc_msg(to_send, self.section.address()))
            }
            RewardStage::ProposingCredits(proposal_details) => {
                // create our acc details
                let mut our_acc = ChurnAccumulationDetails {
                    pk_set: proposal_details.pk_set,
                    rewards: Default::default(),
                };

                let rewards = new_acc
                    .rewards
                    .iter()
                    .map(|reward| CreditAccumulation {
                        agreed_proposal: reward.signed_credit.clone(),
                        signatures: Default::default(),
                        pending_agreement: None,
                    })
                    .collect();

                // sign all the rewards
                let mut our_acc = self.sign_accumulating_rewards(rewards).await?;

                // Add sigs of incoming proposal
                for p in new_acc.rewards {
                    our_acc.add_sig(p.id(), &p.sig)?
                }

                let to_send = our_acc
                    .get_accumulation(self.section.wallet_key(), self.signing.our_index().await?);

                self.stage = RewardStage::AccumulatingCredits(our_acc);

                Ok(send_acc_msg(to_send, self.section.address()))
            }
            RewardStage::AccumulatingCredits(mut our_acc) => {
                // Add sigs of incoming proposal
                for p in new_acc.rewards {
                    our_acc.add_sig(p.id(), &p.sig)?
                }

                if let Some(credit_proofs) = our_acc.pending_agreements() {
                    info!("******* there is an agreement for reward accumulation.");
                    self.stage = RewardStage::Completed(credit_proofs);
                } else {
                    self.stage = RewardStage::AccumulatingCredits(our_acc);
                }
                Ok(NodeDuty::NoOp)
            }
            RewardStage::Completed(_) => Ok(NodeDuty::NoOp),
            RewardStage::None => Err(Error::InvalidGenesisStage),
        }
    }
}

fn send_prop_msg(proposal: RewardProposal, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: ProcessMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeRewardPayout(proposal)),
            id: MessageId::new(),
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}

fn send_acc_msg(accumulation: RewardAccumulation, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: ProcessMsg::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateRewardPayout(accumulation)),
            id: MessageId::new(),
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}
