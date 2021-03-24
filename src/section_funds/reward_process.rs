// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    elder_signing::ElderSigning,
    reward_calc::{distribute_rewards, get_reward_and_mint_amount},
    reward_stage::{
        CreditAccumulation, CreditProposal, RewardAccumulationDetails, RewardProposalDetails,
        RewardStage,
    },
};
use crate::{
    capacity::MAX_SUPPLY,
    node_ops::{NodeDuty, OutgoingMsg},
    Error, Result,
};
use log::{debug, info};
use sn_data_types::{
    Credit, NodeAge, PublicKey, RewardAccumulation, RewardProposal, Signature, Signing, Token,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeSystemCmd},
    Aggregation, DstLocation, MessageId,
};
use std::collections::BTreeMap;
use xor_name::{Prefix, XorName};

///
#[derive(Clone)]
pub struct RewardProcess {
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
    pub fn new(section: OurSection, signing: ElderSigning) -> Self {
        Self {
            section,
            signing,
            stage: RewardStage::AwaitingThreshold,
        }
    }

    pub fn stage(&self) -> &RewardStage {
        &self.stage
    }

    /// Calculates reward for each node
    /// proportional to the age of it,
    /// out of the total payments received.
    /// Additionally adds newly minted tokens, unless max supply has been reached.
    pub async fn reward_and_mint(
        &mut self,
        payments: Token,
        section_managed: Token,
        our_nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
    ) -> Result<NodeDuty> {
        // Max supply is the proportional supply for a section in a network of a certain size.
        // The network size is derived from the prefix len.
        let max_supply =
            Token::from_nano(MAX_SUPPLY / 2_u64.pow(self.section.our_prefix.bit_count() as u32));
        // derive an amount to pay out in rewards, i.e. payments + newly minted tokens
        let rewards = get_reward_and_mint_amount(payments, section_managed, max_supply);
        // generate proposal
        let reward_credits = self.get_reward_credits(rewards, self.section.our_key, our_nodes);
        let proposal_details = self.sign_proposed_rewards(reward_credits).await?;
        let proposal = proposal_details
            .get_proposal(self.section.wallet_key(), self.signing.our_index().await?);

        self.stage = RewardStage::ProposingCredits(proposal_details.clone());
        Ok(send_prop_msg(proposal, self.section.address()))
    }

    async fn sign_proposed_rewards(
        &self,
        rewards: Vec<CreditProposal>,
    ) -> Result<RewardProposalDetails> {
        let mut proposal = RewardProposalDetails {
            rewards: BTreeMap::new(),
            pk_set: self.signing.public_key_set().await?,
        };
        for credit in rewards {
            let _ = proposal.rewards.insert(*credit.id(), credit);
        }
        for (_, credit) in proposal.rewards.clone() {
            let share = match self.signing.sign(&credit.proposal)? {
                Signature::BlsShare(share) => share,
                _ => return Err(Error::ChurnSignError),
            };
            proposal.add_sig(credit.id(), &share)?;
        }
        Ok(proposal)
    }

    async fn sign_accumulating_rewards(
        &self,
        rewards: Vec<CreditAccumulation>,
    ) -> Result<RewardAccumulationDetails> {
        let mut accumulation = RewardAccumulationDetails {
            pk_set: self.signing.public_key_set().await?,
            rewards: BTreeMap::new(),
        };
        for acc in rewards {
            let _ = accumulation.rewards.insert(*acc.id(), acc);
        }
        for (_, credit) in accumulation.rewards.clone() {
            let share = match self.signing.sign(&credit.agreed_proposal)? {
                Signature::BlsShare(share) => share,
                _ => return Err(Error::ChurnSignError),
            };
            accumulation.add_sig(credit.id(), &share)?;
        }
        Ok(accumulation)
    }

    fn get_reward_credits(
        &self,
        rewards: Token,
        section_key: PublicKey,
        nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
    ) -> Vec<CreditProposal> {
        // create reward distribution
        distribute_rewards(rewards, nodes)
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
                    signatures: BTreeMap::new(),
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
            RewardStage::AwaitingThreshold => {
                debug!("@ receive_churn_proposal when RewardStage::None | RewardStage::AwaitingThreshold");
                let rewards = proposal
                    .rewards
                    .iter()
                    .map(|share| CreditProposal {
                        proposal: share.credit.clone(),
                        signatures: BTreeMap::new(),
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
                    let rewards = rewards
                        .into_iter()
                        .map(|(_, signed_credit)| CreditAccumulation {
                            agreed_proposal: signed_credit,
                            signatures: BTreeMap::new(),
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
                        signatures: BTreeMap::new(),
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
            RewardStage::ProposingCredits(_proposal_details) => {
                // TODO: validate on existing proposal details?
                let rewards = new_acc
                    .rewards
                    .iter()
                    .map(|reward| CreditAccumulation {
                        agreed_proposal: reward.signed_credit.clone(),
                        signatures: BTreeMap::new(),
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
        }
    }
}

fn send_prop_msg(proposal: RewardProposal, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeRewardPayout(proposal)),
            id: MessageId::new(),
            target_section_pk: None,
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}

fn send_acc_msg(accumulation: RewardAccumulation, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateRewardPayout(accumulation)),
            id: MessageId::new(),
            target_section_pk: None,
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}
