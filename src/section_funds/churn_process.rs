// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeMap;

use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Error, Result,
};
use log::{debug, info, warn};
use sn_data_types::{
    Credit, PublicKey, SectionElders, Signature, SignatureShare, SignedCredit, Signing, Token,
    TransferPropagated,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, NodeSystemCmd, NodeSystemQuery},
    Aggregation, DstLocation, MessageId,
};
use sn_routing::Elders;
use xor_name::XorName;

use super::{
    elder_signing::ElderSigning,
    section_wallet::SectionWallet,
    wallet_stage::{WalletAccumulation, WalletProposal, WalletStage},
};

///
#[derive(Clone)]
pub struct ChurnProcess {
    balance: Token,
    churn: Churn,
    stage: WalletStage,
    signing: ElderSigning,
}

///
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Churn {
    /// Contains next section Elders/Wallet.
    Regular(Elders),
    /// Contains the new children Elders/Wallets.
    Split {
        ///
        our_elders: Elders,
        ///
        sibling_elders: Elders,
    },
}

impl Churn {
    pub fn wallet_key(&self) -> PublicKey {
        match self {
            Self::Regular(our_elders) | Self::Split { our_elders, .. } => our_elders.key(),
        }
    }

    pub fn wallet_name(&self) -> XorName {
        self.wallet_key().into()
    }

    pub fn our_elders(&self) -> &Elders {
        match self {
            Self::Regular(our_elders) | Self::Split { our_elders, .. } => our_elders,
        }
    }
}

impl ChurnProcess {
    pub fn new(balance: Token, churn: Churn, signing: ElderSigning) -> Self {
        Self {
            balance,
            churn,
            signing,
            stage: WalletStage::AwaitingWalletThreshold,
        }
    }

    pub fn our_elders(&self) -> &Elders {
        self.churn.our_elders()
    }

    pub fn stage(&self) -> &WalletStage {
        &self.stage
    }

    /// Move Wallet
    pub async fn move_wallet(&mut self) -> Result<NodeDuty> {
        match self.churn.clone() {
            Churn::Regular(_next) => self.propose_wallet_creation(self.balance).await,
            Churn::Split {
                our_elders,
                sibling_elders,
            } => {
                // Split the tokens of current actor.
                let half_balance = self.balance.as_nano() / 2;
                let remainder = self.balance.as_nano() % 2;

                // create two transfers; one to each sibling wallet
                let t1_amount = Token::from_nano(half_balance + remainder);
                let t2_amount = Token::from_nano(half_balance);

                // Determine which transfer is first
                // (deterministic order is important for reaching consensus)
                if our_elders.key() > sibling_elders.key() {
                    self.propose_wallet_creation(t1_amount).await
                } else {
                    self.propose_wallet_creation(t2_amount).await
                }
            }
        }
    }

    /// Generates msgs for creation of new section wallet.
    async fn propose_wallet_creation(
        &mut self,
        amount: Token,
    ) -> Result<NodeDuty> {
        let our_elders = self.churn.our_elders();
        let id = MessageId::combine(vec![our_elders.address(), our_elders.name()])
            .0
             .0;

        let credit = Credit {
            id,
            amount,
            recipient: our_elders.key(),
            msg: "New section wallet".to_string(),
        };

        let mut bootstrap = WalletProposal {
            proposal: credit.clone(),
            pk_set: self.signing.public_key_set().await?,
            signatures: Default::default(),
            pending_agreement: None,
        };

        let share = match self.signing.sign(&credit)? {
            Signature::BlsShare(share) => {
                bootstrap.add(share.clone())?;
                share
            }
            _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
        };

        self.stage = WalletStage::ProposingWallet(bootstrap);

        Ok(send_prop_msg(
            credit.clone(),
            share,
            self.churn.our_elders().address(),
        ))
    }

    // TODO: validate the credit...
    pub async fn receive_wallet_proposal(
        &mut self,
        credit: Credit,
        sig: SignatureShare,
    ) -> Result<NodeDuty> {
        if credit.recipient() != self.churn.wallet_key() {
            return Err(Error::Transfer(sn_transfers::Error::CreditDoesNotBelong(
                self.churn.wallet_key(),
                credit,
            )));
        }
        match self.stage.clone() {
            WalletStage::None | WalletStage::AwaitingWalletThreshold => {
                let mut bootstrap = WalletProposal {
                    proposal: credit.clone(),
                    signatures: Default::default(),
                    pending_agreement: None,
                    pk_set: self.signing.public_key_set().await?,
                };

                bootstrap.add(sig)?;

                let share = match self.signing.sign(&credit)? {
                    Signature::BlsShare(share) => {
                        bootstrap.add(share.clone())?;
                        share
                    }
                    _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
                };

                self.stage = WalletStage::ProposingWallet(bootstrap);

                Ok(send_prop_msg(
                    credit.clone(),
                    share,
                    self.churn.our_elders().address(),
                ))
            }
            WalletStage::ProposingWallet(mut bootstrap) => {
                bootstrap.add(sig)?;

                if let Some(signed_credit) = &bootstrap.pending_agreement {
                    info!(
                        "******* there is an agreement for wallet proposal (newbie?: {}).",
                        self.balance == Token::zero()
                    );
                    // replicas signatures over > signed_credit <
                    let mut bootstrap = WalletAccumulation {
                        agreed_proposal: signed_credit.clone(),
                        signatures: Default::default(),
                        pending_agreement: None,
                        pk_set: bootstrap.pk_set,
                    };

                    let share = match self.signing.sign(signed_credit)? {
                        Signature::BlsShare(share) => {
                            bootstrap.add(share.clone())?;
                            share
                        }
                        _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
                    };

                    self.stage = WalletStage::AccumulatingWallet(bootstrap);

                    Ok(send_acc_msg(
                        signed_credit.clone(),
                        share,
                        self.churn.our_elders().address(),
                    ))
                } else {
                    self.stage = WalletStage::ProposingWallet(bootstrap);
                    Ok(NodeDuty::NoOp)
                }
            }
            WalletStage::AccumulatingWallet(_) => Ok(NodeDuty::NoOp),
            WalletStage::Completed(_) => Ok(NodeDuty::NoOp),
            WalletStage::None => Err(Error::InvalidGenesisStage),
        }
    }

    /// Receive wallet accumulation
    pub async fn receive_wallet_accumulation(
        &mut self,
        signed_credit: SignedCredit,
        sig: SignatureShare,
    ) -> Result<NodeDuty> {
        if signed_credit.recipient() != self.churn.wallet_key() {
            return Err(Error::Transfer(sn_transfers::Error::CreditDoesNotBelong(
                self.churn.wallet_key(),
                signed_credit.credit,
            )));
        }
        match self.stage.clone() {
            WalletStage::AwaitingWalletThreshold => {
                // replicas signatures over > signed_credit <
                let mut bootstrap = WalletAccumulation {
                    agreed_proposal: signed_credit.clone(),
                    signatures: Default::default(),
                    pending_agreement: None,
                    pk_set: self.signing.public_key_set().await?,
                };

                bootstrap.add(sig)?;

                let share = match self.signing.sign(&signed_credit)? {
                    Signature::BlsShare(share) => {
                        bootstrap.add(share.clone())?;
                        share
                    }
                    _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
                };

                self.stage = WalletStage::AccumulatingWallet(bootstrap);

                Ok(send_acc_msg(
                    signed_credit,
                    share,
                    self.churn.our_elders().address(),
                ))
            }
            WalletStage::ProposingWallet(bootstrap) => {
                // replicas signatures over > signed_credit <
                let mut bootstrap = WalletAccumulation {
                    agreed_proposal: signed_credit.clone(),
                    signatures: Default::default(),
                    pending_agreement: None,
                    pk_set: bootstrap.pk_set,
                };

                bootstrap.add(sig)?;

                let share = match self.signing.sign(&signed_credit)? {
                    Signature::BlsShare(share) => {
                        bootstrap.add(share.clone())?;
                        share
                    }
                    _ => return Err(Error::InvalidOperation("aarrgh".to_string())),
                };

                self.stage = WalletStage::AccumulatingWallet(bootstrap);

                Ok(send_acc_msg(
                    signed_credit,
                    share,
                    self.churn.our_elders().address(),
                ))
            }
            WalletStage::AccumulatingWallet(mut bootstrap) => {
                bootstrap.add(sig)?;
                if let Some(credit_proof) = bootstrap.pending_agreement {
                    info!(
                        "******* there is an agreement for wallet accumulation (newbie?: {}).",
                        self.balance == Token::zero()
                    );
                    self.stage = WalletStage::Completed(credit_proof);
                } else {
                    self.stage = WalletStage::AccumulatingWallet(bootstrap);
                }
                Ok(NodeDuty::NoOp)
            }
            WalletStage::Completed(_) => Ok(NodeDuty::NoOp),
            WalletStage::None => Err(Error::InvalidGenesisStage),
        }
    }
}

fn send_prop_msg(credit: Credit, sig: SignatureShare, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::ProposeNewWallet { credit, sig }),
            id: MessageId::new(),
            target_section_pk: None,
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}

fn send_acc_msg(signed_credit: SignedCredit, sig: SignatureShare, our_elders: XorName) -> NodeDuty {
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::AccumulateNewWallet { signed_credit, sig }),
            id: MessageId::new(),
            target_section_pk: None,
        },
        section_source: false,                 // sent as single node
        dst: DstLocation::Section(our_elders), // send this msg to our elders!
        aggregation: Aggregation::None,
    })
}
