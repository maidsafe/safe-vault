// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod elder_signing;
mod reward_calc;
pub mod reward_process;
pub mod reward_stage;
pub mod reward_wallets;

use self::{reward_process::RewardProcess, reward_wallets::RewardWallets};
use crate::{Error, Result};
use dashmap::DashMap;
use log::info;
use sn_data_types::{CreditAgreementProof, CreditId, NodeAge, PublicKey, Token};
use sn_messaging::client::ProcessMsg;
use sn_routing::XorName;
use std::collections::BTreeMap;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
#[allow(clippy::large_enum_variant)]
pub enum SectionFunds {
    KeepingNodeWallets {
        wallets: RewardWallets,
        payments: Payments,
    },
    Churning {
        process: RewardProcess,
        wallets: RewardWallets,
        payments: Payments,
    },
}

impl SectionFunds {
    pub fn as_churning_mut(
        &mut self,
    ) -> Result<(&mut RewardProcess, &mut RewardWallets, &mut Payments)> {
        match self {
            Self::Churning {
                process,
                wallets,
                payments,
            } => Ok((process, wallets, payments)),
            _ => Err(Error::NotChurningFunds),
        }
    }

    /// Adds payment
    pub fn add_payment(&self, credit: CreditAgreementProof) {
        // todo: validate
        match &self {
            Self::Churning { payments, .. } | Self::KeepingNodeWallets { payments, .. } => {
                let _ = payments.insert(*credit.id(), credit);
            }
        }
    }

    /// Returns registered wallet key of a node.
    #[allow(unused)]
    pub fn get_node_wallet(&self, node_name: &XorName) -> Option<PublicKey> {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                let (_, key) = wallets.get(node_name)?;
                Some(key)
            }
        }
    }

    /// Returns node wallet keys of registered nodes.
    pub fn node_wallets(&self) -> BTreeMap<XorName, (NodeAge, PublicKey)> {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                wallets.node_wallets()
            }
        }
    }

    /// Nodes register/updates wallets for future reward payouts.
    pub fn set_node_wallet(&self, node_id: XorName, wallet: PublicKey, age: u8) {
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                wallets.set_node_wallet(node_id, age, wallet)
            }
        }
    }

    /// When the section becomes aware that a node has left,
    /// its reward key is removed.
    pub fn remove_node_wallet(&self, node_name: XorName) {
        info!("Removing node wallet");
        match &self {
            Self::Churning { wallets, .. } | Self::KeepingNodeWallets { wallets, .. } => {
                wallets.remove_wallet(node_name)
            }
        }
    }
}

type Payments = DashMap<CreditId, CreditAgreementProof>;
type Rewards = BTreeMap<CreditId, CreditAgreementProof>;

pub trait Credits {
    fn sum(&self) -> Token;
}

impl Credits for Payments {
    fn sum(&self) -> Token {
        Token::from_nano(self.iter().map(|c| (*c).amount().as_nano()).sum())
    }
}

impl Credits for Rewards {
    fn sum(&self) -> Token {
        Token::from_nano(self.iter().map(|(_, c)| c.amount().as_nano()).sum())
    }
}
