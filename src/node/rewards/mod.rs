// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod churning_wallet;
mod elder_signing;
mod rewarding_wallet;

use self::{
    churning_wallet::{ChurningWallet, SectionWallet},
    rewarding_wallet::{RewardingWallet, Validator},
};
use sn_data_types::Token;

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
pub(super) enum SectionWalletStage {
    Rewarding(RewardingWallet),
    SoonChurning {
        current: SectionWallet,
        balance: Token,
    },
    Churning(ChurningWallet),
}
