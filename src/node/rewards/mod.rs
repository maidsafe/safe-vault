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


pub fn query_for_new_replicas(new_wallet: PublicKey) -> NodeMessagingDuty {
    // deterministic msg id for aggregation
    let msg_id = MessageId::combine(vec![new_wallet.into()]);
    NodeMessagingDuty::Send(OutgoingMsg {
        msg: Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id: msg_id,
            target_section_pk: None,
        },
        section_source: true,
        dst: DstLocation::Section(new_wallet.into()),
        aggregation: Aggregation::AtDestination,
    })
}
