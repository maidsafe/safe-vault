// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod churning_wallet;
pub mod elder_signing;
mod reward_calc;
pub mod reward_payout;
pub mod reward_stages;
pub mod rewards;

use self::{
    churning_wallet::{ChurningWallet, SectionWallet},
    reward_payout::RewardPayout,
    reward_stages::RewardStages,
    rewards::Rewards,
};
use super::node_ops::{NodeDuty, OutgoingMsg};
use sn_data_types::{PublicKey, Token};
use sn_messaging::{
    client::{Message, NodeQuery, NodeSystemQuery},
    Aggregation, DstLocation, MessageId,
};

/// The management of section funds,
/// via the usage of a distributed AT2 Actor.
#[allow(clippy::large_enum_variant)]
pub enum SectionFunds {
    // not yet able to do payouts
    TakingNodes(RewardStages),
    // can do payouts
    Rewarding(Rewards),
    // in transition and cannot do payouts
    SoonChurning {
        current: SectionWallet,
        balance: Token,
    },
    // in transition and cannot do payouts
    Churning(ChurningWallet),
}

pub fn query_for_replicas(wallet: PublicKey) -> NodeDuty {
    // deterministic msg id for aggregation
    let msg_id = MessageId::combine(vec![wallet.into()]);
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id: msg_id,
            target_section_pk: None,
        },
        section_source: true,
        dst: DstLocation::Section(wallet.into()),
        aggregation: Aggregation::AtDestination,
    })
}

//     let to_remove = self
//         .rewards
//         .all_nodes()
//         .into_iter()
//         .filter(|c| !prefix.matches(&XorName(c.0)))
//         .collect();
//     self.rewards.remove(to_remove);

// ///
// pub fn section_wallet(&self) -> WalletInfo {
//     self.rewards.section_wallet()
// }

// ///
// pub fn node_rewards(&self) -> BTreeMap<XorName, NodeRewardStage> {
//     self.rewards.node_rewards()
// }

// /// Issues query to Elders of the section
// /// as to catch up with the current state of the replicas.
// pub async fn catchup_with_section(&mut self) -> Result<NetworkDuties> {
//     let prefix_name = self.rewards_and_wallets().prefix().name();
//     self.rewards
//         .get_section_wallet_history(prefix_name)
//         .await
// }

// /// Transition the section funds account to the new key.
// pub async fn initiate_elder_change(
//     &mut self,
//     rewards_and_wallets: RewardsAndWallets,
//     sibling_key: Option<PublicKey>,
// ) -> Result<NetworkDuties> {
//     info!(">> Processing Elder change in data section");
//     // TODO: Query sn_routing for info for [new_section_key]
//     // specifically (regardless of how far back that was) - i.e. not the current info!

//     // if we were demoted, we should not call this at all,
//     // make sure demoted is handled properly first, so that
//     // EldersChanged doesn't lead to calling this method..

//     self.rewards
//         .init_wallet_transition(rewards_and_wallets, sibling_key)
//         .await
// }

// /// At section split, all Elders get their reward payout.
// pub async fn reward_elders(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
// let elders = self.rewards_and_wallets.elder_names();
// self.rewards.payout_rewards(elders).await
// }

// /// When a new node joins, it is registered for receiving rewards.
// pub async fn new_node_joined(&mut self, id: XorName) -> Result<NetworkDuties> {
//     let node_name = self.network.our_name().await;
//     self.rewards
//         .process_reward_duty(RewardDuty::ProcessCmd {
//             cmd: RewardCmd::AddNewNode(id),
//             msg_id: MessageId::new(),
//             origin: SrcLocation::Node(node_name),
//         })
//         .await
// }

// /// When a relocated node joins, a DataSection
// /// has a few different things to do, such as
// /// pay out rewards and trigger chunk replication.
// pub async fn relocated_node_joined(
//     &mut self,
//     old_node_id: XorName,
//     new_node_id: XorName,
//     age: u8,
// ) -> Result<NetworkDuties> {
//     // Adds the relocated account.
//     let node_name = self.network.our_name().await;
//     self.rewards
//         .process_reward_duty(RewardDuty::ProcessCmd {
//             cmd: RewardCmd::AddRelocatingNode {
//                 old_node_id,
//                 new_node_id,
//                 age,
//             },
//             msg_id: MessageId::new(),
//             origin: SrcLocation::Node(node_name),
//         })
//         .await
// }

// /// Name of the node
// /// Age of the node
// pub async fn member_left(&mut self, node_id: XorName, _age: u8) -> Result<NetworkDuties> {
//     let node_name = self.network.our_name().await;
//     let mut duties = self
//         .rewards
//         .process_reward_duty(RewardDuty::ProcessCmd {
//             cmd: RewardCmd::DeactivateNode(node_id),
//             msg_id: MessageId::new(),
//             origin: SrcLocation::Node(node_name),
//         })
//         .await?;
//     duties.extend(self.metadata.trigger_chunk_replication(node_id).await?);
//     Ok(duties)
// }
