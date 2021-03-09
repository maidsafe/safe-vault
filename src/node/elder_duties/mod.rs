// // Copyright 2021 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// // Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// // under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// // KIND, either express or implied. Please review the Licences for the specific language governing
// // permissions and limitations relating to use of the SAFE Network Software.

// mod data_section;
// mod key_section;

// use self::{
//     data_section::{DataSection, RewardData},
//     key_section::WalletSection,
// };
// use crate::{
//     capacity::{Capacity, ChunkHolderDbs, RateLimit},
//     node::node_ops::{ElderDuty, NetworkDuties},
//     node::RewardsAndWallets, NodeInfo, Result,
// };
// use log::trace;
// use sn_data_types::{ActorHistory, NodeRewardStage, PublicKey, TransferPropagated, WalletInfo};
// use sn_routing::Prefix;
// use std::{
//     collections::BTreeMap,
//     fmt::{self, Display, Formatter},
// };
// use xor_name::XorName;

// /// Duties carried out by an Elder node.
// pub struct ElderDuties {
//     state: RewardsAndWallets,
//     wallet_section: WalletSection,
//     data_section: DataSection,
// }

// #[derive(Debug)]
// pub struct RewardsAndWallets {
//     pub section_wallet: WalletInfo,
//     pub node_rewards: BTreeMap<XorName, NodeRewardStage>,
//     pub user_wallets: BTreeMap<PublicKey, ActorHistory>,
// }

// impl ElderDuties {
//     pub async fn new(
//         node_info: &NodeInfo,
//         rewards_and_wallets: RewardsAndWallets,
//         data: RewardsAndWallets,
//     ) -> Result<Self> {
//         trace!("Elder data: {:?}", data);
//         let dbs = ChunkHolderDbs::new(node_info.path())?;
//         let rate_limit = RateLimit::new(rewards_and_wallets.clone(), Capacity::new(dbs.clone()));
//         let wallet_section = WalletSection::new(
//             rate_limit,
//             node_info,
//             rewards_and_wallets.clone(),
//             data.user_wallets,
//         )
//         .await?;
//         let data_section = DataSection::new(
//             node_info,
//             dbs,
//             rewards_and_wallets.clone(),
//             RewardData {
//                 section_wallet: data.section_wallet,
//                 node_rewards: data.node_rewards,
//             },
//         )
//         .await?;
//         Ok(Self {
//             state: rewards_and_wallets,
//             wallet_section,
//             data_section,
//         })
//     }

//     ///
//     pub fn state(&self) -> &RewardsAndWallets {
//         &self.state
//     }

//     ///
//     pub fn section_wallet(&self) -> WalletInfo {
//         self.data_section.section_wallet()
//     }

//     ///
//     pub fn node_rewards(&self) -> BTreeMap<XorName, NodeRewardStage> {
//         self.data_section.node_rewards()
//     }

//     ///
//     pub fn user_wallets(&self) -> BTreeMap<PublicKey, ActorHistory> {
//         self.wallet_section.user_wallets()
//     }

//     /// Initiates genesis
//     pub async fn initiate(&mut self, genesis: Option<TransferPropagated>) -> Result<()> {
//         if let Some(genesis) = genesis {
//             // if we are genesis
//             // does local init, with no roundrip via network messaging
//             self.wallet_section.init_genesis_node(genesis).await?;
//         }
//         Ok(())
//     }

//     /// Processing of any Elder duty.
//     pub async fn process_elder_duty(&mut self, duty: ElderDuty) -> Result<NetworkDuties> {
//         //trace!("Processing elder duty: {:?}", duty);
//         use ElderDuty::*;
//         match duty {
//             ProcessNewMember(name) => self.new_node_joined(name).await,
//             ProcessLostMember { name, age } => self.member_left(name, age).await,
//             ProcessRelocatedMember {
//                 old_node_id,
//                 new_node_id,
//                 age,
//             } => {
//                 self.relocated_node_joined(old_node_id, new_node_id, age)
//                     .await
//             }
//             RunAsKeySection(the_key_duty) => {
//                 self.wallet_section
//                     .process_key_section_duty(the_key_duty)
//                     .await
//             }
//             RunAsDataSection(duty) => self.data_section.process_data_section_duty(duty).await,
//             StorageFull { node_id } => self.increase_full_node_count(node_id).await,
//             SwitchNodeJoin(joins_allowed) => {
//                 self.wallet_section
//                     .set_node_join_flag(joins_allowed)
//                     .await?;
//                 Ok(vec![])
//             }
//             NoOp => Ok(vec![]),
//         }
//     }

//     ///
//     async fn new_node_joined(&mut self, name: XorName) -> Result<NetworkDuties> {
//         self.data_section.new_node_joined(name).await
//     }

//     async fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<NetworkDuties> {
//         self.wallet_section
//             .increase_full_node_count(node_id)
//             .await
//             .map(|()| vec![])
//     }

//     ///
//     async fn relocated_node_joined(
//         &mut self,
//         old_node_id: XorName,
//         new_node_id: XorName,
//         age: u8,
//     ) -> Result<NetworkDuties> {
//         self.data_section
//             .relocated_node_joined(old_node_id, new_node_id, age)
//             .await
//     }

//     ///
//     async fn member_left(&mut self, node_id: XorName, age: u8) -> Result<NetworkDuties> {
//         self.data_section.member_left(node_id, age).await
//     }

//     ///
//     pub async fn perform_elder_change_updates(
//         &mut self,
//         rewards_and_wallets: RewardsAndWallets,
//         sibling_key: Option<PublicKey>,
//     ) -> Result<NetworkDuties> {
//         // 1. First we must update data section..
//         self.data_section
//             .initiate_elder_change(rewards_and_wallets, sibling_key)
//             .await
//     }

//     ///
//     pub async fn complete_elder_change(
//         &mut self,
//         node_info: &NodeInfo,
//         state: RewardsAndWallets,
//     ) -> Result<()> {
//         // 2. Then we must update key section..
//         let dbs = ChunkHolderDbs::new(node_info.path())?;
//         let rate_limit = RateLimit::new(state.clone(), Capacity::new(dbs));
//         self.wallet_section.elders_changed(state, rate_limit);
//         // TODO: self.data_section.update_rewards_and_wallets
//         Ok(())
//     }

//     ///
//     pub async fn split_section(&mut self, prefix: Prefix) -> Result<NetworkDuties> {
//         self.wallet_section.split_section(prefix).await?;
//         self.data_section.split_section(prefix).await
//     }
// }

// impl Display for ElderDuties {
//     fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
//         write!(formatter, "ElderDuties")
//     }
// }
