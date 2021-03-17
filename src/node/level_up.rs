// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::genesis_stage::GenesisStage;
use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    event_mapping::{map_routing_event, LazyError, Mapping, MsgContext},
    metadata::{adult_reader::AdultReader, Metadata},
    node_ops::{NodeDuties, NodeDuty},
    section_funds::{
        elder_signing::ElderSigning,
        reward_payout::{RewardPayout, Validator},
        reward_stages::RewardStages,
        rewards::{RewardCalc, Rewards},
        SectionFunds,
    },
    state_db::store_new_reward_keypair,
    transfers::get_replicas::transfer_replicas,
    transfers::Transfers,
    Error, Node, Result,
};
use crdts::Actor;
use itertools::Itertools;
use log::info;
use sn_data_types::{
    ActorHistory, NodeRewardStage, PublicKey, SectionElders, TransferPropagated, WalletHistory,
};
use sn_routing::XorName;
use sn_transfers::TransferActor;
use std::collections::BTreeMap;

pub struct NextLevelInfo {
    pub section_wallet: WalletHistory,
    pub node_rewards: BTreeMap<XorName, NodeRewardStage>,
    pub user_wallets: BTreeMap<PublicKey, ActorHistory>,
}

impl Node {
    /// Level up and handle more responsibilities.
    pub async fn level_up(&mut self, genesis_tx: Option<TransferPropagated>) -> Result<()> {
        //
        // do not hande immutable chunks anymore
        self.chunks = None;

        //
        // start handling metadata
        let dbs = ChunkHolderDbs::new(self.node_info.path())?;
        let reader = AdultReader::new(self.network_api.clone());
        let meta_data =
            Metadata::new(&self.node_info.path(), &self.used_space, dbs, reader).await?;
        self.meta_data = Some(meta_data);

        //
        // start handling transfers
        let dbs = ChunkHolderDbs::new(self.node_info.root_dir.as_path())?;
        let rate_limit = RateLimit::new(self.network_api.clone(), Capacity::new(dbs.clone()));
        let user_wallets = BTreeMap::<PublicKey, ActorHistory>::new();
        let replicas =
            transfer_replicas(&self.node_info, self.network_api.clone(), user_wallets).await?;
        let transfers = Transfers::new(replicas, rate_limit);
        // does local init, with no roundrip via network messaging
        if let Some(genesis_tx) = &genesis_tx {
            transfers.genesis(genesis_tx.clone()).await?;
        }
        self.transfers = Some(transfers);

        //
        // start handling node reward stages
        let node_rewards = BTreeMap::<XorName, NodeRewardStage>::new();
        if let Some(genesis_tx) = genesis_tx {
            self.set_rewards(
                WalletHistory {
                    replicas: section_elders(&self.network_api).await?,
                    history: ActorHistory::empty(),
                },
                node_rewards,
            )
            .await
        } else {
            let stages = RewardStages::new(node_rewards);
            self.section_funds = Some(SectionFunds::TakingNodes(stages));
            Ok(())
        }
    }

    /// Continue the level up and handle more responsibilities.
    pub async fn continue_level_up(
        &mut self,
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    ) -> Result<()> {
        // merge in provided user wallets
        if let Some(transfers) = &mut self.transfers {
            transfers.merge(user_wallets)
        }

        //
        // start handling reward payouts
        if let Some(SectionFunds::Rewarding(rewards)) = &mut self.section_funds {
            // TODO: more needed here
            rewards.merge(node_rewards);
            Ok(())
        } else if let Some(SectionFunds::TakingNodes(stages)) = &self.section_funds {
            let mut existing_stages = stages.node_rewards();
            existing_stages.extend(node_rewards); // TODO: fix this!
            let stages = RewardStages::new(existing_stages);
            self.section_funds = Some(SectionFunds::TakingNodes(stages));
            Ok(())
        } else {
            Err(Error::InvalidOperation(
                "Invalid section funds stage, expected SectionFunds::TakingNodes".to_string(),
            ))
        }
    }

    /// Complete the level up and handle more responsibilities.
    pub async fn complete_level_up(&mut self, section_wallet: WalletHistory) -> Result<()> {
        if let Some(SectionFunds::Rewarding(_)) = &self.section_funds {
            return Err(Error::InvalidOperation(
                "Invalid section funds stage, expected SectionFunds::TakingNodes".to_string(),
            ));
        }
        // start handling reward payouts
        let node_rewards = if let Some(section_funds) = &self.section_funds {
            section_funds.node_rewards()
        } else if self.network_api.is_elder().await {
            Default::default()
        } else {
            return Err(Error::InvalidOperation(
                "No section funds at this replica".to_string(),
            ));
        };

        self.set_rewards(section_wallet, node_rewards).await
    }

    async fn set_rewards(
        &mut self,
        section_wallet: WalletHistory,
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
    ) -> Result<()> {
        let members = section_elders(&self.network_api).await?;
        let signing = ElderSigning::new(self.network_api.clone()).await?;
        let actor = TransferActor::from_info(signing, section_wallet, Validator {})?;
        let payout = RewardPayout::new(actor, members);
        let reward_calc = RewardCalc::new(self.network_api.our_prefix().await);
        let stages = RewardStages::new(node_rewards);
        let rewards = Rewards::new(payout, stages, reward_calc);
        self.section_funds = Some(SectionFunds::Rewarding(rewards));
        Ok(())
    }
}

async fn section_elders(network_api: &crate::Network) -> Result<SectionElders> {
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    Ok(SectionElders {
        prefix: network_api.our_prefix().await,
        names: network_api.our_elder_names().await,
        key_set: network_api.our_public_key_set().await?,
    })
}
