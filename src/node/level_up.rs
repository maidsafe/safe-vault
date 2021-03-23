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
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
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
use log::{debug, info};
use sn_data_types::{
    ActorHistory, CreditAgreementProof, NodeRewardStage, PublicKey, SectionElders,
    TransferPropagated, WalletHistory,
};
use sn_messaging::{
    client::{NodeCmd, NodeSystemCmd, ProcessMsg},
    Aggregation, DstLocation, MessageId,
};
use sn_routing::XorName;
use sn_transfers::TransferActor;
use std::collections::BTreeMap;

impl Node {
    /// Level up and handle more responsibilities.
    pub async fn genesis(&mut self, genesis_tx: CreditAgreementProof) -> Result<NodeDuty> {
        if let Some(SectionFunds::Rewarding(_)) = &self.section_funds {
            // already had genesis..
            return Ok(NodeDuty::NoOp);
        }

        //
        self.level_up().await?;

        // does local init, with no roundrip via network messaging
        if let Some(transfers) = &mut self.transfers {
            transfers
                .genesis(TransferPropagated {
                    credit_proof: genesis_tx.clone(),
                })
                .await?;
        }

        //
        // start handling node reward
        let section_wallet = WalletHistory {
            replicas: section_elders(&self.network_api).await?,
            history: ActorHistory {
                credits: vec![genesis_tx],
                debits: vec![],
            },
        };
        let node_rewards = BTreeMap::<XorName, NodeRewardStage>::new();
        self.set_as_rewarding(section_wallet, node_rewards).await?;

        Ok(NodeDuty::Send(self.register_wallet().await))
    }

    /// Level up on promotion
    pub async fn level_up(&mut self) -> Result<()> {
        //
        // do not hande immutable chunks anymore
        self.chunks = None;
        self.used_space.reset().await;

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
        let replicas = transfer_replicas(&self.node_info, &self.network_api, user_wallets).await?;
        self.transfers = Some(Transfers::new(replicas, rate_limit));
        Ok(())
    }

    /// Continue the level up and handle more responsibilities.
    pub async fn synch_state(
        &mut self,
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    ) -> Result<NodeDuty> {
        // merge in provided user wallets
        if let Some(transfers) = &mut self.transfers {
            transfers.merge(user_wallets)
        }

        //  merge in provided node reward stages
        match &mut self.section_funds {
            Some(SectionFunds::Rewarding(rewards))
            | Some(SectionFunds::Churning { rewards, .. }) => {
                // TODO: more needed here
                rewards.merge(node_rewards.clone());
            }
            None => {
                return Err(Error::InvalidOperation(
                    "Invalid section funds stage".to_string(),
                ))
            }
        }

        let node_id = self.network_api.our_name().await;
        let no_wallet_found = match node_rewards.get(&node_id) {
            None => true,
            Some(stage) => match stage {
                NodeRewardStage::NewNode | NodeRewardStage::AwaitingActivation(_) => true,
                NodeRewardStage::Active { .. } | NodeRewardStage::AwaitingRelocation(_) => false,
            },
        };
        if no_wallet_found {
            info!(
                "Registering wallet of node: {} (since not found in {:?})",
                node_id, node_rewards
            );
            Ok(NodeDuty::Send(self.register_wallet().await))
        } else {
            Ok(NodeDuty::NoOp)
        }
    }

    async fn set_as_rewarding(
        &mut self,
        section_wallet: WalletHistory,
        node_rewards: BTreeMap<XorName, NodeRewardStage>,
    ) -> Result<()> {
        let members = section_elders(&self.network_api).await?;
        let signing = ElderSigning::new(self.network_api.clone()).await?;
        let actor = TransferActor::from_info(signing, section_wallet, Validator {})?;
        info!(
            "COMPLETED({}): We got our new section wallet synched to us!",
            PublicKey::Bls(members.key())
        );
        let payout = RewardPayout::new(actor, members);
        let reward_calc = RewardCalc::new(self.network_api.our_prefix().await);
        let stages = RewardStages::new(node_rewards);
        let rewards = Rewards::new(payout, stages, reward_calc);
        self.section_funds = Some(SectionFunds::Rewarding(rewards));
        Ok(())
    }
}

pub async fn section_elders(network_api: &crate::Network) -> Result<SectionElders> {
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    Ok(SectionElders {
        prefix: network_api.our_prefix().await,
        names: network_api.our_elder_names().await,
        key_set: network_api.our_public_key_set().await?,
    })
}
