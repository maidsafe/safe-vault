// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{handle::DutyHandler, interaction::register_wallet};
use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    metadata::{adult_reader::AdultReader, Metadata},
    network::Network,
    node_ops::NodeDuty,
    section_funds::{reward_wallets::RewardWallets, SectionFunds},
    state::ElderStateCommand,
    state::State,
    transfers::{
        get_replicas::{replica_info, transfer_replicas},
        Transfers,
    },
    Error, Node, Result,
};
use crdts::Actor;
use dashmap::DashMap;
use itertools::Itertools;
use log::{debug, info};
use sn_data_types::{
    ActorHistory, CreditAgreementProof, NodeAge, PublicKey, SectionElders, TransferPropagated,
    WalletHistory,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeSystemCmd},
    Aggregation, DstLocation, MessageId,
};
use sn_routing::XorName;
use std::collections::BTreeMap;

impl DutyHandler {
    /// If we are an oldie we'll have a transfer instance,
    /// This updates the replica info on it.
    pub(crate) async fn update_replicas(&mut self) -> Result<()> {
        let info = replica_info(&self.network_api).await?;
        let _ = self
            .state
            .elder_command(ElderStateCommand::UpdateReplicaInfo(info))
            .await?;
        Ok(())
    }

    // Level up a newbie to an oldie on promotion
    pub(crate) async fn level_up(&mut self) -> Result<()> {
        self.state.reset_used_space().await; // TODO(drusu): should this be part of adult_state?

        // start handling metadata
        let node_root_dir = self.state.node_root_dir().await;
        let dbs = ChunkHolderDbs::new(node_root_dir.as_path())?;
        let reader = AdultReader::new(self.network_api.clone());
        let used_space = self.state.used_space().await;
        let meta_data = Metadata::new(node_root_dir.as_path(), used_space, dbs, reader).await?;

        // start handling transfers
        let node_root_dir = self.state.node_root_dir().await;
        let dbs = ChunkHolderDbs::new(node_root_dir.as_path())?;
        let rate_limit = RateLimit::new(self.network_api.clone(), Capacity::new(dbs.clone()));
        let user_wallets = BTreeMap::<PublicKey, ActorHistory>::new();
        let replicas = transfer_replicas(node_root_dir, &self.network_api, user_wallets).await?;
        let transfers = Transfers::new(replicas, rate_limit);

        // start handling node rewards
        let section_funds = SectionFunds::KeepingNodeWallets {
            wallets: RewardWallets::new(BTreeMap::<XorName, (NodeAge, PublicKey)>::new()),
            payments: DashMap::new(),
        };

        self.state
            .set_elder_role(meta_data, transfers, section_funds)
            .await;

        Ok(())
    }

    /// Continue the level up and handle more responsibilities.
    pub(crate) async fn synch_state(
        &mut self,
        node_wallets: BTreeMap<XorName, (NodeAge, PublicKey)>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    ) -> Result<NodeDuty> {
        // merge in provided user wallets
        let _ = self
            .state
            .elder_command(ElderStateCommand::MergeUserWallets(user_wallets))
            .await?;

        let node_id = self.network_api.our_name().await;
        let no_wallet_found = node_wallets.get(&node_id).is_none();

        //  merge in provided node reward stages
        let _ = self
            .state
            .elder_command(ElderStateCommand::SetNodeRewardsWallets(node_wallets))
            .await?;

        if no_wallet_found {
            info!(
                "Registering wallet of node: {} (since not found in received state)",
                node_id,
            );
            Ok(NodeDuty::Send(
                register_wallet(&self.network_api, &self.state).await,
            ))
        } else {
            Ok(NodeDuty::NoOp)
        }
    }
}
