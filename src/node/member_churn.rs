// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::role::{ElderRole, Role};
use crate::{
    capacity::{AdultsStorageInfo, Capacity, CapacityReader, CapacityWriter, StoreCost},
    metadata::{adult_reader::AdultReader, Metadata},
    network::Network,
    node_ops::NodeDuty,
    section_funds::{reward_wallets::RewardWallets, SectionFunds},
    transfers::{
        get_replicas::{replica_info, transfer_replicas},
        Transfers,
    },
    Node, Result,
};
use log::info;
use sn_data_types::{ActorHistory, NodeAge, PublicKey};
use sn_messaging::client::DataExchange;
use sn_routing::XorName;
use std::collections::BTreeMap;

impl Node {
    /// If we are an oldie we'll have a transfer instance,
    /// This updates the replica info on it.
    pub(crate) async fn update_replicas(elder: &ElderRole, network: &Network) -> Result<()> {
        let info = replica_info(network).await?;
        elder.transfers.write().await.update_replica_info(info);
        Ok(())
    }

    /// Level up a newbie to an oldie on promotion
    pub async fn level_up(&mut self) -> Result<()> {
        self.used_space.reset().await?;

        let adult_storage_info = AdultsStorageInfo::new();
        let adult_reader = AdultReader::new(self.network_api.clone());
        let capacity_reader = CapacityReader::new(adult_storage_info.clone(), adult_reader.clone());
        let capacity_writer = CapacityWriter::new(adult_storage_info.clone(), adult_reader.clone());
        let capacity = Capacity::new(capacity_reader.clone(), capacity_writer);

        //
        // start handling metadata
        let max_capacity = self.used_space.max_capacity().await;
        let meta_data =
            Metadata::new(&self.node_info.path(), max_capacity, capacity.clone()).await?;

        //
        // start handling transfers
        let store_cost = StoreCost::new(self.network_api.clone(), capacity_reader);
        let user_wallets = BTreeMap::<PublicKey, ActorHistory>::new();
        let replicas = transfer_replicas(&self.node_info, &self.network_api, user_wallets).await?;
        let transfers = Transfers::new(replicas, store_cost);

        //
        // start handling node rewards
        let section_funds = SectionFunds::KeepingNodeWallets(RewardWallets::new(BTreeMap::<
            XorName,
            (NodeAge, PublicKey),
        >::new()));

        self.role = Role::Elder(ElderRole::new(meta_data, transfers, section_funds, false));

        Ok(())
    }

    /// Continue the level up and handle more responsibilities.
    pub(crate) async fn synch_state(
        elder: &ElderRole,
        reward_key: PublicKey,
        network_api: &Network,
        node_wallets: BTreeMap<XorName, (NodeAge, PublicKey)>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
        metadata: DataExchange,
    ) -> Result<NodeDuty> {
        if *elder.received_initial_sync.read().await {
            info!("We are already received the initial sync from our section. Ignoring update");
            return Ok(NodeDuty::NoOp);
        }

        // --------- merge in provided user wallets ---------
        elder.transfers.write().await.merge(user_wallets).await?;
        // --------- merge in provided node reward stages ---------
        for (key, (age, wallet)) in &node_wallets {
            elder
                .section_funds
                .write()
                .await
                .set_node_wallet(*key, *wallet, *age)
        }
        // --------- merge in provided metadata ---------
        elder.meta_data.write().await.update(metadata).await?;

        *elder.received_initial_sync.write().await = true;

        let node_id = network_api.our_name().await;
        let no_wallet_found = node_wallets.get(&node_id).is_none();

        if no_wallet_found {
            info!(
                "Registering wallet of node: {} (since not found in received state)",
                node_id,
            );
            Ok(NodeDuty::Send(
                Self::register_wallet(network_api, reward_key).await,
            ))
        } else {
            Ok(NodeDuty::NoOp)
        }
    }
}
