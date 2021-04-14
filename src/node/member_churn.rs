// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    metadata::{adult_reader::AdultReader, Metadata},
    node::{ElderRole, Role},
    node_ops::NodeDuty,
    section_funds::{reward_wallets::RewardWallets, SectionFunds},
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

impl Node {
    /// If we are an oldie we'll have a transfer instance,
    /// This updates the replica info on it.
    pub async fn update_replicas(&mut self) -> Result<()> {
        let elder = self.role.as_elder_mut()?;
        let info = replica_info(&self.node_info, &self.network_api).await?;
        elder.transfers.update_replica_info(info);
        Ok(())
    }

    /// Level up a newbie to an oldie on promotion
    pub async fn level_up(&mut self) -> Result<()> {
        self.used_space.reset().await; // TODO(drusu): should this be part of adult_state?

        //
        // start handling metadata
        let dbs = ChunkHolderDbs::new(self.node_info.path())?;
        let reader = AdultReader::new(self.network_api.clone());
        let meta_data =
            Metadata::new(&self.node_info.path(), &self.used_space, dbs, reader).await?;

        //
        // start handling transfers
        let dbs = ChunkHolderDbs::new(self.node_info.root_dir.as_path())?;
        let rate_limit = RateLimit::new(self.network_api.clone(), Capacity::new(dbs.clone()));
        let user_wallets = BTreeMap::<PublicKey, ActorHistory>::new();
        let replicas = transfer_replicas(&self.node_info, &self.network_api, user_wallets).await?;
        let transfers = Transfers::new(replicas, rate_limit);

        //
        // start handling node rewards
        let section_funds = SectionFunds::KeepingNodeWallets {
            wallets: RewardWallets::new(BTreeMap::<XorName, (NodeAge, PublicKey)>::new()),
            payments: DashMap::new(),
        };

        self.role = Role::Elder(ElderRole {
            meta_data,
            transfers,
            section_funds,
        });

        // TODO(drusu): return a  mutable reference to elder state?
        Ok(())
    }

    /// Continue the level up and handle more responsibilities.
    pub async fn synch_state(
        &mut self,
        node_wallets: BTreeMap<XorName, (NodeAge, PublicKey)>,
        user_wallets: BTreeMap<PublicKey, ActorHistory>,
    ) -> Result<NodeDuty> {
        let elder = self.role.as_elder_mut()?;

        // merge in provided user wallets
        elder.transfers.merge(user_wallets);

        //  merge in provided node reward stages
        for (key, (age, wallet)) in &node_wallets {
            elder.section_funds.set_node_wallet(*key, *wallet, *age)
        }

        let node_id = self.network_api.our_name().await;
        let no_wallet_found = node_wallets.get(&node_id).is_none();
        if no_wallet_found {
            info!(
                "Registering wallet of node: {} (since not found in received state)",
                node_id,
            );
            Ok(NodeDuty::Send(self.register_wallet().await))
        } else {
            Ok(NodeDuty::NoOp)
        }
    }
}
