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
    section_funds::{rewarding_wallet::RewardingWallet, SectionFunds},
    state_db::store_new_reward_keypair,
    transfers::get_replicas::transfer_replicas,
    transfers::Transfers,
    Node, Result,
};
use sn_data_types::{ActorHistory, PublicKey, TransferPropagated};
use std::collections::BTreeMap;

impl Node {
    /// Level up and handle more responsibilities.
    pub async fn level_up(&mut self, genesis_tx: Option<TransferPropagated>) -> Result<()> {
        // metadata
        let dbs = ChunkHolderDbs::new(self.node_info.path())?;
        let reader = AdultReader::new(self.network_api.clone());
        let meta_data =
            Metadata::new(&self.node_info.path(), &self.used_space, dbs, reader).await?;
        self.meta_data = Some(meta_data);

        // transfers
        let dbs = ChunkHolderDbs::new(self.node_info.root_dir.as_path())?;
        let rate_limit = RateLimit::new(self.network_api.clone(), Capacity::new(dbs.clone()));
        let user_wallets = BTreeMap::<PublicKey, ActorHistory>::new();
        let replicas =
            transfer_replicas(&self.node_info, self.network_api.clone(), user_wallets).await?;
        let transfers = Transfers::new(replicas, rate_limit);
        // does local init, with no roundrip via network messaging
        if let Some(genesis_tx) = genesis_tx {
            transfers.genesis(genesis_tx.clone()).await?;
        }
        self.transfers = Some(transfers);

        // rewards
        // let actor = TransferActor::from_info(signing, reward_data.section_wallet, Validator {})?;
        // let wallet = RewardingWallet::new(actor);
        // self.section_funds = Some(SectionFunds::Rewarding(wallet));
        Ok(())
    }
}
