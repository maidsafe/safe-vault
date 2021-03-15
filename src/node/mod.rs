// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod mapping;
mod messaging;
mod metadata;
mod section_funds;
mod transfers;
mod work;

pub(crate) mod node_ops;
pub mod state_db;

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    chunk_store::UsedSpace,
    Config, Error, Network, Result,
};
use bls::SecretKey;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use futures::lock::Mutex;
use hex_fmt::HexFmt;
use log::{debug, error, info, trace};
use sn_data_types::{ActorHistory, NodeRewardStage, PublicKey, TransferPropagated, WalletInfo};
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use sn_transfers::{TransferActor, Wallet};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

use self::{
    mapping::map_routing_event,
    messaging::send,
    messaging::send_to_nodes,
    metadata::{adult_reader::AdultReader, Metadata},
    node_ops::{NodeDuties, NodeDuty},
    section_funds::{rewarding_wallet::RewardingWallet, SectionFunds},
    state_db::store_new_reward_keypair,
    transfers::get_replicas::transfer_replicas,
    transfers::Transfers,
    work::{
        genesis::begin_forming_genesis_section, genesis::receive_genesis_accumulation,
        genesis::receive_genesis_proposal, genesis_stage::GenesisStage,
    },
};

/// Static info about the node.
#[derive(Clone)]
pub struct NodeInfo {
    ///
    pub genesis: bool,
    ///
    pub root_dir: PathBuf,
    ///
    pub node_name: XorName,
    ///
    pub node_id: Ed25519PublicKey,
    /// The key used by the node to receive earned rewards.
    pub reward_key: PublicKey,
}

impl NodeInfo {
    ///
    pub fn path(&self) -> &Path {
        self.root_dir.as_path()
    }
}

#[derive(Debug, Clone)]
pub struct RewardsAndWallets {
    pub section_wallet: Arc<Mutex<WalletInfo>>,
    pub node_rewards: Arc<Mutex<BTreeMap<XorName, NodeRewardStage>>>,
    pub user_wallets: Arc<Mutex<BTreeMap<PublicKey, ActorHistory>>>,
}

impl RewardsAndWallets {
    fn new(section_wallet: WalletInfo) -> Self {
        Self {
            section_wallet: Arc::new(Mutex::new(section_wallet)),
            node_rewards: Default::default(),
            user_wallets: Default::default(),
        }
    }
}

/// Main node struct.
pub struct Node {
    network_api: Network,
    network_events: EventStream,
    node_info: NodeInfo,
    used_space: UsedSpace,
    prefix: Option<Prefix>,
    genesis_stage: GenesisStage,
    // data operations
    meta_data: Option<Metadata>,
    // transfers
    transfers: Option<Transfers>,
    // reward payouts
    section_funds: Option<SectionFunds>,
}

impl Node {
    /// Initialize a new node.
    pub async fn new(config: &Config) -> Result<Self> {
        // TODO: STARTUP all things
        let root_dir_buf = config.root_dir()?;
        let root_dir = root_dir_buf.as_path();
        std::fs::create_dir_all(root_dir)?;

        debug!("NEW NODE");
        let reward_key_task = async move {
            let res: Result<PublicKey>;
            match config.wallet_id() {
                Some(public_key) => {
                    res = Ok(PublicKey::Bls(state_db::pk_from_hex(public_key)?));
                }
                None => {
                    let secret = SecretKey::random();
                    let public = secret.public_key();
                    store_new_reward_keypair(root_dir, &secret, &public).await?;
                    res = Ok(PublicKey::Bls(public));
                }
            };
            res
        }
        .await;

        let reward_key = reward_key_task?;
        debug!("NEW NODE after reward key");
        let (network_api, network_events) = Network::new(config).await?;

        // TODO: This should be general setup tbh..

        let node_info = NodeInfo {
            genesis: config.is_first(),
            root_dir: root_dir_buf,
            node_name: network_api.our_name().await,
            node_id: network_api.public_key().await,
            reward_key,
        };

        debug!("NEW NODE after messaging");

        let node = Self {
            prefix: Some(network_api.our_prefix().await),
            node_info,
            used_space: UsedSpace::new(config.max_capacity()),
            network_api,
            network_events,
            genesis_stage: GenesisStage::None,
            meta_data: None,
            transfers: None,
            section_funds: None,
        };

        Ok(node)
    }

    /// Returns our connection info.
    pub async fn our_connection_info(&mut self) -> SocketAddr {
        self.network_api.our_connection_info().await
    }

    /// Returns whether routing node is in elder state.
    pub async fn is_elder(&self) -> bool {
        self.network_api.is_elder().await
    }

    /// Starts the node, and runs the main event loop.
    /// Blocks until the node is terminated, which is done
    /// by client sending in a `Command` to free it.
    pub async fn run(&mut self) -> Result<()> {
        // TODO: setup all the bits we need here:

        //let info = self.network_api.our_connection_info().await;
        //info!("Listening for routing events at: {}", info);
        while let Some(event) = self.network_events.next().await {
            // tokio spawn should only be needed around intensive tasks, ie sign/verify
            let node_duties = map_routing_event(event, self.network_api.clone()).await;
            self.process_while_any(node_duties).await;
        }

        Ok(())
    }

    /// Keeps processing resulting node operations.
    async fn process_while_any(&mut self, ops_vec: Result<NodeDuties>) {
        let mut next_ops = ops_vec;

        if let Ok(ops) = next_ops {
            let mut pending_node_ops = Vec::new();

            for duty in ops {
                match self.handle_node_duty(duty).await {
                    Ok(new_ops) => pending_node_ops.extend(new_ops),
                    Err(e) => handle_error(&e),
                };
            }
            next_ops = Ok(pending_node_ops);
        }
    }

    async fn handle_node_duty(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        match duty {
            NodeDuty::GetSectionElders { msg_id, origin } => {}
            NodeDuty::BeginFormingGenesisSection => {
                self.genesis_stage =
                    begin_forming_genesis_section(self.network_api.clone()).await?;
            }
            NodeDuty::ReceiveGenesisProposal { credit, sig } => {
                self.genesis_stage = receive_genesis_proposal(
                    credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
            }
            NodeDuty::ReceiveGenesisAccumulation { signed_credit, sig } => {
                self.genesis_stage = receive_genesis_accumulation(
                    signed_credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
                let genesis_tx = match &self.genesis_stage {
                    GenesisStage::Completed(genesis_tx) => genesis_tx.clone(),
                    _ => return Ok(vec![]),
                };
                self.level_up(Some(genesis_tx)).await?;
            }
            NodeDuty::LevelUp => {
                self.level_up(None).await?;
            }
            NodeDuty::LevelDown => {
                self.meta_data = None;
                self.transfers = None;
                self.section_funds = None;
            }
            NodeDuty::AssumeAdultDuties => {}
            NodeDuty::UpdateElderInfo {
                prefix,
                key,
                elders,
                sibling_key,
            } => {}
            NodeDuty::CompleteElderChange {
                previous_key,
                new_key,
            } => {}
            NodeDuty::InformNewElders => {}
            NodeDuty::CompleteTransitionToElder {
                section_wallet,
                node_rewards,
                user_wallets,
            } => {}
            NodeDuty::ProcessNewMember(_) => {}
            NodeDuty::ProcessLostMember { name, age } => {}
            NodeDuty::ProcessRelocatedMember {
                old_node_id,
                new_node_id,
                age,
            } => {}
            NodeDuty::ReachingMaxCapacity => {}
            NodeDuty::IncrementFullNodeCount { node_id } => {}
            NodeDuty::SwitchNodeJoin(_) => {}
            NodeDuty::Send(msg) => send(msg, self.network_api.clone()).await?,
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, self.network_api.clone()).await?
            }
            NodeDuty::ProcessRead { query, id, origin } => {
                if let Some(ref meta_data) = self.meta_data {
                    return Ok(vec![meta_data.read(query, id, origin).await?]);
                }
            }
            NodeDuty::ProcessWrite { cmd, id, origin } => {
                if let Some(ref mut meta_data) = self.meta_data {
                    return Ok(vec![meta_data.write(cmd, id, origin).await?]);
                }
            }
            NodeDuty::NoOp => {}
        }
        Ok(vec![])
    }

    async fn level_up(&mut self, genesis_tx: Option<TransferPropagated>) -> Result<()> {
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

fn handle_error(err: &Error) {
    use std::error::Error;
    info!(
        "unimplemented: Handle errors. This should be return w/ lazyError to sender. {}",
        err
    );

    if let Some(source) = err.source() {
        error!("Source of error: {:?}", source);
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
