// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod handle_msg;
mod messaging;
mod metadata;
mod transfers;
mod work;

pub(crate) mod node_ops;
pub mod state_db;

use crate::{
    capacity::ChunkHolderDbs,
    chunk_store::UsedSpace,
    node::{
        handle_msg::handle,
        messaging::send,
        state_db::store_new_reward_keypair,
        work::{genesis::begin_forming_genesis_section, genesis_stage::GenesisStage},
    },
    Config, Error, Network, Result,
};
use bls::SecretKey;
use hex_fmt::HexFmt;
// use handle_msg::handle_msg;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use futures::lock::Mutex;
use log::{debug, error, info, trace};
use sn_data_types::{ActorHistory, NodeRewardStage, PublicKey, WalletInfo};
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

use self::{
    messaging::send_to_nodes,
    metadata::{adult_reader::AdultReader, Metadata},
    node_ops::{NodeDuties, NodeDuty},
    transfers::Transfers,
};

/// Info about the node.
#[derive(Clone)]
pub struct NodeInfo {
    ///
    pub genesis: bool,
    ///
    pub root_dir: PathBuf,
    ///
    pub used_space: UsedSpace,
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
    // data operations
    meta_data: Metadata,
    //old elder
    prefix: Option<Prefix>,
    node_name: XorName,
    node_id: Ed25519PublicKey,
    // key_index: usize,
    // public_key_set: ReplicaPublicKeySet,
    // sibling_public_key: Option<PublicKey>,
    // section_chain: SectionChain,
    // elders: Vec<(XorName, SocketAddr)>,
    // adult_reader: AdultReader,
    // interaction: NodeInteraction,
    // node_signing: NodeSigning,
    genesis_stage: GenesisStage,
    transfers: Arc<Mutex<Option<Transfers>>>,
    // rate_limit: RateLimit,
    // dbs: ChunkHolderDbs
    // replica_signing: ReplicaSigningImpl,
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
            used_space: UsedSpace::new(config.max_capacity()),
            reward_key,
            // wallet_section
        };

        debug!("NEW NODE after messaging");

        let dbs = ChunkHolderDbs::new(node_info.path())?;
        let reader = AdultReader::new(network_api.clone());
        let meta_data = Metadata::new(&node_info, dbs, reader).await?;

        let node = Self {
            prefix: Some(network_api.our_prefix().await),
            node_name: network_api.our_name().await,
            node_id: network_api.public_key().await,
            // interaction: NodeInteraction::new(network_api.clone()),
            node_info,
            network_api,
            network_events,
            genesis_stage: GenesisStage::None,
            transfers: Arc::new(Mutex::new(None)),
            meta_data,
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
            let node_duties = self.process_network_event(event).await;
            self.process_while_any(node_duties).await;
        }

        Ok(())
    }

    /// Keeps processing resulting node operations.
    async fn process_while_any(&mut self, ops_vec: Result<NodeDuties>) {
        let mut next_ops = ops_vec;

        while let Ok(ops) = next_ops {
            let mut pending_node_ops = Vec::new();

            if !ops.is_empty() {
                for duty in ops {
                    match self.handle_node_duty(duty).await {
                        Ok(new_ops) => pending_node_ops.extend(new_ops),
                        Err(e) => self.handle_error(&e),
                    };
                }
                next_ops = Ok(pending_node_ops);
            } else {
                break;
            }
        }
    }

    /// Process any routing event
    pub async fn process_network_event(&mut self, event: RoutingEvent) -> Result<NodeDuties> {
        trace!("Processing Routing Event: {:?}", event);
        match event {
            RoutingEvent::Genesis => Ok(vec![NodeDuty::BeginFormingGenesisSection]),
            RoutingEvent::MemberLeft { name, age } => {
                debug!("A node has left the section. Node: {:?}", name);
                Ok(vec![NodeDuty::ProcessLostMember {
                    name: XorName(name.0),
                    age,
                }])
            }
            RoutingEvent::MemberJoined {
                name,
                previous_name,
                age,
                ..
            } => {
                if self.is_forming_genesis().await {
                    // during formation of genesis we do not process this event
                    debug!("Forming genesis so ignore new member");
                    return Ok(vec![]);
                }

                info!("New member has joined the section");

                //self.log_node_counts().await;
                if let Some(prev_name) = previous_name {
                    trace!("The new member is a Relocated Node");
                    let first = NodeDuty::ProcessRelocatedMember {
                        old_node_id: XorName(prev_name.0),
                        new_node_id: XorName(name.0),
                        age,
                    };

                    // Switch joins_allowed off a new adult joining.
                    //let second = NetworkDuty::from(SwitchNodeJoin(false));
                    Ok(vec![first]) // , second
                } else {
                    //trace!("New node has just joined the network and is a fresh node.",);
                    Ok(vec![NodeDuty::ProcessNewMember(XorName(name.0))])
                }
            }
            RoutingEvent::ClientMessageReceived { msg, user } => {
                info!(
                    "TODO: Received client message: {:8?}\n Sent from {:?}",
                    msg, user
                );
                handle(
                    *msg,
                    SrcLocation::EndUser(user),
                    DstLocation::Node(self.network_api.our_name().await),
                )
                .await
            }
            RoutingEvent::MessageReceived { content, src, dst } => {
                info!(
                    "Received network message: {:8?}\n Sent from {:?} to {:?}",
                    HexFmt(&content),
                    src,
                    dst
                );
                handle(Message::from(content)?, src, dst).await
                // ERR -> LAZY
            }
            RoutingEvent::EldersChanged {
                key,
                elders,
                prefix,
                self_status_change,
                sibling_key,
            } => {
                trace!("******Elders changed event!");
                // let mut duties: NetworkDuties =
                match self_status_change {
                    NodeElderChange::None => {
                        // do nothing
                    }
                    NodeElderChange::Promoted => {
                        if self.is_forming_genesis().await {
                            return Ok(vec![NodeDuty::BeginFormingGenesisSection]);
                        } else {
                            // After genesis section formation, any new Elder will be informed
                            // by its peers of data required.
                            // It may also request this if missing.
                            // For now we start with defaults
                            debug!("TODO: FINISH ELDER MAKING");
                            // unimplemented!("PROMOTED");

                            // Ok(NetworkDuties::from(NodeDuty::CompleteTransitionToElder{
                            //     node_rewards: Default::default(),
                            //     section_wallet: WalletInfo {
                            //         replicas:  network_api.public_key_set().await?,
                            //         history: ActorHistory{
                            //             credits: vec![],
                            //             debits: vec![]
                            //         }
                            //     },
                            //     user_wallets: Default::default()
                            // }))
                        }
                    }
                    NodeElderChange::Demoted => {
                        //TODO: Demotion
                        debug!("TODO: demotion");
                        // NetworkDuties::from(NodeDuty::AssumeAdultDuties)
                    }
                };

                let mut sibling_pk = None;
                if let Some(pk) = sibling_key {
                    sibling_pk = Some(PublicKey::Bls(pk));
                }
                // TODO: Update elder info.

                // duties.push(NetworkDuty::from(NodeDuty::UpdateElderInfo {
                //     prefix,
                //     key: PublicKey::Bls(key),
                //     elders: elders.into_iter().map(|e| XorName(e.0)).collect(),
                //     sibling_key: sibling_pk,
                // }));

                // Ok(duties)

                Ok(vec![])
            }
            RoutingEvent::Relocated { .. } => {
                // Check our current status
                let age = self.network_api.age().await;
                if age > MIN_AGE {
                    info!("Node promoted to Adult");
                    info!("Our Age: {:?}", age);
                    // return Ok(())
                    // Ok(NetworkDuties::from(NodeDuty::AssumeAdultDuties))
                }
                Ok(vec![])
            }
            // Ignore all other events
            _ => Ok(vec![]),
        }
    }

    async fn handle_node_duty(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        match duty {
            NodeDuty::GetSectionElders { msg_id, origin } => {}
            NodeDuty::BeginFormingGenesisSection => {
                self.genesis_stage =
                    begin_forming_genesis_section(self.network_api.clone()).await?;
            }
            NodeDuty::ReceiveGenesisProposal { credit, sig } => {}
            NodeDuty::ReceiveGenesisAccumulation { signed_credit, sig } => {}
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
                return Ok(vec![self.meta_data.read(query, id, origin).await?]);
            }
            NodeDuty::ProcessWrite { cmd, id, origin } => {
                return Ok(vec![self.meta_data.write(cmd, id, origin).await?]);
            }
            NodeDuty::NoOp => {}
        }
        Ok(vec![])
    }

    fn handle_error(&self, err: &Error) {
        use std::error::Error;
        info!(
            "unimplemented: Handle errors. This should be return w/ lazyError to sender. {}",
            err
        );

        if let Some(source) = err.source() {
            error!("Source of error: {:?}", source);
        }
    }

    /// Are we forming the genesis?
    async fn is_forming_genesis(&self) -> bool {
        let is_genesis_section = self.network_api.our_prefix().await.is_empty();
        let elder_count = self.network_api.our_elder_names().await.len();
        let section_chain_len = self.network_api.section_chain().await.len();
        is_genesis_section
            && elder_count <= GENESIS_ELDER_COUNT
            && section_chain_len <= GENESIS_ELDER_COUNT
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
