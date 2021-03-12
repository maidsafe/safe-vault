// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// mod adult_duties;
// mod elder_duties;
// mod node_duties;
pub mod data_section;
pub mod key_section;
mod node_ops;
pub mod state_db;
use crdts::Actor;
use serde::Serialize;
mod genesis;
mod handle_msg;
mod messaging;
mod work;

use hex_fmt::HexFmt;

use crate::{
    chunk_store::UsedSpace,
    node::{
        data_section::{DataSection, RewardData},
        genesis::GenesisStage,
        key_section::transfers::replica_signing::ReplicaSigningImpl,
        key_section::WalletSection,
        messaging::Messaging,
        node_ops::{NetworkDuties, NodeDuty, NodeMessagingDuty, OutgoingMsg},
        state_db::{get_age_group, store_age_group, store_new_reward_keypair, AgeGroup},
    },
    Config, Error, Network, Result,
};
use bls::SecretKey;
// use handle_msg::handle_msg;
use log::{debug, error, info, trace};
use sn_data_types::{
    ActorHistory, Credit, NodeRewardStage, PublicKey, ReplicaPublicKeySet, Signature,
    SignatureShare, SignedCredit, Token, TransferPropagated, WalletInfo,
};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use std::collections::BTreeMap;
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

use ed25519_dalek::PublicKey as Ed25519PublicKey;

use sn_messaging::{
    client::TransientElderKey,
    client::{Message, MsgSender, NodeCmd, NodeSystemCmd},
    Aggregation, DstLocation, MessageId,
};

use futures::lock::Mutex;
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use std::sync::Arc;

use std::path::{Path, PathBuf};

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
    // pub wallet_section: WalletSection
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
    // duties: NodeDuties,
    messaging: Messaging,
    network_api: Network,
    network_events: EventStream,
    node_info: NodeInfo,

    // old adult
    // prefix: Prefix,
    // node_name: XorName,
    // node_id: Ed25519PublicKey,
    // section_chain: SectionChain,
    // elders: Vec<(XorName, SocketAddr)>,
    // adult_reader: AdultReader,
    // node_signing: NodeSigning,

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
    genesis_stage: Arc<Mutex<GenesisStage>>,

    pub wallet_section: Arc<Mutex<Option<WalletSection>>>,
    // rate_limit: RateLimit,
    // dbs: ChunkHolderDbs
    // replica_signing: ReplicaSigningImpl,
}

impl Node {
    /// Initialize a new node.
    pub async fn new(config: &Config) -> Result<Self> {
        /// TODO: STARTUP all things
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

        let messaging = Messaging::new(network_api.clone());

        debug!("NEW NODE after messaging");

        let node = Self {
            prefix: Some(network_api.our_prefix().await),
            node_name: network_api.our_name().await,
            node_id: network_api.public_key().await,

            // interaction: NodeInteraction::new(network_api.clone()),
            node_info,

            network_api,
            network_events,
            messaging,

            genesis_stage: Arc::new(Mutex::new(GenesisStage::None)),

            wallet_section: Arc::new(Mutex::new(None)),
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
            self.process_network_event(event).await?
        }

        Ok(())
    }

    /// Process any routing event
    pub async fn process_network_event(&mut self, event: RoutingEvent) -> Result<()> {
        trace!("Processing Routing Event: {:?}", event);
        match event {
            RoutingEvent::Genesis => self.begin_forming_genesis_section().await,
            RoutingEvent::MemberLeft { name, age } => {
                debug!("TODO: A node has left the section. Node: {:?}", name);

                // //self.log_node_counts().await;
                // Ok(NetworkDuties::from(ProcessLostMember {
                //     name: XorName(name.0),
                //     age,
                // }))
                Ok(())
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
                    return Ok(());
                }

                info!("TODO: New member has joined the section");

                Ok(())
                // //self.log_node_counts().await;
                // if let Some(prev_name) = previous_name {
                //     trace!("The new member is a Relocated Node");
                //     let first = NetworkDuty::from(ProcessRelocatedMember {
                //         old_node_id: XorName(prev_name.0),
                //         new_node_id: XorName(name.0),
                //         age,
                //     });

                //     // Switch joins_allowed off a new adult joining.
                //     //let second = NetworkDuty::from(SwitchNodeJoin(false));
                //     Ok(vec![first]) // , second
                // } else {
                //     //trace!("New node has just joined the network and is a fresh node.",);
                //     Ok(NetworkDuties::from(ProcessNewMember(XorName(name.0))))
                // }
            }
            RoutingEvent::ClientMessageReceived { msg, user } => {
                info!(
                    "TODO: Received client message: {:8?}\n Sent from {:?}",
                    msg, user
                );
                Ok(())

                // self.analysis.evaluate(
                //     *msg,
                //     SrcLocation::EndUser(user),
                //     DstLocation::Node(self.analysis.name()),
                // )
            }
            RoutingEvent::MessageReceived { content, src, dst } => {
                info!(
                    "Received network message: {:8?}\n Sent from {:?} to {:?}",
                    HexFmt(&content),
                    src,
                    dst
                );
                self.handle_msg(Message::from(content)?, src, dst).await?;

                // ERR -> LAZY

                Ok(())
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
                        Ok(())
                    }
                    NodeElderChange::Promoted => {
                        if self.is_forming_genesis().await {
                            // Ok(NetworkDuties::from(NodeDuty::BeginFormingGenesisSection))
                            self.begin_forming_genesis_section().await

                            // Ok(())
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
                            Ok(())
                        }
                    }
                    NodeElderChange::Demoted => {
                        //TODO: Demotion
                        debug!("TODO: demotion");
                        // NetworkDuties::from(NodeDuty::AssumeAdultDuties)
                        Ok(())
                    }
                }?;

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

                Ok(())
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
                Ok(())
                // else {
                //     info!("Our AGE: {:?}", age);
                //     Ok(vec![])
                // }
            }
            // Ignore all other events
            _ => Ok(()),
            // _ => Ok(vec![]),
        }
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
