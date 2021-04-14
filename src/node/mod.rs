// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod handle;
mod interaction;
mod member_churn;
mod messaging;
mod split;

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    chunk_store::UsedSpace,
    chunks::Chunks,
    event_mapping::{map_routing_event, LazyError, Mapping, MsgContext},
    metadata::{adult_reader::AdultReader, Metadata},
    network::Network,
    node_ops::{NodeDuties, NodeDuty},
    section_funds::SectionFunds,
    state_db::store_new_reward_keypair,
    transfers::{get_replicas::transfer_replicas, Transfers},
    Config, Error, Result,
};
use bls::SecretKey;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use futures::lock::Mutex;
use hex_fmt::HexFmt;
use log::{debug, error, info, trace, warn};
use sn_data_types::{ActorHistory, PublicKey, TransferPropagated, WalletHistory};
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

struct AdultRole {
    // immutable chunks
    chunks: Chunks,
}

struct ElderRole {
    // data operations
    meta_data: Metadata,
    // transfers
    transfers: Transfers,
    // reward payouts
    section_funds: SectionFunds,
}

#[allow(clippy::large_enum_variant)]
enum Role {
    Adult(AdultRole),
    Elder(ElderRole),
}

impl Role {
    fn as_adult(&self) -> Result<&AdultRole> {
        match self {
            Self::Adult(adult_state) => Ok(adult_state),
            _ => Err(Error::NotAnAdult),
        }
    }

    fn as_adult_mut(&mut self) -> Result<&mut AdultRole> {
        match self {
            Self::Adult(adult_state) => Ok(adult_state),
            _ => Err(Error::NotAnAdult),
        }
    }

    fn as_elder(&self) -> Result<&ElderRole> {
        match self {
            Self::Elder(elder_state) => Ok(elder_state),
            _ => Err(Error::NotAnElder),
        }
    }

    fn as_elder_mut(&mut self) -> Result<&mut ElderRole> {
        match self {
            Self::Elder(elder_state) => Ok(elder_state),
            _ => Err(Error::NotAnElder),
        }
    }
}

/// Main node struct.
pub struct Node {
    network_api: Network,
    network_events: EventStream,
    node_info: NodeInfo,
    used_space: UsedSpace,
    prefix: Prefix,
    role: Role,
}

impl Node {
    /// Initialize a new node.
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub async fn new(config: &Config) -> Result<Self> {
        // TODO: STARTUP all things
        let root_dir_buf = config.root_dir()?;
        let root_dir = root_dir_buf.as_path();
        std::fs::create_dir_all(root_dir)?;

        let reward_key_task = async move {
            let res: Result<PublicKey>;
            match config.wallet_id() {
                Some(public_key) => {
                    res = Ok(PublicKey::Bls(crate::state_db::pk_from_hex(public_key)?));
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
        let (network_api, network_events) = Network::new(config).await?;

        let node_info = NodeInfo {
            genesis: config.is_first(),
            root_dir: root_dir_buf,
            node_name: network_api.our_name().await,
            node_id: network_api.public_key().await,
            reward_key,
        };

        let used_space = UsedSpace::new(config.max_capacity());

        let node = Self {
            prefix: network_api.our_prefix().await,
            role: Role::Adult(AdultRole {
                chunks: Chunks::new(
                    node_info.node_name,
                    node_info.root_dir.as_path(),
                    used_space.clone(),
                )
                .await?,
            }),
            node_info,
            used_space,
            network_api,
            network_events,
        };

        messaging::send(node.register_wallet().await, &node.network_api).await;

        Ok(node)
    }

    /// Returns our connection info.
    pub fn our_connection_info(&mut self) -> SocketAddr {
        self.network_api.our_connection_info()
    }

    /// Returns our name.
    pub async fn our_name(&mut self) -> XorName {
        self.network_api.our_name().await
    }

    /// Returns our prefix.
    pub async fn our_prefix(&mut self) -> Prefix {
        self.network_api.our_prefix().await
    }

    /// Starts the node, and runs the main event loop.
    /// Blocks until the node is terminated, which is done
    /// by client sending in a `Command` to free it.
    pub async fn run(&mut self) -> Result<()> {
        while let Some(event) = self.network_events.next().await {
            // tokio spawn should only be needed around intensive tasks, ie sign/verify
            match map_routing_event(event, &self.network_api).await {
                Mapping::Ok { op, ctx } => self.process_while_any(op, ctx).await,
                Mapping::Error(error) => handle_error(error),
            }
        }

        Ok(())
    }

    /// Keeps processing resulting node operations.
    async fn process_while_any(&mut self, op: NodeDuty, ctx: Option<MsgContext>) {
        let mut next_ops = vec![op];

        while !next_ops.is_empty() {
            let mut pending_node_ops: Vec<NodeDuty> = vec![];
            for duty in next_ops {
                match self.handle(duty).await {
                    Ok(new_ops) => pending_node_ops.extend(new_ops),
                    Err(e) => try_handle_error(e, ctx.clone()),
                };
            }
            next_ops = pending_node_ops;
        }
    }
}

fn handle_error(err: LazyError) {
    use std::error::Error;
    info!(
        "unimplemented: Handle errors. This should be return w/ lazyError to sender. {:?}",
        err
    );

    if let Some(source) = err.error.source() {
        error!("Source of error: {:?}", source);
    }
}

fn try_handle_error(err: Error, ctx: Option<MsgContext>) {
    use std::error::Error;
    if let Some(source) = err.source() {
        if let Some(ctx) = ctx {
            info!(
                "unimplemented: Handle errors. This should be return w/ lazyError to sender. {:?}",
                err
            );
            error!("Source of error: {:?}", source);
        } else {
            error!(
                "Erroring without a msg context. Source of error: {:?}",
                source
            );
        }
    } else {
        info!("unimplemented: Handle errors. {:?}", err);
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
