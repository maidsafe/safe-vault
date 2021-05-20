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
mod role;
mod split;

use crate::{
    chunk_store::UsedSpace,
    chunks::Chunks,
    error::convert_to_error_message,
    event_mapping::{map_routing_event, MsgContext},
    network::Network,
    node_ops::{NodeDuty, OutgoingLazyError},
    state_db::{get_reward_pk, store_new_reward_keypair},
    Config, Error, Result,
};
use log::{error, warn};
use rand::rngs::OsRng;
use role::{AdultRole, Role};
use sn_data_types::PublicKey;
use sn_messaging::{client::ClientMsg, Msg};
use sn_routing::{
    EventStream, {Prefix, XorName},
};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// Static info about the node.
#[derive(Clone)]
pub struct NodeInfo {
    ///
    pub root_dir: PathBuf,
    /// The key used by the node to receive earned rewards.
    pub reward_key: PublicKey,
}

impl NodeInfo {
    ///
    pub fn path(&self) -> &Path {
        self.root_dir.as_path()
    }
}

/// Main node struct.
pub struct Node {
    network_api: Network,
    network_events: EventStream,
    node_info: NodeInfo,
    used_space: UsedSpace,
    role: Role,
}

impl Node {
    /// Initialize a new node.
    pub async fn new(config: &Config) -> Result<Self> {
        let root_dir_buf = config.root_dir()?;
        let root_dir = root_dir_buf.as_path();
        std::fs::create_dir_all(root_dir)?;

        let reward_key = match get_reward_pk(root_dir).await? {
            Some(public_key) => PublicKey::Ed25519(public_key),
            None => {
                let mut rng = OsRng;
                let keypair = ed25519_dalek::Keypair::generate(&mut rng);
                store_new_reward_keypair(root_dir, &keypair).await?;
                PublicKey::Ed25519(keypair.public)
            }
        };

        let (network_api, network_events) = Network::new(root_dir, config).await?;

        let node_info = NodeInfo {
            root_dir: root_dir_buf,
            reward_key,
        };

        let node = Self {
            role: Role::Adult(AdultRole {
                chunks: Chunks::new(node_info.root_dir.as_path(), config.max_capacity()).await?,
            }),
            node_info,
            used_space: UsedSpace::new(config.max_capacity()),
            network_api,
            network_events,
        };

        messaging::send(node.register_wallet().await, &node.network_api).await?;

        Ok(node)
    }

    /// Returns our connection info.
    pub fn our_connection_info(&self) -> SocketAddr {
        self.network_api.our_connection_info()
    }

    /// Returns our name.
    pub async fn our_name(&self) -> XorName {
        self.network_api.our_name().await
    }

    /// Returns our prefix.
    pub async fn our_prefix(&self) -> Prefix {
        self.network_api.our_prefix().await
    }

    /// Starts the node, and runs the main event loop.
    /// Blocks until the node is terminated, which is done
    /// by client sending in a `Command` to free it.
    pub async fn run(&mut self) -> Result<()> {
        while let Some(event) = self.network_events.next().await {
            // tokio spawn should only be needed around intensive tasks, ie sign/verify
            let mapping = map_routing_event(event, &self.network_api).await;
            self.process_while_any(mapping.op, mapping.ctx).await;
        }

        Ok(())
    }

    // Keeps processing resulting node operations.
    async fn process_while_any(&mut self, op: NodeDuty, ctx: Option<MsgContext>) {
        let mut next_ops = vec![op];

        while !next_ops.is_empty() {
            let mut pending_node_ops: Vec<NodeDuty> = vec![];
            for duty in next_ops {
                match self.handle(duty).await {
                    Ok(new_ops) => pending_node_ops.extend(new_ops),
                    Err(e) => {
                        if let Some(new_op) = try_handle_error(e, ctx.clone()) {
                            pending_node_ops.push(new_op)
                        }
                    }
                };
            }
            next_ops = pending_node_ops;
        }
    }
}

fn try_handle_error(err: Error, ctx: Option<MsgContext>) -> Option<NodeDuty> {
    use std::error::Error;
    warn!("Error being handled by node: {:?}", err);
    if let Some(source) = err.source() {
        warn!("Source: {:?}", source);
    }

    match ctx {
        None => {
            error!(
                    "Erroring when processing a message without a msg context, we cannot report it to the sender: {:?}", err
                );
            None
        }
        Some(MsgContext { msg, src }) => {
            warn!("Sending in response to a message: {:?}", msg);
            match msg {
                Msg::Client(ClientMsg::Process(msg)) => {
                    Some(NodeDuty::SendError(OutgoingLazyError {
                        msg: msg.create_processing_error(Some(convert_to_error_message(err))),
                        dst: src.to_dst(),
                    }))
                }
                _ => None,
            }
        }
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
