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
    node_ops::{MsgType, NodeDuty, OutgoingLazyError},
    state_db::{get_reward_pk, store_new_reward_keypair},
    Config, Error, Result,
};
use crate::{event_mapping::Mapping, node_ops::NodeDuties};
use log::{error, warn};
use rand::rngs::OsRng;
use role::{AdultRole, Role};
use sn_data_types::PublicKey;
use sn_messaging::client::ClientMsg;
use sn_routing::{
    EventStream, {Prefix, XorName},
};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::task::JoinHandle;

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
        // let mut threads = vec![tokio::spawn(self.handle(op))];
        let ops = self.handle(op).await;
        let mut threads = self.helper(ops, ctx.clone()).await;
        loop {
            let (result, _count, mut remaining_futures) =
                futures::future::select_all(threads.into_iter()).await;
            match result {
                Ok(res) => {
                    remaining_futures.extend(self.helper(res, ctx.clone()).await);
                }
                Err(e) => {
                    error!("Error spawing thread for task: {}", e);
                }
            }
            threads = remaining_futures;
        }
    }

    async fn helper(
        &mut self,
        result: Result<NodeDuties>,
        ctx: Option<MsgContext>,
    ) -> Vec<JoinHandle<Result<NodeDuties>>> {
        let threads = vec![];
        match result {
            Ok(new_ops) => {
                for op in new_ops {
                    threads.push(tokio::spawn(self.handle(op)));
                }
            }
            Err(e) => {
                let new_ops = try_handle_error(e, ctx.clone());
                for op in new_ops {
                    threads.push(tokio::spawn(self.handle(op)));
                }
            }
        }
        threads
    }
}

fn try_handle_error(err: Error, ctx: Option<MsgContext>) -> NodeDuty {
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
            NodeDuty::NoOp
        }
        Some(MsgContext { msg, src }) => {
            warn!("Sending in response to a message: {:?}", msg);
            match msg {
                MsgType::Client(ClientMsg::Process(msg)) => {
                    NodeDuty::SendError(OutgoingLazyError {
                        msg: msg.create_processing_error(Some(convert_to_error_message(err))),
                        dst: src.to_dst(),
                    })
                }
                _ => NodeDuty::NoOp,
            }
        }
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
