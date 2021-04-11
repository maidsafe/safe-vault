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
mod rpc;
mod split;

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    chunk_store::UsedSpace,
    chunks::Chunks,
    event_mapping::{map_routing_event, LazyError, Mapping, MsgContext},
    metadata::{adult_reader::AdultReader, Metadata},
    node_ops::{NodeDuties, NodeDuty},
    section_funds::SectionFunds,
    state_db::store_new_reward_keypair,
    transfers::get_replicas::transfer_replicas,
    transfers::Transfers,
    Config, Error, Network, Result,
};
use bls::SecretKey;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use futures::lock::Mutex;
use hex_fmt::HexFmt;
use log::{debug, error, info, trace, warn};
use rpc::{Connection, ConnectionStream, RpcInterface};
use sn_data_types::{ActorHistory, PublicKey, TransferPropagated, WalletHistory};
use sn_messaging::{client::Message, DstLocation, SrcLocation};
use sn_routing::{Event as RoutingEvent, EventStream, NodeElderChange, MIN_AGE};
use sn_routing::{Prefix, XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use sn_transfers::{TransferActor, Wallet};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{
    boxed::Box,
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
    pub log_dir: PathBuf,
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

/// Main node struct.
pub struct Node {
    network_api: Network,
    network_events: EventStream,
    node_info: NodeInfo,
    used_space: UsedSpace,
    prefix: Prefix,
    // immutable chunks
    chunks: Option<Chunks>,
    // data operations
    meta_data: Option<Metadata>,
    // transfers
    transfers: Option<Transfers>,
    // reward payouts
    section_funds: Option<SectionFunds>,
    rpc_ifc: Option<Box<RpcInterface>>,
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

        // setup rpc interface
        let rpc_ifc = match config.rpc_port() {
            Some(port) => {
                info!("Running RPC interface on localhost:{}", &port);
                Some(Box::new(RpcInterface::new(root_dir, port)?))
            }
            None => {
                info!("RPC interface disabled.");
                None
            }
        };
        let log_dir_buf = if let Some(dir) = config.log_dir().as_ref() {
            dir.clone()
        } else {
            root_dir_buf.clone() //TODO centralize this
        };
        let node_info = NodeInfo {
            genesis: config.is_first(),
            root_dir: root_dir_buf,
            log_dir: log_dir_buf,
            node_name: network_api.our_name().await,
            node_id: network_api.public_key().await,
            reward_key,
        };

        let used_space = UsedSpace::new(config.max_capacity());

        let node = Self {
            prefix: network_api.our_prefix().await,
            chunks: Some(
                Chunks::new(
                    node_info.node_name,
                    node_info.root_dir.as_path(),
                    used_space.clone(),
                )
                .await?,
            ),
            node_info,
            used_space,
            network_api,
            network_events,
            meta_data: None,
            transfers: None,
            section_funds: None,
            rpc_ifc,
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
        let info = self.network_api.our_connection_info();
        info!("Listening for routing events at: {}", info);

        // optionally bind to get a connection stream
        let mut maybe_rpc_conn_stream = match &mut self.rpc_ifc {
            Some(ref mut ifc) => Some(ifc.bind()?),
            None => None,
        };

        loop {
            tokio::select! {

                // handle network event
                Some(event) = self.network_events.next() => {
                    // tokio spawn should only be needed around intensive tasks, ie sign/verify
                    match map_routing_event(event, &self.network_api).await {
                        Mapping::Ok { op, ctx } => self.process_while_any(op, ctx).await,
                        Mapping::Error(error) => handle_error(error),
                    }
                }

                // handle rpc on separate interface (and_then_conn_stream_get_next helper gets around async closures being unstable)
                // Note the extra `is_some()` condition prevents spinning in `and_then_conn_stream_get_next()`
                Some(conn) = Self::and_then_conn_stream_get_next(&mut maybe_rpc_conn_stream), if maybe_rpc_conn_stream.is_some() => {
                    assert!(self.rpc_ifc.is_some());
                    if let Err(e) = self.handle_rpc_connection(conn).await {
                        error!("RPC error: {:?}", e);
                    }
                }

                // exit node service loop
                else => {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Little helper to deal with unstable async closures in calling conn_stream.get_next()
    async fn and_then_conn_stream_get_next(
        maybe_in_conn: &mut Option<ConnectionStream>,
    ) -> Option<Connection> {
        assert!(maybe_in_conn.is_some());
        if let Some(ref mut in_conn) = maybe_in_conn {
            in_conn.get_next().await
        } else {
            None //should never get here
        }
    }

    /// Handle a new connection from the connection stream.
    ///
    /// Do not call this if self.rpc_ifc.is_none() (although this should be logically
    /// impossible, given you can't get a `Connection` unless `rpc_ifc.is_some() == true`)
    /// NOTE: For now we just always respond Ok(()) to each response stream, but,
    /// in future, we may want to generate NodeOperations in RpcInterface,
    /// service them here, and use the ResponseStream.respond() to report the result
    /// back to the client.
    async fn handle_rpc_connection(&mut self, mut conn: Connection) -> Result<()> {
        assert!(self.rpc_ifc.is_some());
        if let Some(ref rpc_ifc) = self.rpc_ifc {
            while let Some(resp_stream) = rpc_ifc
                .process_next(
                    &mut conn,
                    &self.node_info,
                    self.used_space.clone(),
                    self.network_api.clone(),
                )
                .await?
            {
                resp_stream.respond(Ok(())).await?;
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
