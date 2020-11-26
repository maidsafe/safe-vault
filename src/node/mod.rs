// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod state_db;

mod adult_duties;
mod duty_cfg;
mod elder_duties;
mod keys;
mod msg_wrapping;
mod node_duties;
mod node_ops;

use crate::{
    node::{
        keys::NodeSigningKeys,
        node_duties::NodeDuties,
        node_ops::{GatewayDuty, NetworkDuty, NodeDuty, NodeOperation},
        state_db::{get_age_group, store_age_group, store_new_reward_keypair, AgeGroup, NodeInfo},
    },
    utils::Init,
    Config, Error, Network, Outcome, Result, TernaryResult,
};
use bls::SecretKey;
use log::{error, info};
use rand::{CryptoRng, Rng};
use sn_data_types::PublicKey;
use sn_routing::{Event, EventStream};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Main node struct.
pub struct Node<R: CryptoRng + Rng> {
    duties: NodeDuties<R>,
    network_api: Network,
    network_events: EventStream,
}

impl<R: CryptoRng + Rng> Node<R> {
    /// Initialize a new node.
    pub async fn new(config: &Config, rng: R) -> Result<Self> {
        let root_dir_buf = config.root_dir()?;
        let root_dir = root_dir_buf.as_path();
        std::fs::create_dir_all(root_dir)?;

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
        };
        let age_group_task = async move {
            let res: Result<AgeGroup>;
            if let Some(age_group) = get_age_group(&root_dir).await? {
                res = Ok(age_group)
            } else {
                let age_group = Infant;
                store_age_group(root_dir, &age_group).await?;
                res = Ok(age_group)
            };
            res
        };

        let (reward_key, age_group) = tokio::try_join!(reward_key_task, age_group_task)?;
        let (network_api, network_events) = Network::new(config).await?;
        let keys = NodeSigningKeys::new(network_api.clone());

        let node_info = NodeInfo {
            first: config.is_first(),
            keys,
            root_dir: root_dir_buf,
            init_mode: Init::New,
            /// Upper limit in bytes for allowed network storage on this node.
            /// An Adult would be using the space for chunks,
            /// while an Elder uses it for metadata.
            max_storage_capacity: config.max_capacity(),
            reward_key,
        };

        let mut duties = NodeDuties::new(node_info, network_api.clone(), rng).await;

        use AgeGroup::*;
        let _ = match age_group {
            Infant => Ok(None),
            Adult => {
                duties
                    .process_node_duty(node_ops::NodeDuty::BecomeAdult)
                    .await
            }
            Elder => {
                duties
                    .process_node_duty(node_ops::NodeDuty::BecomeElder)
                    .await
            }
        };

        let node = Self {
            duties,
            network_api,
            network_events,
        };

        Ok(node)
    }

    /// Returns our connection info.
    pub async fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.network_api
            .our_connection_info()
            .await
            .map_err(From::from)
    }

    /// Returns whether routing node is in elder state.
    pub async fn is_elder(&self) -> bool {
        self.network_api.is_elder().await
    }

    /// Starts the node, and runs the main event loop.
    /// Blocks until the node is terminated, which is done
    /// by client sending in a `Command` to free it.
    pub async fn run(&mut self) -> Result<()> {
        let info = self.network_api.our_connection_info().await.unwrap();
        info!("Listening for routing events at: {}", info);
        while let Some(event) = self.network_events.next().await {
            info!("New event received from the Network: {:?}", event);
            let duty = if let Event::ClientMessageReceived { .. } = event {
                info!("Event from client peer: {:?}", event);
                GatewayDuty::ProcessClientEvent(event).into()
            } else {
                NodeDuty::ProcessNetworkEvent(event).into()
            };
            self.process_while_any(Outcome::oki(duty)).await;
        }

        Ok(())
    }

    /// Keeps processing resulting node operations.
    async fn process_while_any(&mut self, op: Outcome<NodeOperation>) {
        use NodeOperation::*;
        let mut next_op = op;
        while let Ok(Some(op)) = next_op {
            next_op = match op {
                Single(operation) => self.process(operation).await,
                Multiple(ops) => {
                    let mut node_ops = Vec::new();
                    for c in ops.into_iter() {
                        match self.process(c).await {
                            Ok(None) | Ok(Some(NoOp)) => (),
                            Ok(Some(op)) => node_ops.push(op),
                            Err(_error) => unimplemented!("Handle errors.."),
                        };
                    }
                    Outcome::oki(node_ops.into())
                }
                NoOp => break,
            }
        }
    }

    async fn process(&mut self, duty: NetworkDuty) -> Outcome<NodeOperation> {
        use NetworkDuty::*;
        match duty {
            RunAsAdult(duty) => {
                info!("Running as Adult: {:?}", duty);
                if let Some(duties) = self.duties.adult_duties() {
                    duties.process_adult_duty(&duty).await
                } else {
                    error!("Currently not an Adult!");
                    Outcome::error(Error::Logic)
                }
            }
            RunAsElder(duty) => {
                info!("Running as Elder: {:?}", duty);
                if let Some(duties) = self.duties.elder_duties() {
                    duties.process_elder_duty(duty).await
                } else {
                    error!("Currently not an Elder!");
                    Outcome::error(Error::Logic)
                }
            }
            RunAsNode(duty) => {
                info!("Running as Node: {:?}", duty);
                self.duties.process_node_duty(duty).await
            }
        }
    }
}

impl<R: CryptoRng + Rng> Display for Node<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
