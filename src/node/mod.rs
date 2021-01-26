// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adult_duties;
mod elder_duties;
mod msg_wrapping;
mod node_duties;
mod node_ops;
pub mod state_db;

use crate::{
    node::{
        node_duties::NodeDuties,
        node_ops::{GatewayDuty, NetworkDuty, NodeDuty, NodeOperation},
        state_db::{get_age_group, store_age_group, store_new_reward_keypair, AgeGroup},
    },
    utils::Init,
    Config, Error, Network, NodeInfo, Result,
};
use bls::SecretKey;
use log::{error, info};
use sn_data_types::PublicKey;
use sn_routing::{Event, EventStream, MIN_AGE};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/// Main node struct.
pub struct Node {
    duties: NodeDuties,
    network_api: Network,
    network_events: EventStream,
}

impl Node {
    /// Initialize a new node.
    pub async fn new(config: &Config) -> Result<Self> {
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

        let (reward_key, _age_group) = tokio::try_join!(reward_key_task, age_group_task)?;
        let (network_api, network_events) = Network::new(config).await?;

        let node_info = NodeInfo {
            genesis: config.is_first(),
            node_id: PublicKey::Ed25519(network_api.public_key().await),
            root_dir: root_dir_buf,
            init_mode: Init::New,
            /// Upper limit in bytes for allowed network storage on this node.
            /// An Adult would be using the space for chunks,
            /// while an Elder uses it for metadata.
            max_storage_capacity: config.max_capacity(),
            reward_key,
        };

        use AgeGroup::*;
        let age = network_api.age().await;
        info!("Our Age: {:?}", age);

        info!("Fetching Age bracket");
        let age_group = if !network_api.is_elder().await && age > MIN_AGE {
            info!("We are Adult");
            Adult
        } else {
            info!("We are Infant");
            Infant
        };

        let mut duties = NodeDuties::new(node_info, network_api.clone()).await;
        let _ = match age_group {
            Infant => Ok(NodeOperation::NoOp),
            Adult => {
                duties
                    .process_node_duty(node_ops::NodeDuty::AssumeAdultDuties)
                    .await
            }
            Elder => {
                info!("Becoming Elder");
                duties
                    .process_node_duty(node_ops::NodeDuty::AssumeElderDuties)
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
        let info = self.network_api.our_connection_info().await?;
        info!("Listening for routing events at: {}", info);
        while let Some(event) = self.network_events.next().await {
            info!("New event received from the Network: {:?}", event);
            let duty = if let Event::ClientMessageReceived { .. } = event {
                info!("Event from client peer: {:?}", event);
                GatewayDuty::ProcessClientEvent(event).into()
            } else {
                NodeDuty::ProcessNetworkEvent(event).into()
            };
            self.process_while_any(Ok(duty)).await;
        }

        Ok(())
    }

    /// Keeps processing resulting node operations.
    async fn process_while_any(&mut self, op: Result<NodeOperation>) {
        use NodeOperation::*;
        let mut next_op = op;
        while let Ok(op) = next_op {
            next_op = match op {
                Single(operation) => match self.process(operation).await {
                    Err(e) => {
                        self.handle_error(&e);
                        Ok(NoOp)
                    }
                    result => result,
                },
                Multiple(ops) => {
                    let mut node_ops = Vec::new();
                    for c in ops.into_iter() {
                        match self.process(c).await {
                            Ok(NoOp) => (),
                            Ok(op) => node_ops.push(op),
                            Err(e) => self.handle_error(&e),
                        };
                    }
                    Ok(node_ops.into())
                }
                NoOp => break,
            }
        }
    }

    async fn process(&mut self, duty: NetworkDuty) -> Result<NodeOperation> {
        use NetworkDuty::*;
        match duty {
            RunAsAdult(duty) => {
                info!("Running as Adult: {:?}", duty);
                if let Some(duties) = self.duties.adult_duties() {
                    duties.process_adult_duty(duty).await
                } else {
                    error!("Currently not an Adult!");
                    Err(Error::Logic("Currently not an Adult".to_string()))
                }
            }
            RunAsElder(duty) => {
                info!("Running as Elder: {:?}", duty);
                if let Some(duties) = self.duties.elder_duties() {
                    duties.process_elder_duty(duty).await
                } else if self.duties.try_enqueue_elder_duty(duty) {
                    Ok(NodeOperation::NoOp)
                } else {
                    error!("Currently not an Elder!");
                    Err(Error::Logic("Currently not an Elder".to_string()))
                }
            }
            RunAsNode(duty) => {
                info!("Running as Node: {:?}", duty);
                self.duties.process_node_duty(duty).await
            }
            NoOp => Ok(NodeOperation::NoOp),
        }
    }

    fn handle_error(&self, err: &Error) {
        info!("unimplemented: Handle errors.. {}", err)
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
