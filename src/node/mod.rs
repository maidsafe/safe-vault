// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adult_duties;
mod elder_duties;
mod node_duties;
mod node_ops;
pub mod state_db;

use crate::{
    chunk_store::UsedSpace,
    node::{
        node_duties::NodeDuties,
        node_ops::{NetworkDuties, NodeDuty},
        state_db::{get_age_group, store_age_group, store_new_reward_keypair, AgeGroup},
    },
    Config, Error, Network, NodeInfo, Result,
};
use bls::SecretKey;
use log::{error, info};
use sn_data_types::PublicKey;
use sn_routing::{EventStream, MIN_AGE};
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
            root_dir: root_dir_buf,
            used_space: UsedSpace::new(config.max_capacity()),
            reward_key,
        };

        use AgeGroup::*;
        let age = network_api.age().await;
        let age_group = if !network_api.is_elder().await && age > MIN_AGE {
            Adult
        } else {
            Infant
        };

        let init_ops = match age_group {
            Infant => Ok(vec![]),
            Adult => Ok(NetworkDuties::from(node_ops::NodeDuty::AssumeAdultDuties)),
            Elder => Err(Error::Logic("Unimplemented".to_string())),
        };

        let mut node = Self {
            duties: NodeDuties::new(node_info, network_api.clone()).await?,
            network_api,
            network_events,
        };

        node.process_while_any(init_ops).await;

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
        //let info = self.network_api.our_connection_info().await;
        //info!("Listening for routing events at: {}", info);
        while let Some(event) = self.network_events.next().await {
            info!("New event received from the Network: {:?}", event);
            self.process_while_any(Ok(NetworkDuties::from(NodeDuty::ProcessNetworkEvent(
                event,
            ))))
            .await;
        }

        Ok(())
    }

    /// Keeps processing resulting node operations.
    async fn process_while_any(&mut self, ops_vec: Result<NetworkDuties>) {
        let mut next_ops = ops_vec;

        while let Ok(ops) = next_ops {
            let mut pending_node_ops = Vec::new();

            if !ops.is_empty() {
                for duty in ops {
                    match self.duties.process(duty).await {
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

    fn handle_error(&self, err: &Error) {
        use std::error::Error;
        info!("unimplemented: Handle errors.. {}", err);

        if let Some(source) = err.source() {
            error!("Source of error: {:?}", source);
        }
    }
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node")
    }
}
