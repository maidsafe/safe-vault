// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use dashmap::DashMap;
use log::debug;
use sn_data_types::{NodeAge, PublicKey};
use sn_routing::Prefix;
use std::collections::BTreeMap;
use xor_name::XorName;

/// The accumulation and paying
/// out of rewards to nodes for
/// their work in the network.
#[derive(Clone)]
pub struct RewardWallets {
    node_rewards: DashMap<XorName, (NodeAge, PublicKey)>,
}

// Node age
type Age = u8;

impl RewardWallets {
    pub fn new(node_rewards: BTreeMap<XorName, (NodeAge, PublicKey)>) -> Self {
        Self {
            node_rewards: node_rewards.into_iter().collect(),
        }
    }

    /// Returns the stage of a specific node.
    pub fn get(&self, node_name: &XorName) -> Option<(NodeAge, PublicKey)> {
        Some(*self.node_rewards.get(node_name)?)
    }

    /// Returns the node ids of all nodes.
    #[allow(unused)]
    pub fn all_nodes(&self) -> Vec<XorName> {
        self.node_rewards.iter().map(|r| *r.key()).collect()
    }

    ///
    pub fn node_wallets(&self) -> BTreeMap<XorName, (NodeAge, PublicKey)> {
        self.node_rewards
            .clone()
            .into_read_only()
            .iter()
            .map(|(node, (age, key))| (*node, (*age, *key)))
            .collect()
    }

    /// Removes a subset of the nodes,
    /// more specifically those no longer
    /// part of this section, after a split.
    pub fn keep_wallets_of(&self, prefix: Prefix) {
        // Removes keys that are no longer our section responsibility.
        let keys = self
            .node_rewards
            .iter()
            .map(|info| *info.key())
            .collect::<Vec<_>>();

        for key in keys {
            if !prefix.matches(&key) {
                if let Some((name, _)) = self.node_rewards.remove(&key) {
                    debug!("Removed node {} from rewards list.", name);
                }
            }
        }
    }

    /// A new node registers a wallet id for future reward payout.
    /// ... or, an active node updates its wallet.
    pub fn set_node_wallet(&self, node_name: XorName, age: Age, wallet: PublicKey) {
        let _ = self.node_rewards.insert(node_name, (age, wallet));
    }

    /// When the section becomes aware that a node has left,
    /// its reward key is removed.
    pub fn remove_wallet(&self, node_name: XorName) {
        let _ = self.node_rewards.remove(&node_name);
    }
}
