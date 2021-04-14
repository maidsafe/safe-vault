use sn_routing::XorName;

use crate::network::Network;

// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[derive(Clone)]
pub struct AdultReader {
    network: Network,
}

impl AdultReader {
    /// Access to the current state of our adult constellation
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    /// Dynamic state
    pub async fn our_adults(&self) -> Vec<XorName> {
        self.network.our_adults().await
    }

    /// Dynamic state
    pub async fn our_adults_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
        self.network
            .our_adults_sorted_by_distance_to(name, count)
            .await
    }
}
