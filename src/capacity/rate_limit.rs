// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{capacity::Capacity, Network};
use sn_data_types::Money;

const MAX_CHUNK_SIZE: u64 = 1_000_000;
const MAX_SUPPLY: u64 = u32::MAX as u64 * 1_000_000_000_u64;

/// Calculation of rate limit for writes.
pub struct RateLimit {
    network: Network,
    capacity: Capacity,
}

impl RateLimit {
    /// Ctor
    pub fn new(network: Network, capacity: Capacity) -> RateLimit {
        Self { network, capacity }
    }

    /// Calculates the rate limit of write operations,
    /// as a cost to be paid for a certain number of bytes.
    pub fn from(&self, bytes: u64) -> Option<Money> {
        let prefix = self.network.our_prefix()?;
        let prefix_len = prefix.bit_count();
        let section_supply_share = MAX_SUPPLY as f64 / 2_f64.powf(prefix_len as f64);

        let full_nodes = self.capacity.full_nodes();
        let available_nodes = self.capacity.node_count();

        Some(RateLimit::rate_limit(
            bytes,
            full_nodes,
            available_nodes,
            section_supply_share,
            prefix_len,
        ))
    }

    fn rate_limit(
        bytes: u64,
        full_nodes: u8,
        available_nodes: u8,
        section_supply_share: f64,
        prefix_len: usize,
    ) -> Money {
        let nodes = (available_nodes + full_nodes) as f64;
        let supply_demand_factor = 0.001
            + (1_f64 / available_nodes as f64).powf(8_f64)
            + ((full_nodes + 30) as f64 / nodes).powf(88_f64);
        let data_size_factor = (bytes as f64 / MAX_CHUNK_SIZE as f64).powf(2_f64)
            + (bytes as f64 / MAX_CHUNK_SIZE as f64);
        let steepness_reductor = prefix_len as f64 + 1_f64;
        let token_source = steepness_reductor * section_supply_share.powf(0.5_f64);
        let rate_limit = (token_source * data_size_factor * supply_demand_factor).round() as u64;
        Money::from_nano(rate_limit)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn calculates_rate_limit() -> Result<()> {
        let bytes = 1_000;
        let prefix_len = 0;
        let available_nodes = 122;
        let full_nodes = 0;
        let section_supply_share =
            ((u32::MAX as u64 * 1_000_000_000) / 2_u64.pow(prefix_len as u32)) as f64;
        let rate_limit = RateLimit::rate_limit(
            bytes,
            full_nodes,
            available_nodes,
            section_supply_share,
            prefix_len,
        )
        .as_nano();
        assert!(rate_limit == 2075);
        Ok(())
    }
}
