// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::super::transfers::replica_manager::ReplicaManager;
use crate::node::economy::Indicator;
use routing::Node as Routing;
use safe_nd::{Money, PublicKey};
use std::{cell::RefCell, rc::Rc};

const NANOS: u64 = 1_000_000_000;

/// Produces indicators for
/// the SAFE Network economy, specifically
/// the cost of storage and the minting of new money.
pub struct Economy {
    indicator: Indicator,
    routing: Rc<RefCell<Routing>>,
    replica: Rc<RefCell<ReplicaManager>>,
}

impl Economy {
    pub fn new(
        section_account: PublicKey,
        routing: Rc<RefCell<Routing>>,
        replica: Rc<RefCell<ReplicaManager>>,
    ) -> Self {
        let mut instance = Self {
            indicator: Indicator {
                period_key: section_account,
                minting_velocity: 2.0,
                period_base_cost: Money::zero(),
            },
            routing,
            replica,
        };
        let _ = instance.update_indicator();
        instance
    }

    /// The calculations within this method
    /// are temporary and should not be considered
    /// a final solution. It's something to work with during test nets.
    pub fn update_indicator(&mut self) -> Option<Indicator> {
        let routing = self.routing.borrow();
        let prefix = routing.our_prefix()?;
        let prefix_len = prefix.bit_count() as u32;

        // Nodes in our section (i.e. apprx. avg. node count per section).
        let adult_count = routing.our_adults().count() as u64;
        let elder_count = routing.our_elders().count() as u64;
        let section_nodes = adult_count + elder_count;
        let section_key = PublicKey::Bls(self.replica.borrow().replicas_pk_set()?.public_key());
        // The actual balance of this section.
        let section_balance = self.replica.borrow().balance(&section_key)?.as_nano();

        self.indicator =
            Self::get_indicator(prefix_len, section_nodes, section_balance, section_key);

        Some(self.indicator.clone())
    }

    fn get_indicator(
        prefix_len: u32,
        section_nodes: u64,
        section_balance: u64,
        section_key: PublicKey,
    ) -> Indicator {
        // Apprx. number of sections in the network.
        let total_sections = 2_u64.pow(prefix_len);
        // Apprx. number of nodes in the network.
        let total_nodes = total_sections * section_nodes;
        // The portion of total supply, that this section responsible for.
        let section_portion = (u32::MAX as u64 * NANOS / total_sections) as f64;
        // Percentages of farmed and unfarmed.
        let unfarmed_percent = section_balance as f64 / section_portion;
        let farmed_percent = 1.0 - unfarmed_percent;
        let ratio = unfarmed_percent / farmed_percent;

        // This is the factor that determines how fast new money should be minted.
        // Faster when less has been minted, slower when more has been minted.
        // Will keep minting until all is minted.
        let minting_velocity = ratio + 1.0;

        // Some obscure tricks to get the base cost within reasonable values
        // for very small as well as very large networks (up to about 130 billion nodes).
        let numerator = 1.0 / (total_nodes * total_nodes) as f64;
        let denominator = ((minting_velocity.powf(0.5) - 1.0).powf(prefix_len as f64)
            + (1.0 / NANOS as f64))
            / (NANOS as f64).powf(0.5);

        // This is the basis for store cost during the period.
        let period_base_cost = u64::max(1, (numerator / denominator * NANOS as f64).round() as u64);
        let period_base_cost = Money::from_nano(period_base_cost);

        Indicator {
            period_key: section_key,
            period_base_cost,
            minting_velocity,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use safe_nd::{PublicKey, Result};
    use threshold_crypto::SecretKey;

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }

    #[test]
    fn indicator_calc_impl_is_according_to_model() -> Result<()> {
        let max_supply = (u32::MAX as u64 * 1_000_000_000) as f64;

        // 15 % minted, 1 section and 122 nodes.
        let prefix_len = 0;
        let section_nodes = 122;
        let section_balance = (0.85 * max_supply) as u64;
        let section_key = get_random_pk();
        let indicator =
            Economy::get_indicator(prefix_len, section_nodes, section_balance, section_key);
        // Expected velocity is 6.67x.
        let expected_velocity = 667;
        let actual_velocity = (indicator.minting_velocity * 100.0).round() as u64;
        assert_eq!(actual_velocity, expected_velocity);
        // Expected base cost is 2.12 SC.
        assert_eq!(indicator.period_base_cost.as_nano(), 2124615464);

        // 25 % minted, 2 sections and 244 nodes.
        let prefix_len = 1;
        let section_nodes = 122;
        let section_balance = (0.75 * max_supply / 2.0) as u64;
        let section_key = get_random_pk();
        let indicator =
            Economy::get_indicator(prefix_len, section_nodes, section_balance, section_key);
        // Expected velocity is 4x.
        let expected_velocity = 400;
        let actual_velocity = (indicator.minting_velocity * 100.0).round() as u64;
        assert_eq!(actual_velocity, expected_velocity);
        // Expected base cost is 0.53 SC.
        assert_eq!(indicator.period_base_cost.as_nano(), 531153866);

        // 59 % minted, ~1 million sections and ~128 million nodes.
        let prefix_len = 20;
        let section_nodes = 122;
        let section_balance = (0.41 * max_supply / (2.0_f64).powf(20.0)) as u64;
        let section_key = get_random_pk();
        let indicator =
            Economy::get_indicator(prefix_len, section_nodes, section_balance, section_key);
        // Expected velocity is 1.69x.
        let expected_velocity = 169;
        let actual_velocity = (indicator.minting_velocity * 100.0).round() as u64;
        assert_eq!(actual_velocity, expected_velocity);
        // Expected base cost is 0.00186 SC.
        assert_eq!(indicator.period_base_cost.as_nano(), 1858843);
        Ok(())
    }
}
