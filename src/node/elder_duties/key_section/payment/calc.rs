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
        // Apprx. number of sections in the network.
        let total_sections = 2_u64.pow(prefix_len);
        // Nodes in our section (i.e. apprx. avg. node count per section).
        let adult_count = routing.our_adults().count() as u64;
        let elder_count = routing.our_elders().count() as u64;
        // Apprx. number of nodes in the network.
        let total_nodes = total_sections * (adult_count + elder_count);

        // The portion of total supply, that this section responsible for.
        let section_portion = (u32::MAX as u64 * NANOS / total_sections) as f64;
        let section_account = PublicKey::Bls(self.replica.borrow().replicas_pk_set()?.public_key());
        // The actual balance of this section.
        let section_balance = self.replica.borrow().balance(&section_account)?.as_nano() as f64;

        // Percentages of farmed and unfarmed.
        let unfarmed_percent = section_balance / section_portion;
        let farmed_percent = 1.0 - unfarmed_percent;
        let ratio = unfarmed_percent / farmed_percent;

        // This is the factor that determines how fast new money should be minted.
        // Faster when less has been minted, slower when more has been minted.
        // Will keep minting until all is minted.
        let minting_velocity = (ratio + 1.0).powf(2.0);

        // Some obscure tricks to get the base cost within reasonable values
        // for very small as well as very large networks (up to about 130 billion nodes).
        let numerator = 1 / (total_nodes * total_nodes) / NANOS;
        let denominator =
            (ratio.powf(prefix_len as f64) + (1.0 / NANOS as f64)) / (NANOS as f64).powf(0.5);

        // This is the basis for store cost during the period.
        let period_base_cost = u64::max(1, (numerator as f64 / denominator) as u64);
        let period_base_cost = Money::from_nano(period_base_cost);

        self.indicator = Indicator {
            period_key: section_account,
            period_base_cost,
            minting_velocity,
        };

        Some(self.indicator.clone())
    }
}
