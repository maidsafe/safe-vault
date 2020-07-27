// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::state_db::AgeGroup;
use routing::Node as Routing;
use safe_nd::XorName;
use std::{cell::RefCell, net::SocketAddr, rc::Rc};

#[derive(Clone)]
pub struct SectionQuerying {
    routing: Rc<RefCell<Routing>>,
}

/// Querying of our section's member composition.
impl SectionQuerying {
    pub fn new(routing: Rc<RefCell<Routing>>) -> Self {
        Self { routing }
    }

    pub fn our_name(&self) -> XorName {
        XorName(self.routing.borrow().id().name().0)
    }

    /// This can be asked for anything that has an XorName.
    /// What we ask is if our section should handle it, whether
    /// it be a piece of data, or a client address.
    pub fn handles(&self, address: &XorName) -> bool {
        let xorname = routing::XorName(address.0);
        match self.routing.borrow().matches_our_prefix(&xorname) {
            Ok(result) => result,
            _ => false,
        }
    }

    pub fn matches_our_prefix(&self, name: XorName) -> bool {
        self.routing
            .borrow()
            .matches_our_prefix(&routing::XorName(name.0))
            .unwrap_or(false)
    }

    pub fn our_elder_names(&self) -> Vec<XorName> {
        self.routing
            .borrow_mut()
            .our_elders()
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub fn our_elder_addresses(&self) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .borrow_mut()
            .our_elders()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
            .collect::<Vec<_>>()
    }

    pub fn our_elder_addresses_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .borrow()
            .our_elders_sorted_by_distance_to(&routing::XorName(name.0))
            .into_iter()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
            .collect::<Vec<_>>()
    }

    pub fn our_elder_names_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
        self.routing
            .borrow()
            .our_elders_sorted_by_distance_to(&routing::XorName(name.0))
            .into_iter()
            .take(count)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub fn our_adults_sorted_by_distance_to(&self, name: &XorName, count: usize) -> Vec<XorName> {
        self.routing
            .borrow()
            .our_elders_sorted_by_distance_to(&routing::XorName(name.0))
            .into_iter()
            .take(count)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub fn is_elder(&self) -> bool {
        if let AgeGroup::Elder = self.our_duties() {
            true
        } else {
            false
        }
    }

    pub fn is_adult(&self) -> bool {
        if let AgeGroup::Adult = self.our_duties() {
            true
        } else {
            false
        }
    }

    fn our_duties(&self) -> AgeGroup {
        if self.routing.borrow().is_elder() {
            AgeGroup::Elder
        } else if self
            .routing
            .borrow()
            .our_adults()
            .map(|c| c.name())
            .any(|x| x == self.routing.borrow().name())
        {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        }
    }
}
