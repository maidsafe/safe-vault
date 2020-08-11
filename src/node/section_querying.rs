// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::network::Routing;
use crate::node::state_db::AgeGroup;
use bls::PublicKeySet;
use safe_nd::PublicKey;
use std::{collections::BTreeSet, net::SocketAddr};
use xor_name::XorName;

/// Querying of our section's member
/// composition, and other section related things.
#[derive(Clone)]
pub struct SectionQuerying<R: Routing + Clone> {
    routing: R,
}

impl<R: Routing + Clone> SectionQuerying<R> {
    pub fn new(routing: R) -> Self {
        Self { routing }
    }

    pub fn our_name(&self) -> XorName {
        XorName(self.routing.id().name().0)
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        Some(PublicKey::Bls(
            self.routing.public_key_set().ok()?.public_key(),
        ))
    }

    pub fn public_key_set(&self) -> Option<PublicKeySet> {
        Some(self.routing.public_key_set().ok()?.clone())
    }

    /// This can be asked for anything that has an XorName.
    /// What we ask is if our section should handle it, whether
    /// it be a piece of data, or a client address.
    pub fn handles(&self, address: &XorName) -> bool {
        let xorname = XorName(address.0);
        match self.routing.matches_our_prefix(&xorname) {
            Ok(result) => result,
            _ => false,
        }
    }

    pub fn matches_our_prefix(&self, name: XorName) -> bool {
        self.routing
            .matches_our_prefix(&XorName(name.0))
            .unwrap_or(false)
    }

    pub fn our_elder_names(&self) -> BTreeSet<XorName> {
        self.routing
            .our_elders()
            .iter()
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<BTreeSet<_>>()
    }

    pub fn our_elder_addresses(&self) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .our_elders()
            .iter()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
            .collect::<Vec<_>>()
    }

    pub fn our_elder_addresses_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .our_elders_sorted_by_distance_to(&XorName(name.0))
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
            .our_elders_sorted_by_distance_to(&XorName(name.0))
            .into_iter()
            .take(count)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub fn our_adults_sorted_by_distance_to(&self, name: &XorName, count: usize) -> Vec<XorName> {
        self.routing
            .our_elders_sorted_by_distance_to(&XorName(name.0))
            .into_iter()
            .take(count)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub fn is_elder(&self) -> bool {
        matches!(self.our_duties(), AgeGroup::Elder)
    }

    pub fn is_adult(&self) -> bool {
        matches!(self.our_duties(), AgeGroup::Adult)
    }

    fn our_duties(&self) -> AgeGroup {
        if self.routing.is_elder() {
            AgeGroup::Elder
        } else if self
            .routing
            .our_adults()
            .iter()
            .map(|c| c.name())
            .any(|x| *x == self.routing.name())
        {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        }
    }
}
