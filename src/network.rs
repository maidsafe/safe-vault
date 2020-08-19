// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::state_db::AgeGroup;
use crate::{Error, Result};
use bytes::Bytes;
use routing::{
    DstLocation, EventStream, Node as RoutingNode, P2pNode, PublicId, RoutingError,
    SectionProofChain, SrcLocation,
};
use safe_nd::PublicKey;
use std::collections::BTreeSet;
use std::{cell::RefCell, net::SocketAddr, rc::Rc};
use xor_name::{Prefix, XorName};

///
#[derive(Clone)]
pub struct Network {
    routing: Rc<RefCell<RoutingNode>>,
}

#[allow(missing_docs)]
impl Network {
    pub fn new(node: RoutingNode) -> Self {
        Self {
            routing: Rc::new(RefCell::new(node)),
        }
    }

    pub fn listen_events(&self) -> Result<EventStream> {
        self.routing
            .borrow()
            .listen_events()
            .map_err(Error::Routing)
    }

    pub fn our_name(&self) -> XorName {
        XorName(self.routing.borrow().id().name().0)
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        Some(PublicKey::Bls(
            self.routing.borrow().public_key_set().ok()?.public_key(),
        ))
    }

    pub fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        Ok(self.routing.borrow().public_key_set()?.clone())
    }

    pub fn is_running(&self) -> bool {
        self.routing.borrow().is_running()
    }

    pub fn id(&self) -> PublicId {
        *self.routing.borrow().id()
    }

    pub fn name(&self) -> XorName {
        *self.routing.borrow().name()
    }

    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.routing
            .borrow_mut()
            .our_connection_info()
            .map_err(Error::Routing)
    }

    pub fn our_prefix(&self) -> Option<Prefix> {
        self.routing.borrow().our_prefix().copied()
    }

    pub fn matches_our_prefix(&self, name: XorName) -> bool {
        self.routing
            .borrow()
            .matches_our_prefix(&XorName(name.0))
            .unwrap_or(false)
    }

    pub fn our_elders(&self) -> Vec<P2pNode> {
        self.routing.borrow().our_elders().cloned().collect()
    }

    pub fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode> {
        self.routing
            .borrow()
            .our_elders_sorted_by_distance_to(name)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn our_adults(&self) -> Vec<P2pNode> {
        self.routing.borrow().our_adults().cloned().collect()
    }

    pub fn in_dst_location(&self, dst: &DstLocation) -> bool {
        self.routing.borrow().in_dst_location(dst)
    }

    pub fn vote_for_user_event(&mut self, event: Vec<u8>) -> Result<()> {
        self.routing
            .borrow_mut()
            .vote_for_user_event(event)
            .map_err(Error::Routing)
    }

    pub async fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<(), RoutingError> {
        self.routing
            .borrow_mut()
            .send_message(src, dst, content)
            .await
    }

    pub async fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        self.routing
            .borrow_mut()
            .send_message_to_client(peer_addr, msg)
            .await
            .map_err(Error::Routing)
    }

    pub fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<()> {
        self.routing
            .borrow_mut()
            .disconnect_from_client(peer_addr)
            .map_err(Error::Routing)
    }

    pub fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.routing
            .borrow()
            .secret_key_share()
            .map_err(Error::Routing)
            .map(|c| c.clone())
    }

    pub fn our_history(&self) -> Option<SectionProofChain> {
        self.routing.borrow().our_history().cloned()
    }

    pub fn our_index(&self) -> Result<usize> {
        self.routing.borrow().our_index().map_err(Error::Routing)
    }

    pub fn our_elder_names(&self) -> BTreeSet<XorName> {
        self.routing
            .borrow()
            .our_elders()
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<BTreeSet<_>>()
    }

    pub fn our_elder_addresses(&self) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .borrow()
            .our_elders()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
            .collect::<Vec<_>>()
    }

    pub fn our_elder_addresses_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .borrow_mut()
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
            .borrow()
            .our_elders_sorted_by_distance_to(&XorName(name.0))
            .into_iter()
            .take(count)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub fn our_adults_sorted_by_distance_to(&self, name: &XorName, count: usize) -> Vec<XorName> {
        self.routing
            .borrow()
            .our_adults_sorted_by_distance_to(&XorName(name.0))
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
        if self.routing.borrow().is_elder() {
            AgeGroup::Elder
        } else if self
            .routing
            .borrow()
            .our_adults()
            .map(|c| c.name())
            .any(|x| *x == *self.routing.borrow().name())
        {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        }
    }
}
