// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::state_db::AgeGroup;
use crate::{Config as NodeConfig, Error, Result};
use bytes::Bytes;
use sn_data_types::PublicKey;
use sn_routing::{
    DstLocation, Error as RoutingError, EventStream, Node as RoutingNode,
    NodeConfig as RoutingConfig, PublicId, SectionProofChain, SrcLocation,
};
use std::collections::BTreeSet;
use std::{cell::RefCell, net::SocketAddr, rc::Rc};
use xor_name::{Prefix, XorName};
use std::sync::{Arc, Mutex};

///
#[derive(Clone)]
pub struct Network {
    routing: Arc<Mutex<RoutingNode>>,
}

#[allow(missing_docs)]
impl Network {
    pub async fn new(config: &NodeConfig) -> Result<(Self, EventStream)> {
        let mut node_config = RoutingConfig::default();
        node_config.first = config.is_first();
        node_config.transport_config = config.network_config().clone();
        node_config.network_params.recommended_section_size = 500;
        let (routing, event_stream) = RoutingNode::new(node_config).await?;

        Ok((
            Self {
                routing: Arc::new(Mutex::new(routing)),
            },
            event_stream,
        ))
    }

    pub async fn listen_events(&self) -> Result<EventStream> {
        futures::executor::block_on(self.routing
            .lock().unwrap()
            .listen_events())
            .map_err(Error::Routing)
    }

    pub fn our_name(&self) -> XorName {
        XorName(self.name().0)
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        Some(PublicKey::Bls(
            futures::executor::block_on(self.routing.lock().unwrap().public_key_set())
                .ok()?
                .public_key(),
        ))
    }

    pub fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        futures::executor::block_on(self.routing.lock().unwrap().public_key_set()).map_err(Error::Routing)
    }

    pub fn id(&self) -> PublicId {
        futures::executor::block_on(self.routing.lock().unwrap().id())
    }

    pub fn is_genesis(&self) -> bool {
        self.routing.lock().unwrap().is_genesis()
    }

    pub fn name(&self) -> XorName {
        futures::executor::block_on(self.routing.lock().unwrap().name())
    }

    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        futures::executor::block_on(self.routing.lock().unwrap().our_connection_info())
            .map_err(Error::Routing)
    }

    pub fn our_prefix(&self) -> Option<Prefix> {
        futures::executor::block_on(self.routing.lock().unwrap().our_prefix())
    }

    pub fn matches_our_prefix(&self, name: XorName) -> bool {
        futures::executor::block_on(self.routing.lock().unwrap().matches_our_prefix(&XorName(name.0)))
            .unwrap_or(false)
    }

    pub async fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<(), RoutingError> {
        futures::executor::block_on(self.routing
            .lock().unwrap()
            .send_message(src, dst, content))
        // Ok(())
    }

    pub async fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        futures::executor::block_on(self.routing
            .lock().unwrap()
            .send_message_to_client(peer_addr, msg))
            .map_err(Error::Routing)
    }

    pub fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        futures::executor::block_on(self.routing.lock().unwrap().secret_key_share())
            .map_err(Error::Routing)
    }

    pub fn our_history(&self) -> Option<SectionProofChain> {
        futures::executor::block_on(self.routing.lock().unwrap().our_history())
    }

    pub fn our_index(&self) -> Result<usize> {
        futures::executor::block_on(self.routing.lock().unwrap().our_index()).map_err(Error::Routing)
    }

    pub fn our_elder_names(&self) -> BTreeSet<XorName> {
        futures::executor::block_on(self.routing.lock().unwrap().our_elders())
            .iter()
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<BTreeSet<_>>()
    }

    pub fn our_elder_addresses(&self) -> Vec<(XorName, SocketAddr)> {
        futures::executor::block_on(self.routing.lock().unwrap().our_elders())
            .iter()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
            .collect::<Vec<_>>()
    }

    pub fn our_elder_addresses_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<(XorName, SocketAddr)> {
        futures::executor::block_on(
            self.routing
                .lock().unwrap()
                .our_elders_sorted_by_distance_to(&XorName(name.0)),
        )
        .into_iter()
        .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
        .collect::<Vec<_>>()
    }

    pub fn our_elder_names_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
        futures::executor::block_on(
            self.routing
                .lock().unwrap()
                .our_elders_sorted_by_distance_to(&XorName(name.0)),
        )
        .into_iter()
        .take(count)
        .map(|p2p_node| XorName(p2p_node.name().0))
        .collect::<Vec<_>>()
    }

    pub fn our_adults_sorted_by_distance_to(&self, name: &XorName, count: usize) -> Vec<XorName> {
        futures::executor::block_on(
            self.routing
                .lock().unwrap()
                .our_adults_sorted_by_distance_to(&XorName(name.0)),
        )
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
        if futures::executor::block_on(self.routing.lock().unwrap().is_elder()) {
            AgeGroup::Elder
        } else if futures::executor::block_on(self.routing.lock().unwrap().our_adults())
            .iter()
            .any(|adult| *adult.name() == self.name())
        {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        }
    }
}
