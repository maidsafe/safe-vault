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
use std::net::SocketAddr;
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
        self.routing
            .lock().unwrap()
            .listen_events()
            .await
            .map_err(Error::Routing)
    }

    pub async fn our_name(&self) -> XorName {
        XorName(self.name().await.0)
    }

    pub async fn public_key(&self) -> Option<PublicKey> {
        Some(PublicKey::Bls(
            self.routing.lock().unwrap().public_key_set()
                .await
                .ok()?
                .public_key(),
        ))
    }

    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.routing.lock().unwrap().public_key_set().await.map_err(Error::Routing)
    }

    pub async fn id(&self) -> PublicId {
        self.routing.lock().unwrap().id().await
    }

    pub fn is_genesis(&self) -> bool {
        self.routing.lock().unwrap().is_genesis()
    }

    pub async fn name(&self) -> XorName {
        self.routing.lock().unwrap().name().await
    }

    pub async fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.routing.lock().unwrap().our_connection_info()
            .await
            .map_err(Error::Routing)
    }

    pub async fn our_prefix(&self) -> Option<Prefix> {
        self.routing.lock().unwrap().our_prefix().await
    }

    pub async fn matches_our_prefix(&self, name: XorName) -> bool {
        self.routing.lock().unwrap().matches_our_prefix(&XorName(name.0)).await
            .unwrap_or(false)
    }

    pub async fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Bytes,
    ) -> Result<(), RoutingError> {
        self.routing
            .lock().unwrap()
            .send_message(src, dst, content).await
        // Ok(())
    }

    pub async fn send_message_to_client(
        &mut self,
        peer_addr: SocketAddr,
        msg: Bytes,
    ) -> Result<()> {
        self.routing
            .lock().unwrap()
            .send_message_to_client(peer_addr, msg).await
            .map_err(Error::Routing)
    }

    pub async fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.routing.lock().unwrap().secret_key_share()
        .await
            .map_err(Error::Routing)
    }

    pub async fn our_history(&self) -> Option<SectionProofChain> {
        self.routing.lock().unwrap().our_history().await
    }

    pub async fn our_index(&self) -> Result<usize> {
        self.routing.lock().unwrap().our_index().await.map_err(Error::Routing)
    }

    pub async fn our_elder_names(&self) -> BTreeSet<XorName> {
        self.routing.lock().unwrap().our_elders()
            .await
            .iter()
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<BTreeSet<_>>()
    }

    pub async fn our_elder_addresses(&self) -> Vec<(XorName, SocketAddr)> {
        self.routing.lock().unwrap().our_elders()
            .await
            .iter()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
            .collect::<Vec<_>>()
    }

    pub async fn our_elder_addresses_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<(XorName, SocketAddr)> {
            self.routing
                .lock().unwrap()
                .our_elders_sorted_by_distance_to(&XorName(name.0))
        .await
        .into_iter()
        .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.peer_addr()))
        .collect::<Vec<_>>()
    }

    pub async fn our_elder_names_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
            self.routing
                .lock().unwrap()
                .our_elders_sorted_by_distance_to(&XorName(name.0))
        .await
        .into_iter()
        .take(count)
        .map(|p2p_node| XorName(p2p_node.name().0))
        .collect::<Vec<_>>()
    }

    pub async fn our_adults_sorted_by_distance_to(&self, name: &XorName, count: usize) -> Vec<XorName> {
            self.routing
                .lock().unwrap()
                .our_adults_sorted_by_distance_to(&XorName(name.0))
                .await
        .into_iter()
        .take(count)
        .map(|p2p_node| XorName(p2p_node.name().0))
        .collect::<Vec<_>>()
    }

    pub async fn is_elder(&self) -> bool {
        matches!(self.our_duties().await, AgeGroup::Elder)
    }

    pub async fn is_adult(&self) -> bool {
        matches!(self.our_duties().await, AgeGroup::Adult)
    }

    async fn our_duties(&self) -> AgeGroup {
        let our_name = self.name().await;
        if self.routing.lock().unwrap().is_elder().await {
            AgeGroup::Elder
        } else if self.routing.lock().unwrap().our_adults()
            .await
            .iter()
            .any(|adult| *adult.name() == our_name)
        {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        }
    }
}
