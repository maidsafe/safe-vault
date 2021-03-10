// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::state_db::AgeGroup, utils, Config as NodeConfig, Error, Result};
use bytes::Bytes;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use futures::lock::Mutex;
use serde::Serialize;
use sn_data_types::{PublicKey, Signature};
use sn_messaging::Itinerary;
use sn_routing::{
    Config as RoutingConfig, Error as RoutingError, EventStream, Routing as RoutingNode,
    SectionChain,
};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use xor_name::{Prefix, XorName};

///
#[derive(Clone)]
pub struct Network {
    routing: Arc<Mutex<RoutingNode>>,
}

#[allow(missing_docs)]
impl Network {
    pub async fn new(config: &NodeConfig) -> Result<(Self, EventStream)> {
        let node_config = RoutingConfig {
            first: config.is_first(),
            transport_config: config.network_config().clone(),
            ..Default::default()
        };
        let (routing, event_stream) = RoutingNode::new(node_config).await?;

        Ok((
            Self {
                routing: Arc::new(Mutex::new(routing)),
            },
            event_stream,
        ))
    }

    pub async fn sign_as_node<T: Serialize>(&self, data: &T) -> Result<Signature> {
        let data = utils::serialise(data)?;
        let sig = self.routing.lock().await.sign_as_node(&data).await;
        Ok(Signature::Ed25519(sig))
    }

    pub async fn sign_as_elder<T: Serialize>(
        &self,
        data: &T,
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        let data = utils::serialise(data)?;
        let share = self
            .routing
            .lock()
            .await
            .sign_as_elder(&data, public_key)
            .await
            .map_err(Error::Routing)?;
        Ok(share)
    }

    pub async fn age(&self) -> u8 {
        self.routing.lock().await.age().await
    }

    pub async fn public_key(&self) -> Ed25519PublicKey {
        self.routing.lock().await.public_key().await
    }

    pub async fn section_public_key(&self) -> Option<PublicKey> {
        Some(PublicKey::Bls(
            self.routing
                .lock()
                .await
                .public_key_set()
                .await
                .ok()?
                .public_key(),
        ))
    }

    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.routing
            .lock()
            .await
            .public_key_set()
            .await
            .map_err(Error::Routing)
    }

    pub async fn our_name(&self) -> XorName {
        self.routing.lock().await.name().await
    }

    pub async fn our_connection_info(&mut self) -> SocketAddr {
        self.routing.lock().await.our_connection_info()
    }

    pub async fn our_prefix(&self) -> Prefix {
        self.routing.lock().await.our_prefix().await
    }

    pub async fn matches_our_prefix(&self, name: XorName) -> bool {
        self.routing
            .lock()
            .await
            .matches_our_prefix(&XorName(name.0))
            .await
    }

    pub async fn send_message(
        &mut self,
        itry: Itinerary,
        content: Bytes,
    ) -> Result<(), RoutingError> {
        self.routing.lock().await.send_message(itry, content).await
    }

    pub async fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<()> {
        self.routing
            .lock()
            .await
            .set_joins_allowed(joins_allowed)
            .await
            .map_err(Error::Routing)
    }

    pub async fn our_history(&self) -> SectionChain {
        self.routing.lock().await.our_history().await
    }

    pub async fn our_index(&self) -> Result<usize> {
        self.routing
            .lock()
            .await
            .our_index()
            .await
            .map_err(Error::Routing)
    }

    pub async fn our_elder_names(&self) -> BTreeSet<XorName> {
        self.routing
            .lock()
            .await
            .our_elders()
            .await
            .iter()
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<BTreeSet<_>>()
    }

    pub async fn our_elder_addresses(&self) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .lock()
            .await
            .our_elders()
            .await
            .iter()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.addr()))
            .collect::<Vec<_>>()
    }

    pub async fn our_elder_addresses_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<(XorName, SocketAddr)> {
        self.routing
            .lock()
            .await
            .our_elders_sorted_by_distance_to(&XorName(name.0))
            .await
            .into_iter()
            .map(|p2p_node| (XorName(p2p_node.name().0), *p2p_node.addr()))
            .collect::<Vec<_>>()
    }

    pub async fn our_elder_names_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
        self.routing
            .lock()
            .await
            .our_elders_sorted_by_distance_to(&XorName(name.0))
            .await
            .into_iter()
            .take(count)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub async fn our_adults(&self) -> Vec<XorName> {
        self.routing
            .lock()
            .await
            .our_adults_sorted_by_distance_to(&XorName::default())
            .await
            .into_iter()
            .take(u8::MAX as usize)
            .map(|p2p_node| XorName(p2p_node.name().0))
            .collect::<Vec<_>>()
    }

    pub async fn our_adults_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
        self.routing
            .lock()
            .await
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
        let our_name = self.our_name().await;
        if self.routing.lock().await.is_elder().await {
            AgeGroup::Elder
        } else if self
            .routing
            .lock()
            .await
            .our_adults()
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
