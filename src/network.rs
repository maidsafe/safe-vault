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

// TODO: use only sn_data_types
use bls::{PublicKeySet, PublicKeyShare as BlsPublicKeyShare};

use futures::lock::Mutex;
use log::debug;
use serde::Serialize;
use sn_data_types::{Error as DtError, PublicKey, Result as DtResult, Signature};
use sn_messaging::Itinerary;
use sn_routing::{
    Config as RoutingConfig, Error as RoutingError, EventStream, Routing as RoutingNode,
    SectionChain,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{collections::BTreeSet, path::PathBuf};
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

    /// Sign with our node's ED25519 key
    pub async fn sign_as_node<T: Serialize>(&self, data: &T) -> Result<Signature> {
        let data = utils::serialise(data)?;
        let sig = self.routing.lock().await.sign_as_node(&data).await;
        Ok(Signature::Ed25519(sig))
    }

    /// Sign with our BLS PK Share
    pub async fn sign_as_elder<T: Serialize>(
        &self,
        data: &T,
        // public_key_share: PublicKey,
    ) -> Result<bls::SignatureShare> {
        //TODO: just use PKshare from routing direct here?
        // This has to be a Dt error for signing trait

        let bls_pk = self
            .section_public_key()
            .await
            .ok_or(Error::NoSectionPublicKey)?
            .bls()
            .ok_or(Error::ProvidedPkIsNotBlsShare)?;
        // debug!("pre-sign-as-elder {:?}", public_key_share);
        // let bls_pk = public_key_share.bls_share().ok_or(DtError::InvalidOperation)?;
        debug!("post-sign-as-elder");

        let data = utils::serialise(data)?;
        let share = self
            .routing
            .lock()
            .await
            .sign_as_elder(&data, &bls_pk)
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

    pub async fn sibling_public_key(&self) -> Option<PublicKey> {
        let sibling_prefix = self.our_prefix().await.sibling();
        self.routing
            .lock()
            .await
            .section_key(&sibling_prefix)
            .await
            .map(|key| PublicKey::Bls(key))
    }

    pub async fn our_public_key_set(&self) -> Result<bls::PublicKeySet> {
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

    pub async fn section_chain(&self) -> SectionChain {
        self.routing.lock().await.section_chain().await
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
        itinerary: Itinerary,
        content: Bytes,
    ) -> Result<(), RoutingError> {
        self.routing
            .lock()
            .await
            .send_message(itinerary, content)
            .await
    }

    pub async fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<()> {
        self.routing
            .lock()
            .await
            .set_joins_allowed(joins_allowed)
            .await
            .map_err(Error::Routing)
    }

    /// get our PKshare
    pub async fn our_public_key_share(&self) -> Result<PublicKey> {
        let index = self.our_index().await?;
        Ok(PublicKey::from(
            self.our_public_key_set().await?.public_key_share(index),
        ))
    }

    /// BLS key index in routing for key shares
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

        let is_elder;
        {
            is_elder = self.routing.lock().await.is_elder().await;
        }

        let is_adult;
        {
            is_adult = self
                .routing
                .lock()
                .await
                .our_adults()
                .await
                .iter()
                .any(|adult| *adult.name() == our_name)
        }

        if is_elder {
            AgeGroup::Elder
        } else if is_adult {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        }
    }
}
