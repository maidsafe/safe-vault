// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// we want a consistent view of the elder constellation

// when we have an ElderChange, underlying sn_routing will
// return the new key set on querying (caveats in high churn?)
// but we want a snapshot of the state to work with, before we use the new keys

// so, to correctly transition between keys, we need to not mix states,
// and keep a tidy order, i.e. use one constellation at a time.

use crate::{chunk_store::UsedSpace, Network, Result};
use bls::{PublicKeySet, PublicKeyShare};
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use itertools::Itertools;
use log::debug;
use serde::Serialize;
use sn_data_types::{PublicKey, Signature, SignatureShare};
use sn_messaging::client::TransientElderKey;
use sn_routing::SectionChain;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use xor_name::{Prefix, XorName};

// we want a consistent view of the elder constellation

// when we have an ElderChange, underlying sn_routing will
// return the new key set on querying (caveats in high churn?)
// but we want a snapshot of the state to work with, before we use the new keys

// so, to correctly transition between keys, we need to not mix states,
// and keep a tidy order, i.e. use one constellation at a time.

#[derive(Clone)]
///
pub enum NodeState {
    ///
    Infant(Ed25519PublicKey),
    ///
    Adult(AdultState),
    ///
    Elder(ElderState),
}

impl NodeState {
    /// Static state
    pub fn node_id(&self) -> Ed25519PublicKey {
        match self {
            Self::Infant(id) => *id,
            Self::Adult(state) => state.node_id,
            Self::Elder(state) => state.node_id,
        }
    }

    ///
    pub fn node_name(&self) -> XorName {
        PublicKey::Ed25519(self.node_id()).into()
    }
}

#[derive(Clone)]
///
pub struct AdultState {
    prefix: Prefix,
    node_name: XorName,
    node_id: Ed25519PublicKey,
    section_chain: SectionChain,
    elders: Vec<(XorName, SocketAddr)>,
    adult_reader: AdultReader,
    node_signing: NodeSigning,
}

impl AdultState {
    /// Takes a snapshot of current state
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub async fn new(network: Network) -> Result<Self> {
        Ok(Self {
            prefix: network.our_prefix().await,
            node_name: network.our_name().await,
            node_id: network.public_key().await,
            section_chain: network.section_chain().await,
            elders: network.our_elder_addresses().await,
            adult_reader: AdultReader::new(network.clone()),
            node_signing: NodeSigning::new(network),
        })
    }

    // ---------------------------------------------------
    // ----------------- STATIC STATE --------------------
    // ---------------------------------------------------

    /// Static state
    pub fn node_name(&self) -> XorName {
        self.node_name
    }

    /// Static state
    pub fn node_id(&self) -> Ed25519PublicKey {
        self.node_id
    }

    /// Static state
    pub fn section_chain(&self) -> &SectionChain {
        &self.section_chain
    }

    /// "Sort of" static; this is calling into routing layer
    /// but the underlying keys will not change.
    pub async fn sign_as_node<T: Serialize>(&self, data: &T) -> Result<Signature> {
        self.node_signing.sign_as_node(&data).await
    }
}

#[derive(Clone)]
///
pub struct ElderState {
    prefix: Prefix,
    node_name: XorName,
    node_id: Ed25519PublicKey,
    key_index: usize,
    public_key_set: PublicKeySet,
    sibling_public_key: Option<PublicKey>,
    section_chain: SectionChain,
    elders: Vec<(XorName, SocketAddr)>,
    adult_reader: AdultReader,
    interaction: NodeInteraction,
    node_signing: NodeSigning,
}

impl ElderState {
    /// Takes a snapshot of current state
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub async fn new(network: Network) -> Result<Self> {
        debug!(
            ">> setting up elderstate, PK from routing is: {:?}",
            PublicKey::Bls(network.public_key_set().await?.public_key())
        );

        Ok(Self {
            prefix: network.our_prefix().await,
            node_name: network.our_name().await,
            node_id: network.public_key().await,
            key_index: network.our_index().await?,
            public_key_set: network.public_key_set().await?,
            sibling_public_key: network.sibling_public_key().await,
            section_chain: network.section_chain().await,
            elders: network.our_elder_addresses().await,
            adult_reader: AdultReader::new(network.clone()),
            interaction: NodeInteraction::new(network.clone()),
            node_signing: NodeSigning::new(network),
        })
    }

    ///
    pub async fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<()> {
        self.interaction.set_joins_allowed(joins_allowed).await
    }

    // ---------------------------------------------------
    // ----------------- DYNAMIC STATE -------------------
    // ---------------------------------------------------

    /// Dynamic state
    pub async fn adults(&self) -> Vec<XorName> {
        self.adult_reader.our_adults().await
    }

    /// Dynamic state
    pub async fn adults_sorted_by_distance_to(&self, name: &XorName, count: usize) -> Vec<XorName> {
        self.adult_reader
            .our_adults_sorted_by_distance_to(name, count)
            .await
    }

    // ---------------------------------------------------
    // ----------------- STATIC STATE --------------------
    // ---------------------------------------------------

    /// Static state
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Static state
    pub fn node_name(&self) -> XorName {
        self.node_name
    }

    /// Static state
    pub fn node_id(&self) -> Ed25519PublicKey {
        self.node_id
    }

    /// Static state
    pub fn key_index(&self) -> usize {
        self.key_index
    }

    /// Static state
    pub fn section_public_key(&self) -> PublicKey {
        PublicKey::Bls(self.public_key_set().public_key())
    }

    /// Static state
    pub fn sibling_public_key(&self) -> Option<PublicKey> {
        self.sibling_public_key
    }

    /// Static state
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Static state
    pub fn public_key_share(&self) -> PublicKeyShare {
        self.public_key_set.public_key_share(self.key_index)
    }

    /// Static state
    pub fn section_chain(&self) -> &SectionChain {
        &self.section_chain
    }

    /// Static state
    pub fn elder_names(&self) -> BTreeSet<&XorName> {
        self.elders.iter().map(|(name, _)| name).collect()
    }

    /// Static state
    pub fn elders(&self) -> &Vec<(XorName, SocketAddr)> {
        &self.elders
    }

    /// Static state
    pub fn elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<&(XorName, SocketAddr)> {
        self.elders
            .iter()
            .sorted_by(|(lhs, _), (rhs, _)| name.cmp_distance(lhs, rhs))
            .collect()
    }

    /// Creates a detached BLS signature share of `data` if the `self` holds a BLS keypair share.
    pub async fn sign_as_elder<T: Serialize>(&self, data: &T) -> Result<SignatureShare> {
        let share = self
            .node_signing
            .sign_as_elder(data, &self.public_key_set().public_key())
            .await?;
        Ok(SignatureShare {
            share,
            index: self.key_index,
        })
    }

    /// "Sort of" static; this is calling into routing layer
    /// but the underlying keys will not change.
    pub async fn sign_as_node<T: Serialize>(&self, data: &T) -> Result<Signature> {
        self.node_signing.sign_as_node(&data).await
    }

    // ------ DEPRECATE? -------------

    /// Static state
    pub fn elder_key(&self) -> TransientElderKey {
        TransientElderKey {
            node_id: self.node_id,
            bls_key: self.public_key_share(),
            bls_share_index: self.key_index(),
            bls_public_key_set: self.public_key_set().clone(),
        }
    }
}

#[derive(Clone)]
struct AdultReader {
    network: Network,
}

impl AdultReader {
    /// Access to the current state of our adult constellation
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    /// Dynamic state
    pub async fn our_adults(&self) -> Vec<XorName> {
        self.network.our_adults().await
    }

    /// Dynamic state
    pub async fn our_adults_sorted_by_distance_to(
        &self,
        name: &XorName,
        count: usize,
    ) -> Vec<XorName> {
        self.network
            .our_adults_sorted_by_distance_to(name, count)
            .await
    }
}

#[derive(Clone)]
pub struct NodeSigning {
    network: Network,
}

impl NodeSigning {
    ///
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    // "Sort of" static; this is calling into routing layer
    // but the underlying keys will not change.
    pub async fn sign_as_node<T: Serialize>(&self, data: &T) -> Result<Signature> {
        self.network.sign_as_node(&data).await
    }

    //
    pub async fn sign_as_elder<T: Serialize>(
        &self,
        data: &T,
        public_key: &bls::PublicKey,
    ) -> Result<bls::SignatureShare> {
        self.network.sign_as_elder(data, public_key).await
    }
}

#[derive(Clone)]
pub struct NodeInteraction {
    network: Network,
}

impl NodeInteraction {
    ///
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    ///
    pub async fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<()> {
        self.network.set_joins_allowed(joins_allowed).await
    }
}

/// Info about the node.
#[derive(Clone)]
pub struct NodeInfo {
    ///
    pub genesis: bool,
    ///
    pub root_dir: PathBuf,
    ///
    pub used_space: UsedSpace,
    /// The key used by the node to receive earned rewards.
    pub reward_key: PublicKey,
}

impl NodeInfo {
    ///
    pub fn path(&self) -> &Path {
        self.root_dir.as_path()
    }
}
