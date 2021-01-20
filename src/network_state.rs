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

// What things do we _need_ to snapshot?
// - Public/Secret KeySet
// - ..
// What things do we _need_ to access most current state of?
// - ..

use crate::{utils, Network, Result};
use bls::{PublicKeySet, PublicKeyShare, SecretKeyShare};
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use itertools::Itertools;
use serde::Serialize;
use sn_data_types::{PublicKey, Signature, SignatureShare};
use sn_messaging::TransientElderKey;
use sn_routing::SectionProofChain;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use xor_name::{Prefix, XorName};

#[derive(Clone)]
///
pub enum NodeState {
    ///
    Adult(AdultState),
    ///
    Elder(ElderState),
}

impl NodeState {
    /// Static state
    pub fn node_id(&self) -> Ed25519PublicKey {
        match self {
            Self::Adult(state) => state.node_id,
            Self::Elder(state) => state.node_id,
        }
    }
}

#[derive(Clone)]
///
pub struct AdultState {
    info: NodeInfo,
    prefix: Prefix,
    node_name: XorName,
    node_id: Ed25519PublicKey,
    public_key_set: PublicKeySet,
    section_proof_chain: SectionProofChain,
    elders: Vec<(XorName, SocketAddr)>,
    adult_reader: AdultReader,
}

impl AdultState {
    /// Takes a snapshot of current state
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub async fn new(info: NodeInfo, network: Network) -> Result<Self> {
        Ok(Self {
            info,
            prefix: network.our_prefix().await,
            node_name: network.name().await,
            node_id: network.public_key().await,
            public_key_set: network.public_key_set().await?,
            section_proof_chain: network.our_history().await,
            elders: network.our_elder_addresses().await,
            adult_reader: AdultReader::new(network.clone()),
        })
    }

    /// Static state
    pub fn info(&self) -> &NodeInfo {
        &self.info
    }

    /// Static state
    pub fn node_name(&self) -> XorName {
        self.node_name
    }

    /// Static state
    pub fn node_id(&self) -> Ed25519PublicKey {
        self.node_id
    }
}

#[derive(Clone)]
///
pub struct ElderState {
    info: NodeInfo,
    prefix: Prefix,
    node_name: XorName,
    node_id: Ed25519PublicKey,
    key_index: usize,
    public_key_set: PublicKeySet,
    secret_key_share: SecretKeyShare,
    section_proof_chain: SectionProofChain,
    elders: Vec<(XorName, SocketAddr)>,
    adult_reader: AdultReader,
    interaction: NodeInteraction,
}

impl ElderState {
    /// Takes a snapshot of current state
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub async fn new(info: &NodeInfo, network: Network) -> Result<Self> {
        Ok(Self {
            info: info.clone(),
            prefix: network.our_prefix().await,
            node_name: network.name().await,
            node_id: network.public_key().await,
            key_index: network.our_index().await?,
            public_key_set: network.public_key_set().await?,
            secret_key_share: network.secret_key_share().await?,
            section_proof_chain: network.our_history().await,
            elders: network.our_elder_addresses().await,
            adult_reader: AdultReader::new(network.clone()),
            interaction: NodeInteraction::new(network),
        })
    }

    /// Use routing to send a message to a client peer address
    pub async fn send_to_client(&self, peer_addr: SocketAddr, bytes: Bytes) -> Result<()> {
        self.interaction.send_to_client(peer_addr, bytes).await
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
    pub fn info(&self) -> &NodeInfo {
        &self.info
    }

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
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Static state
    pub fn public_key_share(&self) -> PublicKeyShare {
        self.public_key_set.public_key_share(self.key_index)
    }

    /// Static state
    pub fn secret_key_share(&self) -> &SecretKeyShare {
        &self.secret_key_share
    }

    /// Static state
    pub fn section_proof_chain(&self) -> &SectionProofChain {
        &self.section_proof_chain
    }

    /// Static state
    pub async fn elder_names(&self) -> BTreeSet<&XorName> {
        self.elders.iter().map(|(name, _)| name).collect()
    }

    /// Static state
    pub async fn elders(&self) -> &Vec<(XorName, SocketAddr)> {
        &self.elders
    }

    /// Static state
    pub async fn elders_sorted_by_distance_to(
        &self,
        name: &XorName,
    ) -> Vec<&(XorName, SocketAddr)> {
        self.elders
            .iter()
            .sorted_by(|(lhs, _), (rhs, _)| name.cmp_distance(lhs, rhs))
            .collect()
    }

    /// Creates a detached BLS signature share of `data` if the `self` holds a BLS keypair share.
    pub fn sign_as_elder<T: Serialize>(&self, data: &T) -> Result<Signature> {
        let data = utils::serialise(data)?;
        let index = self.key_index();
        let bls_secret_key = self.secret_key_share();
        Ok(Signature::BlsShare(SignatureShare {
            index,
            share: bls_secret_key.sign(data),
        }))
    }

    /// Creates a detached Ed25519 signature of `data`.
    pub fn sign_as_node<T: Serialize>(&self, data: &T) -> Result<Signature> {
        // NB: TEMP USE OF BLS SIG HERE
        let data = utils::serialise(data)?;
        let index = self.key_index();
        let bls_secret_key = self.secret_key_share();
        Ok(Signature::BlsShare(SignatureShare {
            index,
            share: bls_secret_key.sign(data),
        }))
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

use bytes::Bytes;

#[derive(Clone)]
pub struct NodeInteraction {
    network: Network,
}

impl NodeInteraction {
    ///
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    /// Use routing to send a message to a client peer address
    pub async fn send_to_client(&self, peer_addr: SocketAddr, bytes: Bytes) -> Result<()> {
        self.network
            .send_message_to_client(peer_addr, bytes)
            .await?;

        Ok(())
    }

    ///
    pub async fn set_joins_allowed(&mut self, joins_allowed: bool) -> Result<()> {
        self.network.set_joins_allowed(joins_allowed).await
    }
}

/// Info about the node used
/// to init its various dbs
/// (among things).
#[derive(Clone)]
pub struct NodeInfo {
    ///
    pub genesis: bool,
    ///
    pub node_id: PublicKey,
    ///
    pub root_dir: PathBuf,
    ///
    pub init_mode: utils::Init,
    /// Upper limit in bytes for allowed network storage on this node.
    /// An Adult would be using the space for chunks,
    /// while an Elder uses it for metadata.
    pub max_storage_capacity: u64,
    /// The key used by the node to receive earned rewards.
    pub reward_key: PublicKey,
}

impl NodeInfo {
    ///
    pub fn path(&self) -> &Path {
        self.root_dir.as_path()
    }
}
