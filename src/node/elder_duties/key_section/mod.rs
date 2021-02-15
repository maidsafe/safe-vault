// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod transfers;

use self::transfers::{replica_signing::ReplicaSigning, replicas::Replicas, Transfers};
use crate::{
    capacity::RateLimit,
    node::node_ops::{KeySectionDuty, NodeOperation},
    ElderState, NodeInfo, Result,
};
use log::{info, trace};
use sn_data_types::{PublicKey, TransferPropagated};
use sn_routing::Prefix;
use transfers::replica_signing::ReplicaSigningImpl;

#[derive(Clone, Debug)]
///
pub struct ReplicaInfo<T>
where
    T: ReplicaSigning,
{
    id: bls::PublicKeyShare,
    key_index: usize,
    peer_replicas: bls::PublicKeySet,
    section_proof_chain: sn_routing::SectionProofChain,
    signing: T,
    initiating: bool,
}

/// A Key Section interfaces with clients,
/// who are essentially a public key,
/// (hence the name Key Section), used by
/// a specific socket address.
/// The Gateway deals with onboarding (handshakes etc)
/// and routing messages back and forth to clients.
/// Payments deals with the payment for data writes,
/// while transfers deals with sending tokens between keys.
pub struct KeySection {
    transfers: Transfers,
    elder_state: ElderState,
}

impl KeySection {
    pub async fn new(
        rate_limit: RateLimit,
        node_info: &NodeInfo,
        elder_state: ElderState,
    ) -> Result<Self> {
        let replicas = Self::transfer_replicas(node_info, elder_state.clone());
        let transfers = Transfers::new(replicas, rate_limit);
        Ok(Self {
            transfers,
            elder_state,
        })
    }

    ///
    pub async fn increase_full_node_count(&mut self, node_id: PublicKey) -> Result<()> {
        self.transfers.increase_full_node_count(node_id)
    }

    /// Initiates as first node in a network.
    pub async fn init_genesis_node(&mut self, genesis: TransferPropagated) -> Result<()> {
        self.transfers.genesis(genesis).await
    }

    /// Issues queries to Elders of the section
    /// as to catch up with shares state and
    /// start working properly in the group.
    pub async fn catchup_with_section(&mut self) -> Result<Vec<NetworkDuty>> {
        // currently only at2 replicas need to catch up
        self.transfers.catchup_with_replicas().await
    }

    pub async fn set_node_join_flag(&mut self, joins_allowed: bool) -> Result<Vec<NetworkDuty>> {
        match self.elder_state.set_joins_allowed(joins_allowed).await {
            Ok(()) => {
                info!("Successfully set joins_allowed to true");
                Ok(vec![])
            }
            Err(e) => Err(e),
        }
    }

    // Update our replica with the latest keys
    pub fn elders_changed(&mut self, elder_state: ElderState, rate_limit: RateLimit) {
        // TODO: Query sn_routing for info for [new_section_key]
        // specifically (regardless of how far back that was) - i.e. not the current info!
        let id = elder_state.public_key_share();
        let key_index = elder_state.key_index();
        let peer_replicas = elder_state.public_key_set().clone();
        let signing = ReplicaSigningImpl::new(elder_state.clone());
        let info = ReplicaInfo {
            id,
            key_index,
            peer_replicas,
            section_proof_chain: elder_state.section_proof_chain().clone(),
            signing,
            initiating: false,
        };
        self.transfers.update_replica_info(info, rate_limit);
    }

    /// When section splits, the Replicas in either resulting section
    /// also split the responsibility of their data.
    pub async fn split_section(&mut self, prefix: Prefix) -> Result<()> {
        self.transfers.split_section(prefix).await
    }

    pub async fn process_key_section_duty(&self, duty: KeySectionDuty) -> Result<Vec<NetworkDuty>> {
        trace!("Processing as Elder KeySection");
        use KeySectionDuty::*;
        match duty {
            RunAsTransfers(duty) => self.transfers.process_transfer_duty(&duty).await,
            NoOp => Ok(vec![]),
        }
    }

    fn transfer_replicas(
        node_info: &NodeInfo,
        elder_state: ElderState,
    ) -> Replicas<ReplicaSigningImpl> {
        let root_dir = node_info.root_dir.clone();
        let id = elder_state.public_key_share();
        let key_index = elder_state.key_index();
        let peer_replicas = elder_state.public_key_set().clone();
        let signing = ReplicaSigningImpl::new(elder_state.clone());
        let info = ReplicaInfo {
            id,
            key_index,
            peer_replicas,
            section_proof_chain: elder_state.section_proof_chain().clone(),
            signing,
            initiating: true,
        };
        Replicas::new(root_dir, info)
    }
}
