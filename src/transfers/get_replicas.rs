// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{replica_signing::ReplicaSigningImpl, replicas::Replicas, ReplicaInfo};
use crate::{network::Network, node::NodeInfo, Error, Result};
use sn_data_types::{ActorHistory, Credit, CreditAgreementProof, PublicKey, SignedCredit, Token};
use std::collections::BTreeMap;

pub async fn transfer_replicas(
    node_info: &NodeInfo,
    network: &Network,
    user_wallets: BTreeMap<PublicKey, ActorHistory>,
) -> Result<Replicas<ReplicaSigningImpl>> {
    let root_dir = node_info.root_dir.clone();
    let info = replica_info(node_info, network).await?;
    Replicas::new(root_dir, info, user_wallets).await
}

pub async fn replica_info(
    node_info: &NodeInfo,
    network: &Network,
) -> Result<ReplicaInfo<ReplicaSigningImpl>> {
    let id = network
        .our_public_key_share()
        .await?
        .bls_share()
        .ok_or(Error::ProvidedPkIsNotBlsShare)?;
    let key_index = network.our_index().await?;
    let peer_replicas = network.our_public_key_set().await?;
    let signing = ReplicaSigningImpl::new(network.clone());
    Ok(ReplicaInfo {
        id,
        key_index,
        peer_replicas,
        section_chain: network.section_chain().await,
        signing,
    })
}
