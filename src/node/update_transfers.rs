// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    transfers::{replica_signing::ReplicaSigningImpl, replicas::ReplicaInfo, Transfers},
    Error, Network, Result,
};
use std::path::Path;

///
pub async fn update_transfers(
    path: &Path,
    transfers: &mut Transfers,
    network_api: &Network,
) -> Result<()> {
    let id = network_api.our_public_key_share().await?;
    let key_index = network_api
        .our_index()
        .await
        .map_err(|_| Error::NoSectionPublicKeySet)?;
    let peer_replicas = network_api.our_public_key_set().await?;
    let signing = ReplicaSigningImpl::new(network_api.clone());
    let info = ReplicaInfo {
        id: id.bls_share().ok_or(Error::ProvidedPkIsNotBlsShare)?,
        key_index,
        peer_replicas,
        section_chain: network_api.section_chain().await,
        signing,
        initiating: false,
    };
    transfers.update_replica_info(info);
    Ok(())
}
