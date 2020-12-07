// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Network};
use bls::PublicKeySet;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use serde::Serialize;
use sn_data_types::{Signature, SignatureShare, TransientElderKey as ElderKey};
use xor_name::XorName;

#[derive(Clone)]
pub struct NodeSigningKeys {
    routing: Network,
}

impl NodeSigningKeys {
    pub fn new(routing: Network) -> Self {
        Self { routing }
    }

    pub async fn node_id(&self) -> Ed25519PublicKey {
        self.routing.public_key().await
    }

    pub async fn name(&self) -> XorName {
        self.routing.name().await
    }

    pub async fn elder_key(&self) -> Option<ElderKey> {
        let bls_share_index = self.routing.our_index().await.ok()?;
        let bls_public_key_set = self.public_key_set().await?;
        let bls_key = bls_public_key_set.public_key_share(bls_share_index);

        Some(ElderKey {
            node_id: self.node_id().await,
            bls_key,
            bls_share_index,
            bls_public_key_set,
        })
    }

    pub async fn public_key_set(&self) -> Option<PublicKeySet> {
        Some(self.routing.public_key_set().await.ok()?)
    }

    // pub async fn section_name(&self) -> XorName {
    //     self.routing.section_name().await
    // }

    /// Creates a detached Ed25519 signature of `data`.
    pub async fn sign_as_node<T: Serialize>(&self, data: &T) -> Signature {
        self.routing.sign_as_node(data).await
    }

    /// Creates a detached BLS signature share of `data` if the `self` holds a BLS keypair share.
    pub async fn sign_as_elder<T: Serialize>(&self, data: &T) -> Option<Signature> {
        let data = utils::serialise(data);
        let index = self.routing.our_index().await.ok()?;
        let bls_secret_key = self.routing.secret_key_share().await.ok()?;
        Some(Signature::BlsShare(SignatureShare {
            index,
            share: bls_secret_key.sign(data),
        }))
    }
}
