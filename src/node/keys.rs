// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{network::Routing, utils};
use bls::PublicKeySet;
use safe_nd::{BlsProof, BlsProofShare, Ed25519Proof, Proof, PublicKey, Signature, SignatureShare};
use serde::Serialize;

#[derive(Clone)]
pub struct NodeSigningKeys<N: Routing + Clone> {
    routing: N,
}

impl<N: Routing + Clone> NodeSigningKeys<N> {
    pub fn new(routing: N) -> Self {
        Self { routing }
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        let index = self.routing.our_index().ok()?;
        let share = self.routing.public_key_set().ok()?.public_key_share(index);
        Some(PublicKey::BlsShare(share))
    }

    /// Signs with the BLS if any, else the Ed25519.
    pub fn sign<T: Serialize>(&self, data: &T) -> Signature {
        let data = utils::serialise(data);
        if let Some(sig) = self.sign_using_bls(&data) {
            sig
        } else {
            self.sign_using_ed25519(&data)
        }
    }

    pub fn produce_proof<T: Serialize>(&self, data: &T) -> Proof {
        match self.sign(data) {
            Signature::BlsShare(share) => Proof::BlsShare(BlsProofShare {
                index: share.index,
                signature_share: share.share,
                public_key_set: match self.public_key_set() {
                    Some(key_set) => key_set,
                    None => unreachable!(), // this is admittedly not very elegant code..
                },
            }),
            Signature::Ed25519(signature) => Proof::Ed25519(Ed25519Proof {
                public_key: match self.public_key() {
                    Some(PublicKey::Ed25519(key)) => key,
                    _ => unreachable!(), // this is admittedly not very elegant code..
                },
                signature,
            }),
            Signature::Bls(signature) => Proof::Bls(BlsProof {
                public_key: match self.public_key() {
                    Some(PublicKey::Bls(key)) => key,
                    _ => unreachable!(), // this is admittedly not very elegant code..
                },
                signature,
            }),
        }
    }

    fn public_key_set(&self) -> Option<PublicKeySet> {
        Some(self.routing.public_key_set().ok()?.clone())
    }

    /// Creates a detached Ed25519 signature of `data`.
    fn sign_using_ed25519<T: AsRef<[u8]>>(&self, _data: &T) -> Signature {
        unimplemented!()
        //Signature::Ed25519(self.ed25519.sign(data.as_ref()))
    }

    /// Creates a detached BLS signature share of `data` if the `self` holds a BLS keypair share.
    fn sign_using_bls<T: AsRef<[u8]>>(&self, data: &T) -> Option<Signature> {
        let index = self.routing.our_index().ok()?;
        let bls_secret_key = self.routing.secret_key_share().ok()?;
        Some(Signature::BlsShare(SignatureShare {
            index,
            share: bls_secret_key.sign(data),
        }))
    }
}
