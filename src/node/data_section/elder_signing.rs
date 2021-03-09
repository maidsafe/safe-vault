// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// use crate::node::RewardsAndWallets;
use crate::{Error, Network};
use bls::PublicKeySet;
use log::error;
use sn_data_types::{Error as DtError, OwnerType, Result as DtResult, SignatureShare, Signing};

#[derive(Clone)]
pub struct ElderSigning {
    id: OwnerType,
    network: Network,
}

impl ElderSigning {
    pub fn new(network: Network, pk_set: PublicKeySet) -> Self {
        Self {
            id: OwnerType::Multi(pk_set),
            network,
        }
    }
}

impl Signing for ElderSigning {
    fn id(&self) -> OwnerType {
        self.id.clone()
    }

    fn sign<T: serde::Serialize>(&self, data: &T) -> DtResult<sn_data_types::Signature> {
        // use sn_data_types::Error as DtError;

        let (share, index) = futures::executor::block_on(async {
                // let pk = self.network.our_public_key_share().await?;
                 //.await.ok_or(|_| Error::NoSectionPublicKey)?;
                let share = self.network.sign_as_elder(data).await?;
                let index = self.network.our_index().await?;

                Ok((share, index))
            })
            // TODO add more errors for this
            .map_err( |error: Error | {
                error!("Error signing in ElderSigning");
                DtError::InvalidOperation
            })?;

        Ok(sn_data_types::Signature::BlsShare(SignatureShare {
            share,
            index,
        }))
    }

    fn verify<T: serde::Serialize>(&self, sig: &sn_data_types::Signature, data: &T) -> bool {
        let data = match bincode::serialize(data) {
            Ok(data) => data,
            Err(_) => return false,
        };
        use sn_data_types::Signature::*;
        match sig {
            Bls(sig) => {
                if let OwnerType::Multi(set) = self.id() {
                    set.public_key().verify(&sig, data)
                } else {
                    false
                }
            }
            Ed25519(_) => {
                if let OwnerType::Single(public_key) = self.id() {
                    public_key.verify(sig, data).is_ok()
                } else {
                    false
                }
            }
            BlsShare(share) => {
                if let OwnerType::Multi(set) = self.id() {
                    let pubkey_share = set.public_key_share(share.index);
                    pubkey_share.verify(&share.share, data)
                } else {
                    false
                }
            }
        }
    }
}
