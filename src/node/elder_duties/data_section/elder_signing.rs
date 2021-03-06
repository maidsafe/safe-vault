// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::ElderState;
use sn_data_types::{OwnerType, Result as DtResult, Signing};

#[derive(Clone)]
pub struct ElderSigning {
    id: OwnerType,
    elder_state: ElderState,
}

impl ElderSigning {
    pub fn new(elder_state: ElderState) -> Self {
        Self {
            id: OwnerType::Multi(elder_state.public_key_set().clone()),
            elder_state,
        }
    }
}

impl Signing for ElderSigning {
    fn id(&self) -> OwnerType {
        self.id.clone()
    }

    fn sign<T: serde::Serialize>(&self, data: &T) -> DtResult<sn_data_types::Signature> {
        use sn_data_types::Error as DtError;
        Ok(sn_data_types::Signature::BlsShare(
            futures::executor::block_on(self.elder_state.sign_as_elder(data))
                .map_err(|_| DtError::InvalidOperation)?,
        ))
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
