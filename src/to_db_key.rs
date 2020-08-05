// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::utils;
use safe_nd::{BlobAddress, ClientPublicId, MapAddress, PublicId, PublicKey, SequenceAddress};
use serde::{de::DeserializeOwned, Serialize};
use xor_name::XorName;

pub(crate) trait ToDbKey: Serialize {
    /// The encoded string representation of an identifier, used as a key in the context of a
    /// PickleDB <key,value> store.
    fn to_db_key(&self) -> String {
        let serialised = utils::serialise(&self);
        base64::encode(&serialised)
    }
}

pub fn from_db_key<T: DeserializeOwned>(key: &str) -> Option<T> {
    let decoded = base64::decode(key).ok()?;
    Some(utils::deserialise(&decoded))
}

impl ToDbKey for SequenceAddress {}
impl ToDbKey for ClientPublicId {}
impl ToDbKey for BlobAddress {}
impl ToDbKey for MapAddress {}
impl ToDbKey for PublicId {}
impl ToDbKey for PublicKey {}
impl ToDbKey for XorName {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;
    use safe_nd::PublicKey;
    use threshold_crypto::SecretKey;

    #[test]
    fn to_from_db_key() -> Result<()> {
        let key = get_random_pk();
        let serialised = key.to_db_key();
        let deserialised = from_db_key(&serialised).unwrap();
        assert_eq!(key, deserialised);
        Ok(())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
