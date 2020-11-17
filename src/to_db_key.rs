// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Result};
use serde::{de::DeserializeOwned, Serialize};
use sn_data_types::{
    BlobAddress, CreditId, DebitId, Keypair, MapAddress, PublicKey, SequenceAddress,
};
use xor_name::XorName;

pub(crate) trait ToDbKey: Serialize {
    /// The encoded string representation of an identifier, used as a key in the context of a
    /// PickleDB <key,value> store.
    fn to_db_key(&self) -> Result<String> {
        let serialised = utils::serialise(&self)?;
        Ok(base64::encode(&serialised))
    }
}

pub fn from_db_key<T: DeserializeOwned>(key: &str) -> Option<T> {
    let decoded = base64::decode(key).ok()?;
    utils::deserialise(&decoded).ok()
}

impl ToDbKey for SequenceAddress {}
impl ToDbKey for Keypair {}
impl ToDbKey for BlobAddress {}
impl ToDbKey for MapAddress {}
impl ToDbKey for PublicKey {}
impl ToDbKey for XorName {}
impl ToDbKey for CreditId {}
impl ToDbKey for DebitId {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Error, Result};
    use bls::SecretKey;
    use sn_data_types::PublicKey;

    #[test]
    fn to_from_db_key() -> Result<()> {
        let key = get_random_pk();
        let serialised = key.to_db_key()?;
        let deserialised = from_db_key(&serialised)
            .ok_or_else(|| Error::Logic("Error deserializing db key".to_string()))?;
        assert_eq!(key, deserialised);
        Ok(())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
