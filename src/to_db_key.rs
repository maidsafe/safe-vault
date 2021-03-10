// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use sn_data_types::{
    BlobAddress, CreditId, DebitId, Keypair, MapAddress, PublicKey, RegisterAddress,
};
use xor_name::XorName;

pub(crate) trait ToDbKey: Serialize {
    /// The encoded string representation of an identifier, used as a key in the context of a
    /// PickleDB <key,value> store.
    fn to_db_key(&self) -> Result<String> {
        let serialised = utils::serialise(&self)?;
        Ok(hex::encode(&serialised))
    }
}

#[allow(unused)]
pub fn from_db_key<T: DeserializeOwned>(key: &str) -> Result<T> {
    let decoded = hex::decode(key).map_err(|e| Error::Logic(e.to_string()))?;
    utils::deserialise(&decoded)
}

impl ToDbKey for RegisterAddress {}
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
    use crate::Result;
    use bls::SecretKey;
    use sn_data_types::PublicKey;

    #[test]
    fn to_from_db_key() -> Result<()> {
        let key = get_random_pk();
        let serialised = key.to_db_key()?;
        let deserialised: PublicKey = from_db_key(&serialised)?;
        assert_eq!(key, deserialised);
        Ok(())
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(SecretKey::random().public_key())
    }
}
