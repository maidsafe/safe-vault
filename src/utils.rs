// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use self::rust_sodium::crypto::sign;
#[cfg(any(test, feature = "use-mock-crust", feature = "use-mock-routing"))]
pub use fake_clock::FakeClock as Instant;
use log::error;
use maidsafe_utilities::serialisation;
#[cfg(feature = "use-mock-crypto")]
use routing::mock_crypto::rust_sodium;
use routing::{sha3, MutableData, Value, XorName};
#[cfg(not(feature = "use-mock-crypto"))]
use rust_sodium;
use serde::Serialize;
use serde_derive::{Deserialize, Serialize};
use std::collections;
#[cfg(feature = "use-mock-crust")]
use std::collections::hash_map::DefaultHasher;
#[cfg(feature = "use-mock-crust")]
use std::hash::BuildHasherDefault;
#[cfg(not(any(test, feature = "use-mock-crust", feature = "use-mock-routing")))]
pub use std::time::Instant;
use tiny_keccak;

#[derive(
    Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize,
)]
pub struct SecureHash(sha3::Digest256);

/// Compute secure hash of the given value.
pub fn secure_hash<T: Serialize>(value: &T) -> SecureHash {
    serialisation::serialise(value)
        .map(|data| SecureHash(tiny_keccak::sha3_256(&data)))
        .unwrap_or_else(|_| {
            error!("Serialisation failure");
            Default::default()
        })
}

// Note: for testing with mock crust, use collections with deterministic hashing.

#[cfg(feature = "use-mock-crust")]
pub type HashMap<K, V> = collections::HashMap<K, V, BuildHasherDefault<DefaultHasher>>;
#[cfg(not(feature = "use-mock-crust"))]
pub type HashMap<K, V> = collections::HashMap<K, V>;

#[cfg(feature = "use-mock-crust")]
pub type HashSet<T> = collections::HashSet<T, BuildHasherDefault<DefaultHasher>>;
#[cfg(not(feature = "use-mock-crust"))]
pub type HashSet<T> = collections::HashSet<T>;

pub fn client_name_from_key(key: &sign::PublicKey) -> XorName {
    XorName(tiny_keccak::sha3_256(&key[..]))
}

pub fn mdata_shell_hash(data: &MutableData) -> SecureHash {
    let shell = (
        *data.name(),
        data.tag(),
        data.version(),
        data.owners().clone(),
        data.permissions().clone(),
    );
    secure_hash(&shell)
}

pub fn mdata_value_hash(value: &Value) -> SecureHash {
    secure_hash(&value)
}

/// Verify that the client with `client_name` is the owner of `data`.
pub fn verify_mdata_owner(data: &MutableData, client_name: &XorName) -> bool {
    data.owners()
        .iter()
        .map(|owner_key| client_name_from_key(owner_key))
        .any(|name| name == *client_name)
}
