// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#[cfg(any(test, feature = "use-mock-crust", feature = "use-mock-routing"))]
pub use fake_clock::FakeClock as Instant;
use maidsafe_utilities::serialisation;
use routing::{MutableData, Value, XorName, sha3};
use rust_sodium::crypto::sign;
use serde::Serialize;
use std::collections;
#[cfg(feature = "use-mock-crust")]
use std::collections::hash_map::DefaultHasher;
#[cfg(feature = "use-mock-crust")]
use std::hash::BuildHasherDefault;
#[cfg(not(any(test, feature = "use-mock-crust", feature = "use-mock-routing")))]
pub use std::time::Instant;
use tiny_keccak;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
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
    let shell = (*data.name(),
                 data.tag(),
                 data.version(),
                 data.owners().clone(),
                 data.permissions().clone());
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
