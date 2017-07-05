// Copyright 2016 MaidSafe.net limited.
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

#[cfg(not(feature = "use-mock-crust"))]
use authority::ClientAuthority;
use authority::ClientManagerAuthority;
use rand::{self, Rand, Rng};
use routing::{EntryAction, EntryActions, ImmutableData, MutableData, Value};
use rust_sodium::crypto::sign;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use utils;

#[macro_export]
macro_rules! assert_match {
    ($e:expr, $p:pat => $r:expr) => {
        match $e {
            $p => $r,
            ref x => panic!("Unexpected {:?} (expecting: {})", x, stringify!($p)),
        }
    };

    ($e:expr, $p:pat) => {
        assert_match!($e, $p => ())
    }
}

/// Toggle iterations for quick test environment variable
pub fn iterations() -> usize {
    use std::env;
    match env::var("QUICK_TEST") {
        Ok(_) => 4,
        Err(_) => 10,
    }
}

/// Generate random vector of the given length.
pub fn gen_vec<T: Rand, R: Rng>(size: usize, rng: &mut R) -> Vec<T> {
    rng.gen_iter().take(size).collect()
}

/// Generate random immutable data
pub fn gen_immutable_data<R: Rng>(size: usize, rng: &mut R) -> ImmutableData {
    ImmutableData::new(gen_vec(size, rng))
}

/// Generate mutable data with the given tag, number of entries and owner.
pub fn gen_mutable_data<R: Rng>(tag: u64,
                                num_entries: usize,
                                owner: sign::PublicKey,
                                rng: &mut R)
                                -> MutableData {
    let entries = gen_mutable_data_entries(num_entries, rng);
    let mut owners = BTreeSet::new();
    let _ = owners.insert(owner);
    unwrap!(MutableData::new(rng.gen(), tag, Default::default(), entries, owners))
}

/// Generate the given number of mutable data entries.
pub fn gen_mutable_data_entries<R: Rng>(num: usize, rng: &mut R) -> BTreeMap<Vec<u8>, Value> {
    let mut entries = BTreeMap::new();
    while entries.len() < num {
        let (key, value) = gen_mutable_data_entry(rng);
        let _ = entries.insert(key, value);
    }

    entries
}

/// Generate mutable data entry (key, value) pair.
pub fn gen_mutable_data_entry<R: Rng>(rng: &mut R) -> (Vec<u8>, Value) {
    let key_size = rng.gen_range(1, 10);
    let key = gen_vec(key_size, rng);

    let value_size = rng.gen_range(1, 10);
    let value = Value {
        content: gen_vec(value_size, rng),
        entry_version: 0,
    };

    (key, value)
}

/// Generate random entry actions to mutate the given mutable data.
pub fn gen_mutable_data_entry_actions<R: Rng>(data: &MutableData,
                                              count: usize,
                                              rng: &mut R)
                                              -> BTreeMap<Vec<u8>, EntryAction> {
    let mut actions = EntryActions::new();

    let modify_count = cmp::min(rng.gen_range(0, count + 1), data.keys().len());
    let insert_count = count - modify_count;

    let keys_to_modify = rand::sample(rng, data.keys().into_iter().cloned(), modify_count);
    for key in keys_to_modify {
        let version = unwrap!(data.get(&key)).entry_version + 1;

        if rng.gen() {
            actions = actions.del(key, version);
        } else {
            let content = gen_vec(10, rng);
            actions = actions.update(key, content, version);
        }
    }

    for _ in 0..insert_count {
        let key = gen_vec(10, rng);
        if data.get(&key).is_some() {
            continue;
        }

        let content = gen_vec(10, rng);
        actions = actions.ins(key, content, 0);
    }

    actions.into()
}

/// Generate random `Client` authority and return it together with its client key.
#[cfg(not(feature = "use-mock-crust"))]
pub fn gen_client_authority() -> (ClientAuthority, sign::PublicKey) {
    use routing::FullId;
    let full_id = FullId::new();

    let client = ClientAuthority {
        client_id: *full_id.public_id(),
        proxy_node_name: rand::random(),
    };

    (client, *full_id.public_id().signing_public_key())
}

/// Generate `ClientManager` authority for the client with the given client key.
pub fn gen_client_manager_authority(client_key: sign::PublicKey) -> ClientManagerAuthority {
    ClientManagerAuthority(utils::client_name_from_key(&client_key))
}
