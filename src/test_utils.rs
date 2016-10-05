// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![cfg(feature = "use-mock-crust")]

use rand::Rng;
use routing::{AppendedData, DataIdentifier, Filter, FullId, ImmutableData, PrivAppendableData,
              PubAppendableData, StructuredData};
use rust_sodium::crypto::box_;
use std::collections::BTreeSet;

/// Creates random immutable data - tests only
pub fn random_immutable_data<R: Rng>(size: usize, rng: &mut R) -> ImmutableData {
    ImmutableData::new(rng.gen_iter().take(size).collect())
}

/// Creates random structured data - tests only
pub fn random_structured_data<R: Rng>(type_tag: u64,
                                      full_id: &FullId,
                                      rng: &mut R)
                                      -> StructuredData {
    random_structured_data_with_size(type_tag, full_id, 10, rng)
}

/// Creates random structured data with size - tests only
pub fn random_structured_data_with_size<R: Rng>(type_tag: u64,
                                                full_id: &FullId,
                                                size: usize,
                                                rng: &mut R)
                                                -> StructuredData {
    StructuredData::new(type_tag,
                        rng.gen(),
                        0,
                        rng.gen_iter().take(size).collect(),
                        vec![full_id.public_id().signing_public_key().clone()],
                        vec![],
                        Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test")
}

/// Creates random public appendable data - tests only
pub fn random_pub_appendable_data<R: Rng>(full_id: &FullId, rng: &mut R) -> PubAppendableData {
    random_pub_appendable_data_with_size(full_id, 0, rng)
}

/// Creates random public appendable data with size - tests only
pub fn random_pub_appendable_data_with_size<R: Rng>(full_id: &FullId, size: usize, rng: &mut R) -> PubAppendableData {
    let mut current_owner_keys = vec![full_id.public_id().signing_public_key().clone()];
    if size > 0 {
        for _ in 0..size / 32 {
            current_owner_keys.push(full_id.public_id().signing_public_key().clone());
        }
    }
    PubAppendableData::new(rng.gen(),
                           0,
                           current_owner_keys,
                           vec![],
                           BTreeSet::new(),
                           Filter::black_list(None),
                           Some(full_id.signing_private_key()))
        .expect("Cannot create public appendable data for test")
}

/// Creates a new public appendable data with an incremented version number
pub fn pub_appendable_data_version_up<R: Rng>(full_id: &FullId,
                                              old_ad: &PubAppendableData,
                                              rng: &mut R)
                                              -> PubAppendableData {
    let mut new_ad = PubAppendableData::new(*old_ad.name(),
                                            old_ad.get_version() + 1,
                                            vec![full_id.public_id().signing_public_key().clone()],
                                            vec![full_id.public_id().signing_public_key().clone()],
                                            BTreeSet::new(),
                                            Filter::black_list(None),
                                            None)
        .expect("Cannot create public appendable data for test");
    for data in old_ad.get_data() {
        new_ad.append(data.clone());
    }
    let pointer = DataIdentifier::Structured(rng.gen(), 12345);
    let appended_data = unwrap_result!(AppendedData::new(pointer,
                                                         full_id.public_id()
                                                             .signing_public_key()
                                                             .clone(),
                                                         full_id.signing_private_key()));
    new_ad.append(appended_data);
    let _ = new_ad.add_signature(full_id.signing_private_key());
    new_ad
}

/// Creates random private appendable data - tests only
pub fn random_priv_appendable_data<R: Rng>(full_id: &FullId,
                                           encrypt_key: box_::PublicKey,
                                           rng: &mut R)
                                           -> PrivAppendableData {
    random_priv_appendable_data_with_size(full_id, encrypt_key, 0, rng)
}

/// Creates random private appendable data with size - tests only
pub fn random_priv_appendable_data_with_size<R: Rng>(full_id: &FullId,
                                                     encrypt_key: box_::PublicKey,
                                                     size: usize,
                                                     rng: &mut R)
                                                     -> PrivAppendableData {
    let mut current_owner_keys = vec![full_id.public_id().signing_public_key().clone()];
    if size > 0 {
        for _ in 0..size / 32 {
            current_owner_keys.push(full_id.public_id().signing_public_key().clone());
        }
    }
    PrivAppendableData::new(rng.gen(),
                            0,
                            current_owner_keys,
                            vec![],
                            BTreeSet::new(),
                            Filter::black_list(None),
                            encrypt_key,
                            Some(full_id.signing_private_key()))
        .expect("Cannot create private appendable data for test")
}
