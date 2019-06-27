// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Implementation of the "Vault" node for the SAFE Network.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

mod action;
mod adult;
mod chunk_store;
mod coins_handler;
mod config_handler;
mod destination_elder;
mod error;
mod source_elder;
mod to_db_key;
mod utils;
mod vault;

pub(crate) use to_db_key::ToDbKey;

/// Utilities for testing.
#[cfg(any(test, feature = "mock"))]
pub mod test_utils;

// `crate::quic_p2p` refers to real or mock quic_p2p, depending on the "mock" feature flag.
#[cfg(feature = "mock")]
use self::test_utils::mock_quic_p2p as quic_p2p;
#[cfg(not(feature = "mock"))]
use quic_p2p;

pub use crate::{
    chunk_store::error::Error as ChunkStoreError,
    config_handler::Config,
    error::{Error, Result},
    vault::Vault,
};
