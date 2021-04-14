// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Implementation of the "Node" node for the SAFE Network.

#![allow(unused)] // FIXME: Remove this
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![warn(
    // TODO: add missing debug implementations for structs?
    // missing_debug_implementations,
    unsafe_code,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
// For quick_error
#![recursion_limit = "128"]

mod capacity;
mod chaos;
mod chunk_store;
mod chunks;
mod config_handler;
mod error;
mod event_mapping;
mod metadata;
mod network;
mod node;
mod node_ops;
mod section_funds;
mod to_db_key;
mod transfers;

/// Docs
pub mod state_db;

pub mod utils;

pub use crate::{
    config_handler::{add_connection_info, set_connection_info, Config},
    error::{Error, Result},
    node::Node,
};
