// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Implementation of the "Node" node for the SAFE Network.

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
mod config_handler;
mod error;
mod network;
mod node;
mod to_db_key;

pub mod utils;

#[cfg(all(test, feature = "simulated-payouts"))]
mod tests;

pub(crate) use to_db_key::ToDbKey;

pub use crate::{
    chunk_store::error::Error as ChunkStoreError,
    config_handler::{write_connection_info, Config},
    error::{Error, Result},
    network::Network,
    node::Node,
};

///
pub type Outcome<T> = Result<Option<T>>;

trait TernaryResult<T> {
    fn oki(item: T) -> Self;
    fn oki_no_change() -> Self;
    fn oki_no_value() -> Self;
    fn error(error: Error) -> Self;
    fn has_value(&self) -> bool;
    fn get_value(&self) -> Option<&T>;
    fn get_error(&self) -> Option<&Error>;
    fn convert<K: From<T>>(self) -> Outcome<K>;
}

impl<T> TernaryResult<T> for Outcome<T> {
    fn oki(item: T) -> Self {
        Ok(Some(item))
    }
    fn oki_no_change() -> Self {
        Ok(None)
    }
    fn oki_no_value() -> Self {
        Ok(None)
    }
    fn error(error: Error) -> Self {
        Err(error)
    }
    fn has_value(&self) -> bool {
        matches!(self, Ok(Some(_)))
    }
    fn get_value(&self) -> Option<&T> {
        if let Ok(Some(value)) = self {
            Some(value)
        } else {
            None
        }
    }
    fn get_error(&self) -> Option<&Error> {
        if let Err(error) = self {
            Some(error)
        } else {
            None
        }
    }
    fn convert<K: From<T>>(self) -> Outcome<K> {
        self.map(|c| c.map(|d| d.into()))
    }
}
