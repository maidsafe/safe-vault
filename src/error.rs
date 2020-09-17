// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::chunk_store;
use quick_error::quick_error;
use std::io;

quick_error! {
    #[allow(clippy::large_enum_variant)]
    #[derive(Debug)]
    /// Vault error variants.
    pub enum Error {
        /// Error in ChunkStore.
        ChunkStore(error: chunk_store::error::Error) {
            cause(error)
            description(error.description())
            display("ChunkStore error: {}", error)
            from()
        }
        /// I/O error.
        Io(error: io::Error) {
            cause(error)
            description(error.description())
            display("I/O error: {}", error)
            from()
        }
        /// JSON serialisation error.
        JsonSerialisation(error: serde_json::Error) {
            cause(error)
            description(error.description())
            display("JSON serialisation error: {}", error)
            from()
        }
        /// Bincode error.
        Bincode(error: bincode::Error) {
            cause(error)
            description(error.description())
            display("Bincode error: {}", error)
            from()
        }
        /// PickleDB error.
        PickleDb(error: pickledb::error::Error) {
            display("PickleDb error: {}", error)
            from()
        }
        /// NetworkData error.
        NetworkData(error: sn_data_types::Error) {
            cause(error)
            description(error.description())
            display("NetworkData error: {}", error)
            from()
        }
        /// NetworkData Entry error.
        NetworkDataEntry(error: sn_data_types::EntryError) {
            display("NetworkData Entry error: {:?}", error)
            from()
        }
        /// Routing error.
        Routing(error: sn_routing::Error) {
            display("Routing error: {:?}", error)
            from()
        }
        ///
        InvalidConfig(error: String) {
            display("Config error: {:?}", error)
            from()
        }
        /// Onboarding error
        Onboarding{
            display("Onboarding error")
        }
        /// Message is invalid.
        InvalidMessage {}
        /// Account doesn't exist.
        NoSuchAccount {}
        /// Logic error.
        Logic {
            display("Logic error")
            from()
        }
    }
}

/// Specialisation of `std::Result` for Vault.
pub type Result<T, E = Error> = std::result::Result<T, E>;
