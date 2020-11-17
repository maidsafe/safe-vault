// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use quick_error::quick_error;
use std::io;

quick_error! {
    /// `ChunkStore` error.
    #[derive(Debug)]
    pub enum Error {
        /// Error during filesystem IO operations.
        Io(error: io::Error) {
            cause(error)
            description(error.description())
            display("I/O error: {}", error)
            from()
        }
        /// Bincode error.
        Bincode(error: bincode::Error) {
            cause(error)
            description(error.description())
            display("Bincode error: {}", error)
            from()
        }
        /// Not enough space in `ChunkStore` to perform `put`.
        NotEnoughSpace {
            display("Not enough space")
        }
        /// Key, Value pair not found in `ChunkStore`.
        NoSuchChunk {
            display("Chunk not found")
        }
        /// Other ChunkStore errors
        Other(error: String) {
            display("Error: {:?}", error)
        }
    }
}

pub(super) type Result<T> = std::result::Result<T, Error>;
