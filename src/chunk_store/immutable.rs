// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::chunk::{Chunk, ChunkId};
use sn_data_types::{Blob, BlobAddress};

impl Chunk for Blob {
    type Id = BlobAddress;
    fn id(&self) -> &Self::Id {
        match self {
            Blob::Public(ref chunk) => chunk.address(),
            Blob::Private(ref chunk) => chunk.address(),
        }
    }
}

impl ChunkId for BlobAddress {}
