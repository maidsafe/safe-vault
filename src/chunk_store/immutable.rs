// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::chunk::{Chunk, ChunkId};
use safe_nd::{IData, IDataAddress, PubImmutableData, UnpubImmutableData, XorName};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

impl Chunk for IData {
    type Id = IDataAddress;
    fn id(&self) -> &Self::Id {
        match self {
            IData::Pub(ref chunk) => chunk.address(),
            IData::Unpub(ref chunk) => chunk.address(),
        }
    }
}

impl ChunkId for IDataAddress {
    fn raw_name(&self) -> &XorName {
        self.name()
    }
}
