// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::chunk::{Chunk, ChunkId};
use safe_nd::{
    AData, ADataAddress, PubSeqAppendOnlyData, PubUnseqAppendOnlyData, UnpubSeqAppendOnlyData,
    UnpubUnseqAppendOnlyData, XorName,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

impl Chunk for AData {
    type Id = ADataAddress;
    fn id(&self) -> &Self::Id {
        self.address()
    }
}

impl ChunkId for ADataAddress {
    fn raw_name(&self) -> &XorName {
        self.name()
    }
}
