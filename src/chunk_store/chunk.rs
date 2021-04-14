// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::to_db_key::ToDbKey;
use serde::{de::DeserializeOwned, Serialize};
use xor_name::XorName;

pub(crate) trait Chunk: Serialize + DeserializeOwned {
    type Id: ChunkId;
    fn id(&self) -> &Self::Id;
}

pub(crate) trait ChunkId: ToDbKey + PartialEq + Eq + DeserializeOwned {}

impl ChunkId for XorName {}
