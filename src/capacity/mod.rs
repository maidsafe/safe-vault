// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod adult_storage_info;
mod rate_limit;

pub use adult_storage_info::AdultsStorageInfo;
pub use rate_limit::RateLimit;

pub const MAX_SUPPLY: u64 = u32::MAX as u64 * 1_000_000_000_u64;
const MAX_CHUNK_SIZE: u64 = 1_000_000;

/// A util for sharing the
/// info on data capacity among the
/// chunk storing nodes in the section.
#[derive(Clone)]
pub struct Capacity {
    adult_storage_info: AdultsStorageInfo,
}

impl Capacity {
    /// Pass in adult_storage_info with info on chunk holders.
    pub(super) fn new(adult_storage_info: AdultsStorageInfo) -> Self {
        Self { adult_storage_info }
    }

    /// Number of full chunk storing nodes in the section.
    pub async fn full_nodes(&self) -> u8 {
        self.adult_storage_info.full_adults.read().await.len() as u8
    }
}
