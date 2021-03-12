// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    metadata::Metadata,
    node_ops::MetadataDuty,
    // rewards::{RewardCalc, Rewards, Validator},
};
use crate::{
    capacity::ChunkHolderDbs,
    node::node_ops::{DataSectionDuty, NetworkDuties, RewardCmd, RewardDuty},
    node::NodeInfo,
    Network, Result,
};
use log::info;
use sn_data_types::{OwnerType, Result as DtResult, Signing, WalletInfo};
use sn_messaging::{MessageId, SrcLocation};
use sn_routing::Prefix;
use sn_transfers::TransferActor;
use xor_name::XorName;

/// A DataSection is responsible for
/// the storage and retrieval of data,
/// and the rewarding of nodes in the section
/// for participating in these duties.
pub struct DataSection {
    /// The logic for managing data.
    metadata: Metadata,
}

impl DataSection {
    ///
    pub async fn new(info: &NodeInfo, dbs: ChunkHolderDbs, network: Network) -> Result<Self> {
        // Metadata
        let metadata = Metadata::new(info, dbs, network).await?;

        Ok(Self { metadata })
    }

    pub async fn process_metadata_duty(&mut self, duty: MetadataDuty) -> Result<()> {
        self.metadata.process_metadata_duty(duty).await
    }
}
