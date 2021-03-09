// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::chunk_storage::ChunkStorage;
use crate::node::node_ops::NodeMessagingDuty;
use crate::Result;
use sn_messaging::{client::BlobRead, EndUser, MessageId};

/// Read operations on data chunks.

pub(super) async fn get_result(
    read: &BlobRead,
    msg_id: MessageId,
    origin: EndUser,
    storage: &ChunkStorage,
) -> Result<NodeMessagingDuty> {
    let BlobRead::Get(address) = read;
    storage.get(address, msg_id, origin).await
}
