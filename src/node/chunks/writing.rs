// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Write operations on data chunks.

use super::chunk_storage::ChunkStorage;
use crate::node::node_ops::NodeMessagingDuty;
use crate::Result;
use sn_messaging::{client::BlobWrite, EndUser, MessageId};

pub(super) async fn get_result(
    write: &BlobWrite,
    msg_id: MessageId,
    origin: EndUser,
    storage: &mut ChunkStorage,
) -> Result<NodeMessagingDuty> {
    use BlobWrite::*;
    match &write {
        New(data) => storage.store(&data, msg_id, origin).await,
        DeletePrivate(address) => storage.delete(*address, msg_id, origin).await, // really though, for a delete, what we should be looking at is the origin signature! That would be the source of truth!
    }
}
