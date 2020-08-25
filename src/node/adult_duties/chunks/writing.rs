// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Write operations on data chunks.

use super::chunk_storage::ChunkStorage;
use crate::node::node_ops::MessagingDuty;
use log::error;
use safe_nd::{BlobWrite, MsgEnvelope};

pub(super) fn get_result(
    write: &BlobWrite,
    msg: &MsgEnvelope,
    storage: &mut ChunkStorage,
) -> Option<MessagingDuty> {
    use BlobWrite::*;
    match &write {
        New(data) => {
            if msg.verify() {
                storage.store(&data, msg.id(), &msg.origin)
            } else {
                error!("Accumulated signature for {:?} is invalid!", &msg.id());
                None
            }
        }
        DeletePrivate(address) => {
            if msg.verify() {
                // really though, for a delete, what we should be looking at is the origin signature! That would be the source of truth!
                storage.delete(*address, msg.id(), &msg.origin)
            } else {
                error!("Accumulated signature is invalid!");
                None
            }
        }
    }
}