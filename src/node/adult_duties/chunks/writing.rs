// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::chunk_storage::ChunkStorage;
use crate::node::node_ops::MessagingDuty;
use log::error;
use safe_nd::{BlobWrite, MsgEnvelope, MsgSender};

/// Write operations on data chunks.
pub(super) struct Writing {
    write: BlobWrite,
    msg: MsgEnvelope,
}

impl Writing {
    pub fn new(write: BlobWrite, msg: MsgEnvelope) -> Self {
        Self { write, msg }
    }

    pub fn get_result(&self, storage: &mut ChunkStorage) -> Option<MessagingDuty> {
        use BlobWrite::*;
        match &self.write {
            New(data) => {
                if self.verify_msg() {
                    storage.store(&data, self.msg.id(), &self.msg.origin)
                } else {
                    error!("Accumulated signature for {:?} is invalid!", &self.msg.id());
                    None
                }
            }
            DeletePrivate(address) => {
                if self.verify_msg() {
                    // really though, for a delete, what we should be looking at is the origin signature! That would be the source of truth!
                    storage.delete(*address, self.msg.id(), &self.msg.origin)
                } else {
                    error!("Accumulated signature is invalid!");
                    None
                }
            }
        }
    }

    fn verify_msg(&self) -> bool {
        match self.msg.most_recent_sender() {
            MsgSender::Section { .. } => self.msg.verify(),
            _ => false,
        }
    }
}
