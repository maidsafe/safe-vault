// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::chunk_storage::ChunkStorage;
use crate::node::node_ops::NodeMessagingDuty;
use crate::{Error, Result};
use log::error;
use sn_data_types::Error as DtError;
use sn_messaging::{Address, BlobRead, MsgEnvelope};

/// Read operations on data chunks.

pub(super) async fn get_result(
    read: &BlobRead,
    msg: MsgEnvelope,
    storage: &ChunkStorage,
) -> Result<NodeMessagingDuty> {
    let BlobRead::Get(address) = read;
    if let Address::Section(_) = msg.most_recent_sender().address() {
        let verification = msg.verify();
        if let Ok(true) = verification {
            storage.get(address, msg.id(), &msg.origin).await
        } else {
            error!(
                "Accumulated signature is invalid! Verification: {:?}",
                verification
            );
            Err(Error::NetworkData(DtError::InvalidSignature))
        }
    // } else if matches!(self.requester, PublicId::Node(_)) {
    //     if self.verify(&address) {
    //         storage.get(
    //             self.src,
    //             *address,
    //             &self.requester,
    //             self.message_id,
    //             self.request.clone(),
    //             self.accumulated_signature.as_ref(),
    //         )
    //     } else {
    //         error!("Accumulated signature is invalid!");
    //         None
    //     }
    } else {
        // only receiving these requests from sections
        Err(Error::Logic(format!(
            "{:?}: Can only receive requests from sections",
            msg.id()
        )))
    }
}
