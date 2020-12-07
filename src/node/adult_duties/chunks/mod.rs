// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod chunk_storage;
mod reading;
mod writing;

use crate::{node::node_ops::NodeMessagingDuty, node::state_db::NodeInfo, Result};
use crate::{Error, Outcome, TernaryResult};
use chunk_storage::ChunkStorage;

use log::trace;
use sn_data_types::{Cmd, DataCmd, DataQuery, Message, MsgEnvelope, Query};

use std::fmt::{self, Display, Formatter};

/// Operations on data chunks.
pub(crate) struct Chunks {
    chunk_storage: ChunkStorage,
}
pub use chunk_storage::UsedSpace;

impl Chunks {
    pub async fn new(node_info: &NodeInfo, used_space: UsedSpace) -> Result<Self> {
        let chunk_storage = ChunkStorage::new(node_info, used_space).await?;

        Ok(Self { chunk_storage })
    }

    pub async fn receive_msg(&mut self, msg: MsgEnvelope) -> Outcome<NodeMessagingDuty> {
        trace!(
            "{}: Received ({:?} from src {:?}",
            self,
            msg.id(),
            msg.most_recent_sender().address(),
        );
        match &msg.message {
            Message::Query {
                query: Query::Data(DataQuery::Blob(read)),
                ..
            } => reading::get_result(read, msg, &self.chunk_storage).await,
            Message::Cmd {
                cmd:
                    Cmd::Data {
                        cmd: DataCmd::Blob(write),
                        ..
                    },
                ..
            } => writing::get_result(write, msg, &mut self.chunk_storage).await,
            _ => Outcome::error(Error::Logic(format!(
                "{:?}: Could not receive msg as Adult",
                msg.id()
            ))),
        }
    }

    // fn handle_response(
    //     &mut self,
    //     src: SrcLocation,
    //     response: Response,
    //     requester: PublicId,
    //     message_id: MessageId,
    //     proof: Option<(Request, Signature)>,
    // ) -> Outcome<NodeMessagingDuty> {
    //     use Response::*;
    //     trace!(
    //         "{}: Received ({:?} {:?}) from {}",
    //         self,
    //         response,
    //         message_id,
    //         utils::get_source_name(src),
    //     );
    //     if let Some((request, signature)) = proof {
    //         if !matches!(requester, PublicId::Node(_))
    //             && self
    //                 .validate_section_signature(&request, &signature)
    //                 .is_none()
    //         {
    //             error!("Invalid section signature");
    //             return None;
    //         }
    //         match response {
    //             GetBlob(result) => {
    //                 if matches!(requester, PublicId::Node(_)) {
    //                     debug!("got the duplication copy");
    //                     if let Ok(data) = result {
    //                         trace!(
    //                             "Got GetBlob copy response for address: ({:?})",
    //                             data.address(),
    //                         );
    //                         self.chunk_storage.store(
    //                             src,
    //                             &data,
    //                             &requester,
    //                             message_id,
    //                             Some(&signature),
    //                             request,
    //                         )
    //                     } else {
    //                         None
    //                     }
    //                 } else {
    //                     None
    //                 }
    //             }
    //             //
    //             // ===== Invalid =====
    //             //
    //             ref _other => {
    //                 error!(
    //                     "{}: Should not receive {:?} as a data handler.",
    //                     self, response
    //                 );
    //                 None
    //             }
    //         }
    //     } else {
    //         error!("Missing section signature");
    //         None
    //     }
    // }

    // fn public_key(&self) -> Option<PublicKey> {
    //     Some(
    //         self.routing_node
    //             .borrow()
    //             .public_key_set()
    //             .ok()?
    //             .public_key(),
    //     )
    // }

    // fn validate_section_signature(&self, request: &Request, signature: &Signature) -> Option<()> {
    //     if self
    //         .public_key()?
    //         .verify(signature, &utils::serialise(request))
    //     {
    //         Some(())
    //     } else {
    //         None
    //     }
    // }
}

impl Display for Chunks {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Chunks")
    }
}
