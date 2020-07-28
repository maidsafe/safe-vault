// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! RPC messages internal to Vaults.

use safe_nd::{Coins, IDataAddress, MessageId, PublicId, Request, Response, XorName};
use safe_network_signature_aggregator::ProofShare;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use threshold_crypto::Signature;

/// RPC messages exchanged between nodes.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum Rpc {
    /// Wrapper for a forwarded client request, including the client's public identity.
    Request {
        request: Request,
        requester: PublicId,
        message_id: MessageId,
        proof: Option<ProofShare>,
    },
    /// Wrapper for a response from Adults to DataHandlers, or from DataHandlers to ClientHandlers.
    Response {
        response: Response,
        requester: PublicId,
        message_id: MessageId,
        refund: Option<Coins>,
        proof: Option<(Request, Signature)>,
    },
    /// Wrapper for a duplicate request, from elders to other nodes in the section.
    Duplicate {
        address: IDataAddress,
        holders: BTreeSet<XorName>,
        message_id: MessageId,
        proof: Option<ProofShare>,
    },
    /// Wrapper for a duplicate completion response, from a node to elders.
    DuplicationComplete {
        response: Response,
        message_id: MessageId,
        proof: Option<(IDataAddress, Signature)>,
    },
}

impl Rpc {
    /// Returns the message ID
    pub(crate) fn message_id(&self) -> &MessageId {
        use Rpc::*;
        match self {
            Request { message_id, .. }
            | Duplicate { message_id, .. }
            | Response { message_id, .. }
            | DuplicationComplete { message_id, .. } => message_id,
        }
    }
}
