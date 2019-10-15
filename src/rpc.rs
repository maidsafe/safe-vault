// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! RPC messages internal to Vaults.

use safe_nd::{Coins, Error as NdError, MessageId, PublicId, Request, Response, TransactionId};
use serde::{Deserialize, Serialize};

/// RPC messages exchanged between nodes.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum Rpc {
    /// Wrapper for a forwarded client request, including the client's public identity.
    Request {
        request: Request,
        requester: PublicId,
        message_id: MessageId,
    },
    /// Wrapper for a response from Adults to DataHandlers, or from DataHandlers to ClientHandlers.
    Response {
        response: Response,
        requester: PublicId,
        message_id: MessageId,
        refund: Option<Coins>,
    },
    /// Refund for a failed coin transfer. Send between ClientHandlers.
    Refund {
        requester: PublicId,
        amount: Coins,
        transaction_id: TransactionId,
        reason: NdError,
        message_id: MessageId,
    },
}
