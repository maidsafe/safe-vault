// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use safe_nd::{MessageId, Request, Response, XorName};

#[derive(Debug)]
pub(crate) enum Action {
    // Send a validated client request from src elders to dst elders
    ForwardClientRequest {
        // TODO - confirm this.  ATM, this represents the owner's name if the src is an app.
        client_name: XorName,
        request: Request,
        message_id: MessageId,
    },
    // Send a response as an adult or elder to own section's elders
    RespondToOurDstElders {
        sender: XorName,
        response: Response,
        message_id: MessageId,
    },
    RespondToSrcElders {
        sender: XorName,
        client_name: XorName,
        response: Response,
        message_id: MessageId,
    },
    // Send the same request to each individual peer (used to send IData requests to adults).
    SendToPeers {
        targets: Vec<XorName>,
        request: Request,
        message_id: MessageId,
    },
}
