// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::rpc::Rpc;
use safe_nd::XorName;
use std::collections::BTreeSet;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Action {
    // Send a validated client request from src elders to dst elders.
    ForwardClientRequest(Rpc),
    // Send a response as an adult or elder to own section's elders.
    RespondToOurDstElders {
        sender: XorName,
        message: Rpc,
    },
    RespondToSrcElders {
        sender: XorName,
        message: Rpc,
    },
    // Send the same request to each individual peer (used to send IData requests to adults).
    SendToPeers {
        sender: XorName,
        targets: BTreeSet<XorName>,
        message: Rpc,
    },
}
