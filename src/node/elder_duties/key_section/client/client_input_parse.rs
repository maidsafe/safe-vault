// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bytes::Bytes;
use log::{info, warn};
use safe_nd::{HandshakeRequest, Message, MessageId, MsgEnvelope, MsgSender, PublicId};
use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
};

/*
Parsing of bytes received from a client,
which are interpreted into two different
kinds of input; messages and handshake requests.
*/

/// The different types
/// of input to the network
/// from a client.
pub enum ClientInput {
    /// Messages sent from a connected
    /// client, in order to use the services
    /// of the network.
    Msg(ClientMsg),
    /// Requests sent in the bootstrapping
    /// process, where a client connects
    /// to the network.
    Handshake(HandshakeRequest),
}

#[derive(Clone, Debug)]
pub struct ClientMsg {
    pub msg: MsgEnvelope,
    pub public_id: PublicId,
}

impl ClientMsg {
    pub fn id(&self) -> MessageId {
        self.msg.id()
    }
}

impl Display for ClientMsg {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}, {}", self.public_id.name(), &self.msg.id().0)
    }
}

pub fn try_deserialize_msg(bytes: &Bytes) -> Option<ClientInput> {
    let msg = match bincode::deserialize(&bytes) {
        Ok((
            public_id,
            msg
            @
            MsgEnvelope {
                message: Message::Cmd { .. },
                origin: MsgSender::Client { .. },
                ..
            },
        ))
        | Ok((
            public_id,
            msg
            @
            MsgEnvelope {
                message: Message::Query { .. },
                origin: MsgSender::Client { .. },
                ..
            },
        )) => ClientMsg { msg, public_id },
        another => {
            warn!("some other messageeeeeee {:?}", another);
            return None;
        } // Only cmds and queries from client are allowed through here.
    };
    warn!("Deserialized client msg: {}", msg);
    Some(ClientInput::Msg(msg))
}

pub fn try_deserialize_handshake(bytes: &Bytes, peer_addr: SocketAddr) -> Option<ClientInput> {
    let hs = match bincode::deserialize(&bytes) {
        Ok(hs @ HandshakeRequest::Bootstrap(_))
        | Ok(hs @ HandshakeRequest::Join(_))
        | Ok(hs @ HandshakeRequest::ChallengeResult(_)) => hs,
        Err(err) => {
            info!(
                "Failed to deserialize client input from {} as a handshake: {}",
                peer_addr, err
            );
            return None;
        }
    };

    Some(ClientInput::Handshake(hs))
}
