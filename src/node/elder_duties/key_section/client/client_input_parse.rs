// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use bytes::Bytes;
use log::info;
use sn_data_types::{Error as DtError, HandshakeRequest, Message, MsgEnvelope};
use std::net::SocketAddr;

/*
Parsing of bytes received from a client,
which are interpreted into two different
kinds of input; messages and handshake requests.
*/

/// The different types
/// of input to the network
/// from a client.
/// 1. Requests sent in the bootstrapping
/// process, where a client connects
/// to the network.
/// 2. Messages sent from a connected
/// client, in order to use the services
/// of the network.

pub fn try_deserialize_msg(bytes: &Bytes) -> Result<MsgEnvelope> {
    let msg = match bincode::deserialize(&bytes) {
        Ok(
            msg
            @
            MsgEnvelope {
                message: Message::Cmd { .. },
                ..
            },
        )
        | Ok(
            msg
            @
            MsgEnvelope {
                message: Message::Query { .. },
                ..
            },
        ) => msg,
        _ => return Err(Error::Logic("Error deserializing Client msg".to_string())), // Only cmds and queries from client are allowed through here.
    };

    if msg.origin.is_client() {
        Ok(msg)
    } else {
        Err(Error::Logic(format!(
            "{:?}: Msg origin is not Client",
            msg.id()
        )))
    }
}

pub fn try_deserialize_handshake(bytes: &Bytes, peer_addr: SocketAddr) -> Result<HandshakeRequest> {
    let hs = match bincode::deserialize(&bytes) {
        Ok(hs @ HandshakeRequest::Bootstrap(_))
        | Ok(hs @ HandshakeRequest::Join(_))
        | Ok(hs @ HandshakeRequest::ChallengeResult(_)) => hs,
        Err(err) => {
            info!(
                "Failed to deserialize client input from {} as a handshake: {}",
                peer_addr, err
            );
            return Err(Error::NetworkData(DtError::FailedToParse(format!(
                "Failed to deserialize client input from {} as a handshake: {}",
                peer_addr, err
            ))));
        }
    };
    Ok(hs)
}
