// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use bytes::Bytes;
use log::warn;
use sn_data_types::{Error as DtError, HandshakeRequest};
use sn_messaging::client::{Message, MsgEnvelope};
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

pub fn try_deserialize_msg(bytes: Bytes) -> Result<MsgEnvelope> {
    match MsgEnvelope::from(bytes) {
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
        ) => {
            if msg.origin.is_client() {
                Ok(msg)
            } else {
                Err(Error::Logic(format!(
                    "{}: Msg origin is not Client",
                    msg.id()
                )))
            }
        }
        // Only cmds and queries from client are allowed through here.
        other => Err(Error::Logic(format!(
            "Error deserializing Client msg: {:?}",
            other
        ))),
    }
}

pub fn try_deserialize_handshake(bytes: &Bytes, peer_addr: SocketAddr) -> Result<HandshakeRequest> {
    match bincode::deserialize(&bytes) {
        Ok(hs @ HandshakeRequest::Bootstrap(_)) | Ok(hs @ HandshakeRequest::Join(_)) => Ok(hs),
        Err(err) => {
            warn!(
                "Failed to deserialize client input from {} as a handshake: {}",
                peer_addr, err
            );

            Err(Error::NetworkData(DtError::FailedToParse(format!(
                "Failed to deserialize client input from {} as a handshake: {}",
                peer_addr, err
            ))))
        }
    }
}
