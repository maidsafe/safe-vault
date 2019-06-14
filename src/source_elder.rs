// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{action::Action, utils, vault::Init, Result};
use bytes::Bytes;
use crossbeam_channel::{self, Receiver, Sender};
use log::{info, trace};
use pickledb::PickleDb;
use quic_p2p::{Config as QuicP2pConfig, Event, Peer, QuicP2p};
use safe_nd::{Challenge, Message, MessageId, PublicId, Request, Response, Signature};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};
use unwrap::unwrap;

const CLIENT_ACCOUNTS_DB_NAME: &str = "client_accounts.db";

pub(crate) struct SourceElder {
    client_accounts: PickleDb,
    clients: HashMap<SocketAddr, PublicId>,
    // Map of new client connections to the challenge value we sent them.
    client_candidates: HashMap<SocketAddr, Vec<u8>>,
    quic_p2p: QuicP2p,
}

impl SourceElder {
    pub fn new<P: AsRef<Path>>(
        root_dir: P,
        config: &QuicP2pConfig,
        init_mode: Init,
    ) -> Result<(Self, Receiver<Event>)> {
        let client_accounts = utils::new_db(root_dir, CLIENT_ACCOUNTS_DB_NAME, init_mode)?;
        let (quic_p2p, event_receiver) = Self::setup_quic_p2p(config)?;
        let src_elder = Self {
            client_accounts,
            clients: Default::default(),
            client_candidates: Default::default(),
            quic_p2p,
        };

        Ok((src_elder, event_receiver))
    }

    fn setup_quic_p2p(config: &QuicP2pConfig) -> Result<(QuicP2p, Receiver<Event>)> {
        let (event_sender, event_receiver) = crossbeam_channel::unbounded();
        let mut quic_p2p = quic_p2p::Builder::new(event_sender)
            .with_config(config.clone())
            .build()?;
        let our_conn_info = quic_p2p.our_connection_info()?;
        info!(
            "QuicP2p started on {}\nwith certificate {:?}",
            our_conn_info.peer_addr, our_conn_info.peer_cert_der
        );
        println!(
            "Our connection info:\n{}\n",
            unwrap!(serde_json::to_string(&our_conn_info))
        );
        Ok((quic_p2p, event_receiver))
    }

    pub fn handle_new_connection(&mut self, peer: Peer) {
        // If we already know the peer, drop the connection attempt.
        if self.clients.contains_key(&peer.peer_addr())
            || self.client_candidates.contains_key(&peer.peer_addr())
        {
            return;
        }

        let peer_addr = match peer {
            Peer::Node { node_info } => {
                info!(
                    "Rejecting connection attempt by node on {}",
                    node_info.peer_addr
                );
                self.quic_p2p.disconnect_from(node_info.peer_addr);
                return;
            }
            Peer::Client { peer_addr } => peer_addr,
        };

        let challenge = utils::random_vec(8);
        match bincode::serialize(&Challenge::Request(challenge.clone())) {
            Ok(msg) => self.quic_p2p.send(peer.clone(), Bytes::from(msg)),
            Err(err) => info!("Unable to serialise Challenge::Request: {}", err),
        }
        let _ = self.client_candidates.insert(peer.peer_addr(), challenge);
        info!("Connected to new client on {}", peer_addr);
    }

    pub fn handle_connection_failure(&mut self, peer_addr: SocketAddr) {
        if let Some(client_id) = self.clients.remove(&peer_addr) {
            info!("Disconnected from {:?} on {}", client_id, peer_addr);
        } else {
            let _ = self.client_candidates.remove(&peer_addr);
            info!("Disconnected from client candidate on {}", peer_addr);
        }
    }

    pub fn handle_client_message(&mut self, peer_addr: SocketAddr, bytes: Bytes) -> Option<Action> {
        if let Some(client_id) = self.clients.get(&peer_addr).cloned() {
            match bincode::deserialize(&bytes) {
                Ok(Message::Request {
                    request,
                    message_id,
                    signature,
                }) => {
                    return self.handle_client_request(&client_id, request, message_id, signature);
                }
                Ok(Message::Response { response, .. }) => {
                    info!("{} invalidly sent {:?}", client_id, response);
                }
                Err(err) => {
                    info!("Unable to deserialise message from {}: {}", client_id, err);
                }
            }
        } else {
            match bincode::deserialize(&bytes) {
                Ok(Challenge::Response(public_id, signature)) => {
                    self.handle_challenge(peer_addr, public_id, signature);
                }
                Ok(Challenge::Request(_)) => {
                    info!("Received unexpected challenge request from {}", peer_addr);
                    self.quic_p2p.disconnect_from(peer_addr);
                }
                Err(err) => {
                    info!(
                        "Unable to deserialise challenge from {}: {}",
                        peer_addr, err
                    );
                }
            }
        }
        None
    }

    fn handle_client_request(
        &mut self,
        client_id: &PublicId,
        request: Request,
        message_id: MessageId,
        signature: Option<Signature>,
    ) -> Option<Action> {
        info!(
            "Received ({:?} {:?}) from {}",
            request, message_id, client_id
        );
        unimplemented!();
    }

    /// Handles a received challenge response.
    ///
    /// Checks that the response contains a valid signature of the challenge we previously sent.
    fn handle_challenge(
        &mut self,
        peer_addr: SocketAddr,
        public_id: PublicId,
        signature: Signature,
    ) {
        let public_key = match public_id {
            PublicId::Client(ref pub_id) => pub_id.public_key(),
            PublicId::App(ref pub_id) => pub_id.public_key(),
            PublicId::Node(_) => {
                info!(
                    "Client on {} identifies as a node: {}",
                    peer_addr, public_id
                );
                self.quic_p2p.disconnect_from(peer_addr);
                return;
            }
        };
        if let Some(challenge) = self.client_candidates.remove(&peer_addr) {
            match public_key.verify(&signature, challenge) {
                Ok(()) => {
                    info!("Accepted {} on {}", public_id, peer_addr);
                    let _ = self.clients.insert(peer_addr, public_id);
                }
                Err(err) => {
                    info!(
                        "Challenge failed for {} on {}: {}",
                        public_id, peer_addr, err
                    );
                    self.quic_p2p.disconnect_from(peer_addr);
                }
            }
        } else {
            info!(
                "{} on {} supplied challenge response without us providing it.",
                public_id, peer_addr
            );
            self.quic_p2p.disconnect_from(peer_addr);
        }
    }
}
