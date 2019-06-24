// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{action::Action, utils, vault::Init, Result};
use bytes::Bytes;
use crossbeam_channel::{self, Receiver};
use lazy_static::lazy_static;
use log::{error, info, trace, warn};
use pickledb::PickleDb;
use quic_p2p::{Config as QuicP2pConfig, Event, Peer, QuicP2p};
use safe_nd::{
    AppPermissions, Challenge, ClientPublicId, Coins, Message, MessageId, NodePublicId, PublicId,
    PublicKey, Request, Response, Signature, XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::Path,
};
use unwrap::unwrap;

const CLIENT_ACCOUNTS_DB_NAME: &str = "client_accounts.db";
lazy_static! {
    static ref COST_OF_PUT: Coins = unwrap!(Coins::from_nano(1_000_000_000));
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientAccount {
    apps: HashMap<PublicKey, AppPermissions>,
    balance: Coins,
}

pub(crate) struct SourceElder {
    id: NodePublicId,
    client_accounts: PickleDb,
    clients: HashMap<SocketAddr, PublicId>,
    // Map of new client connections to the challenge value we sent them.
    client_candidates: HashMap<SocketAddr, Vec<u8>>,
    quic_p2p: QuicP2p,
}

impl SourceElder {
    pub fn new<P: AsRef<Path>>(
        id: NodePublicId,
        root_dir: P,
        config: &QuicP2pConfig,
        init_mode: Init,
    ) -> Result<(Self, Receiver<Event>)> {
        let client_accounts = utils::new_db(root_dir, CLIENT_ACCOUNTS_DB_NAME, init_mode)?;
        let (quic_p2p, event_receiver) = Self::setup_quic_p2p(config)?;
        let src_elder = Self {
            id,
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
                    "{}: Rejecting connection attempt by node on {}",
                    self, node_info.peer_addr
                );
                self.quic_p2p.disconnect_from(node_info.peer_addr);
                return;
            }
            Peer::Client { peer_addr } => peer_addr,
        };

        let challenge = utils::random_vec(8);
        let msg = utils::serialise(&Challenge::Request(challenge.clone()));
        self.quic_p2p.send(peer.clone(), Bytes::from(msg));
        let _ = self.client_candidates.insert(peer.peer_addr(), challenge);
        info!("{}: Connected to new client on {}", self, peer_addr);
    }

    pub fn handle_connection_failure(&mut self, peer_addr: SocketAddr) {
        if let Some(client_id) = self.clients.remove(&peer_addr) {
            info!(
                "{}: Disconnected from {:?} on {}",
                self, client_id, peer_addr
            );
        } else {
            let _ = self.client_candidates.remove(&peer_addr);
            info!(
                "{}: Disconnected from client candidate on {}",
                self, peer_addr
            );
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
                    info!("{}: {} invalidly sent {:?}", self, client_id, response);
                }
                Err(err) => {
                    info!(
                        "{}: Unable to deserialise message from {}: {}",
                        self, client_id, err
                    );
                }
            }
        } else {
            match bincode::deserialize(&bytes) {
                Ok(Challenge::Response(public_id, signature)) => {
                    self.handle_challenge(peer_addr, public_id, signature);
                }
                Ok(Challenge::Request(_)) => {
                    info!(
                        "{}: Received unexpected challenge request from {}",
                        self, peer_addr
                    );
                    self.quic_p2p.disconnect_from(peer_addr);
                }
                Err(err) => {
                    info!(
                        "{}: Unable to deserialise challenge from {}: {}",
                        self, peer_addr, err
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
        use Request::*;
        trace!(
            "{}: Received ({:?} {:?}) from {}",
            self,
            request,
            message_id,
            client_id
        );
        if let Some(sig) = signature.as_ref() {
            if !self.is_valid_client_signature(client_id, &request, &message_id, sig) {
                return None;
            }
        }
        // TODO - remove this
        #[allow(unused)]
        match request {
            //
            // ===== Immutable Data =====
            //
            PutIData(_) => {
                let owner = utils::owner(client_id)?;
                let balance = self.balance(owner)?;
                let new_balance = balance.checked_sub(*COST_OF_PUT)?;

                self.has_signature(client_id, &request, &message_id, &signature)?;

                self.set_balance(owner, new_balance)?;
                Some(Action::ForwardClientRequest {
                    client_name: *client_id.name(),
                    request,
                    message_id,
                })
            }
            GetIData(ref address) => unimplemented!(),
            DeleteUnpubIData(ref address) => unimplemented!(),
            //
            // ===== Mutable Data =====
            //
            PutUnseqMData(_) => unimplemented!(),
            PutSeqMData(_) => unimplemented!(),
            GetMData(ref address) => unimplemented!(),
            GetMDataValue { ref address, .. } => unimplemented!(),
            DeleteMData(ref address) => unimplemented!(),
            GetMDataShell(ref address) => unimplemented!(),
            GetMDataVersion(ref address) => unimplemented!(),
            ListMDataEntries(ref address) => unimplemented!(),
            ListMDataKeys(ref address) => unimplemented!(),
            ListMDataValues(ref address) => unimplemented!(),
            SetMDataUserPermissions { ref address, .. } => unimplemented!(),
            DelMDataUserPermissions { ref address, .. } => unimplemented!(),
            ListMDataPermissions(ref address) => unimplemented!(),
            ListMDataUserPermissions { ref address, .. } => unimplemented!(),
            MutateSeqMDataEntries { ref address, .. } => unimplemented!(),
            MutateUnseqMDataEntries { ref address, .. } => unimplemented!(),
            //
            // ===== Append Only Data =====
            //
            PutAData(_) => unimplemented!(),
            GetAData(ref address) => unimplemented!(),
            GetADataShell { ref address, .. } => unimplemented!(),
            DeleteAData(ref address) => unimplemented!(),
            GetADataRange { ref address, .. } => unimplemented!(),
            GetADataIndices(ref address) => unimplemented!(),
            GetADataLastEntry(ref address) => unimplemented!(),
            GetADataPermissions { ref address, .. } => unimplemented!(),
            GetPubADataUserPermissions { ref address, .. } => unimplemented!(),
            GetUnpubADataUserPermissions { ref address, .. } => unimplemented!(),
            GetADataOwners { ref address, .. } => unimplemented!(),
            AddPubADataPermissions { ref address, .. } => unimplemented!(),
            AddUnpubADataPermissions { ref address, .. } => unimplemented!(),
            SetADataOwner { ref address, .. } => unimplemented!(),
            AppendSeq { ref append, .. } => unimplemented!(),
            AppendUnseq(ref append) => unimplemented!(),
            //
            // ===== Coins =====
            //
            TransferCoins {
                ref source,
                ref amount,
                ..
            } => unimplemented!(),
            GetTransaction { .. } => unimplemented!(),
            GetBalance(ref address) => unimplemented!(),
            //
            // ===== Client (Owner) to SrcElders =====
            //
            ListAuthKeysAndVersion => unimplemented!(),
            InsAuthKey {
                ref key,
                version,
                ref permissions,
            } => unimplemented!(),
            DelAuthKey { ref key, version } => unimplemented!(),
        }
    }

    fn is_valid_client_signature(
        &self,
        client_id: &PublicId,
        request: &Request,
        message_id: &MessageId,
        signature: &Signature,
    ) -> bool {
        let pub_key = match client_id {
            PublicId::Node(_) => {
                error!("{}: Logic error.  This should be unreachable.", self);
                return false;
            }
            PublicId::Client(pub_id) => pub_id.public_key(),
            PublicId::App(pub_id) => pub_id.public_key(),
        };
        match pub_key.verify(signature, utils::serialise(&(request, message_id))) {
            Ok(_) => true,
            Err(error) => {
                warn!(
                    "{}: ({:?}/{:?}) from {} is invalid: {}",
                    self, request, message_id, client_id, error
                );
                false
            }
        }
    }

    // This method only exists to avoid duplicating the log line in many places.
    fn has_signature(
        &self,
        client_id: &PublicId,
        request: &Request,
        message_id: &MessageId,
        signature: &Option<Signature>,
    ) -> Option<()> {
        if signature.is_none() {
            warn!(
                "{}: ({:?}/{:?}) from {} is unsigned",
                self, request, message_id, client_id
            );
            return None;
        }
        Some(())
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
                    "{}: Client on {} identifies as a node: {}",
                    self, peer_addr, public_id
                );
                self.quic_p2p.disconnect_from(peer_addr);
                return;
            }
        };
        if let Some(challenge) = self.client_candidates.remove(&peer_addr) {
            match public_key.verify(&signature, challenge) {
                Ok(()) => {
                    info!("{}: Accepted {} on {}", self, public_id, peer_addr);
                    let _ = self.clients.insert(peer_addr, public_id);
                }
                Err(err) => {
                    info!(
                        "{}: Challenge failed for {} on {}: {}",
                        self, public_id, peer_addr, err
                    );
                    self.quic_p2p.disconnect_from(peer_addr);
                }
            }
        } else {
            info!(
                "{}: {} on {} supplied challenge response without us providing it.",
                self, public_id, peer_addr
            );
            self.quic_p2p.disconnect_from(peer_addr);
        }
    }

    pub fn _handle_node_response(
        &mut self,
        dst_elders: XorName,
        src_elders: XorName,
        response: Response,
        message_id: MessageId,
    ) -> Option<Action> {
        use Response::*;
        trace!(
            "{}: Received ({:?} {:?}) to {} from {}",
            self,
            response,
            message_id,
            src_elders,
            dst_elders
        );
        // TODO - remove this
        #[allow(unused)]
        match response {
            //
            // ===== Immutable Data =====
            //
            PutIData(result) => unimplemented!(),
            GetIData(result) => unimplemented!(),
            DeleteUnpubIData(result) => unimplemented!(),
            //
            // ===== Mutable Data =====
            //
            GetUnseqMData(result) => unimplemented!(),
            PutUnseqMData(result) => unimplemented!(),
            GetSeqMData(result) => unimplemented!(),
            PutSeqMData(result) => unimplemented!(),
            GetSeqMDataShell(result) => unimplemented!(),
            GetUnseqMDataShell(result) => unimplemented!(),
            GetMDataVersion(result) => unimplemented!(),
            ListUnseqMDataEntries(result) => unimplemented!(),
            ListSeqMDataEntries(result) => unimplemented!(),
            ListMDataKeys(result) => unimplemented!(),
            ListSeqMDataValues(result) => unimplemented!(),
            ListUnseqMDataValues(result) => unimplemented!(),
            DeleteMData(result) => unimplemented!(),
            SetMDataUserPermissions(result) => unimplemented!(),
            DelMDataUserPermissions(result) => unimplemented!(),
            ListMDataUserPermissions(result) => unimplemented!(),
            ListMDataPermissions(result) => unimplemented!(),
            MutateSeqMDataEntries(result) => unimplemented!(),
            MutateUnseqMDataEntries(result) => unimplemented!(),
            GetSeqMDataValue(result) => unimplemented!(),
            GetUnseqMDataValue(result) => unimplemented!(),
            //
            // ===== Append Only Data =====
            //
            PutAData(result) => unimplemented!(),
            GetAData(result) => unimplemented!(),
            GetADataShell(result) => unimplemented!(),
            GetADataOwners(result) => unimplemented!(),
            GetADataRange(result) => unimplemented!(),
            GetADataIndices(result) => unimplemented!(),
            GetADataLastEntry(result) => unimplemented!(),
            GetUnpubADataPermissionAtIndex(result) => unimplemented!(),
            GetPubADataPermissionAtIndex(result) => unimplemented!(),
            GetPubADataUserPermissions(result) => unimplemented!(),
            GetUnpubADataUserPermissions(result) => unimplemented!(),
            AddUnpubADataPermissions(result) => unimplemented!(),
            AddPubADataPermissions(result) => unimplemented!(),
            SetADataOwner(result) => unimplemented!(),
            AppendSeq(result) => unimplemented!(),
            AppendUnseq(result) => unimplemented!(),
            DeleteAData(result) => unimplemented!(),
            //
            // ===== Coins =====
            //
            GetTransaction(result) => unimplemented!(),
            //
            // ===== Invalid =====
            //
            TransferCoins(_)
            | GetBalance(_)
            | ListAuthKeysAndVersion(_)
            | InsAuthKey(_)
            | DelAuthKey(_) => {
                error!(
                    "{}: Should not receive {:?} as a source elder.",
                    self, response
                );
                None
            }
        }
    }

    fn balance(&self, client_id: &ClientPublicId) -> Option<Coins> {
        self.client_accounts
            .get(&client_id.to_string())
            .map(|account: ClientAccount| account.balance)
    }

    fn set_balance(&mut self, client_id: &ClientPublicId, balance: Coins) -> Option<()> {
        let db_key = client_id.to_string();
        let mut account = self.client_accounts.get::<ClientAccount>(&db_key)?;
        account.balance = balance;
        if let Err(error) = self.client_accounts.set(&db_key, &account) {
            error!(
                "{}: Failed to update balance for {}: {}",
                self, client_id, error
            );
            return None;
        }
        Some(())
    }
}

impl Display for SourceElder {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}
