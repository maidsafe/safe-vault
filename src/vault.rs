// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::{Action, ConsensusAction},
    client_handler::ClientHandler,
    data_handler::DataHandler,
    rpc::Rpc,
    utils, Config, Result,
};
use crossbeam_channel::{Receiver, Select};
use hex_fmt::HexFmt;
use log::{debug, error, info, trace, warn};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use routing::{
    event::Event as RoutingEvent, AccumulationError, DstLocation, Node, Proof, ProofShare,
    SignatureAccumulator, SrcLocation, TransportEvent as ClientEvent,
};
use safe_nd::{
    ClientRequest, LoginPacketRequest, MessageId, NodeFullId, PublicId, Request, Response, XorName,
};
use std::borrow::Cow;
use std::{
    cell::{Cell, RefCell},
    fmt::{self, Display, Formatter},
    fs,
    net::SocketAddr,
    path::PathBuf,
    rc::Rc,
};

const STATE_FILENAME: &str = "state";

#[allow(clippy::large_enum_variant)]
enum State {
    Infant,
    Adult {
        data_handler: DataHandler,
        accumulator: SignatureAccumulator<(Request, MessageId)>,
    },
    Elder {
        client_handler: ClientHandler,
        data_handler: DataHandler,
        accumulator: SignatureAccumulator<(Request, MessageId)>,
    },
}

/// Specifies whether to try loading cached data from disk, or to just construct a new instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Init {
    Load,
    New,
}

/// Command that the user can send to a running vault to control its execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Shutdown the vault
    Shutdown,
}

/// Main vault struct.
pub struct Vault<R: CryptoRng + Rng> {
    id: NodeFullId,
    root_dir: PathBuf,
    state: State,
    event_receiver: Receiver<RoutingEvent>,
    client_receiver: Receiver<ClientEvent>,
    command_receiver: Receiver<Command>,
    routing_node: Rc<RefCell<Node>>,
    rng: R,
}

impl<R: CryptoRng + Rng> Vault<R> {
    /// Create and start vault. This will block until a `Command` to free it is fired.
    pub fn new(
        routing_node: Node,
        event_receiver: Receiver<RoutingEvent>,
        client_receiver: Receiver<ClientEvent>,
        config: &Config,
        command_receiver: Receiver<Command>,
        mut rng: R,
    ) -> Result<Self> {
        let mut init_mode = Init::Load;

        let (is_elder, id) = Self::read_state(&config)?.unwrap_or_else(|| {
            let id = NodeFullId::new(&mut rng);
            init_mode = Init::New;
            (false, id)
        });

        #[cfg(feature = "mock_parsec")]
        {
            trace!(
                "creating vault {:?} with routing_id {:?}",
                id.public_id().name(),
                routing_node.id()
            );
        }

        let root_dir = config.root_dir()?;
        let root_dir = root_dir.as_path();

        let routing_node = Rc::new(RefCell::new(routing_node));

        let state = if is_elder {
            let total_used_space = Rc::new(Cell::new(0));
            let client_handler = ClientHandler::new(
                id.public_id().clone(),
                &config,
                &total_used_space,
                init_mode,
                routing_node.clone(),
            )?;
            let data_handler = DataHandler::new(
                id.public_id().clone(),
                &config,
                &total_used_space,
                init_mode,
                is_elder,
                routing_node.clone(),
            )?;
            State::Elder {
                client_handler,
                data_handler,
                accumulator: SignatureAccumulator::new(),
            }
        } else {
            info!("Initializing new Vault as Infant");
            State::Infant
        };

        let vault = Self {
            id,
            root_dir: root_dir.to_path_buf(),
            state,
            event_receiver,
            client_receiver,
            command_receiver,
            routing_node,
            rng,
        };
        vault.dump_state()?;
        Ok(vault)
    }

    /// Returns our connection info.
    pub fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.routing_node
            .borrow_mut()
            .our_connection_info()
            .map_err(From::from)
    }

    /// Returns whether routing node is in elder state.
    pub fn is_elder(&mut self) -> bool {
        self.routing_node.borrow().is_elder()
    }

    /// Runs the main event loop. Blocks until the vault is terminated.
    pub fn run(&mut self) {
        loop {
            let mut sel = Select::new();

            let mut r_node = self.routing_node.borrow_mut();
            r_node.register(&mut sel);
            let routing_event_rx_idx = sel.recv(&self.event_receiver);
            let client_network_rx_idx = sel.recv(&self.client_receiver);
            let command_rx_idx = sel.recv(&self.command_receiver);

            let selected_operation = sel.ready();
            drop(r_node);

            match selected_operation {
                idx if idx == client_network_rx_idx => {
                    let event = match self.client_receiver.recv() {
                        Ok(ev) => ev,
                        Err(e) => panic!("FIXME: {:?}", e),
                    };
                    self.step_client(event);
                }
                idx if idx == routing_event_rx_idx => {
                    let event = match self.event_receiver.recv() {
                        Ok(ev) => ev,
                        Err(e) => panic!("FIXME: {:?}", e),
                    };
                    self.step_routing(event);
                }
                idx if idx == command_rx_idx => {
                    let command = match self.command_receiver.recv() {
                        Ok(ev) => ev,
                        Err(e) => panic!("FIXME: {:?}", e),
                    };
                    match command {
                        Command::Shutdown => break,
                    }
                }
                idx => {
                    if let Err(err) = self
                        .routing_node
                        .borrow_mut()
                        .handle_selected_operation(idx)
                    {
                        warn!("Could not process operation: {}", err);
                    }
                }
            }
        }
    }

    fn promote_to_adult(&mut self) -> Result<()> {
        let mut config = Config::default();
        config.set_root_dir(self.root_dir.clone());
        let total_used_space = Rc::new(Cell::new(0));
        let data_handler = DataHandler::new(
            self.id.public_id().clone(),
            &config,
            &total_used_space,
            Init::New,
            false,
            self.routing_node.clone(),
        )?;
        self.state = State::Adult {
            data_handler,
            accumulator: SignatureAccumulator::new(),
        };
        Ok(())
    }

    fn promote_to_elder(&mut self) -> Result<()> {
        let mut config = Config::default();
        config.set_root_dir(self.root_dir.clone());
        let total_used_space = Rc::new(Cell::new(0));
        let client_handler = ClientHandler::new(
            self.id.public_id().clone(),
            &config,
            &total_used_space,
            Init::New,
            self.routing_node.clone(),
        )?;
        let data_handler = DataHandler::new(
            self.id.public_id().clone(),
            &config,
            &total_used_space,
            Init::New,
            true,
            self.routing_node.clone(),
        )?;
        self.state = State::Elder {
            client_handler,
            data_handler,
            accumulator: SignatureAccumulator::new(),
        };
        Ok(())
    }

    /// Processes any outstanding network events and returns. Does not block.
    /// Returns whether at least one event was processed.
    pub fn poll(&mut self) -> bool {
        let mut _processed = false;
        loop {
            let mut sel = Select::new();
            let mut r_node = self.routing_node.borrow_mut();
            r_node.register(&mut sel);
            let routing_event_rx_idx = sel.recv(&self.event_receiver);
            let client_network_rx_idx = sel.recv(&self.client_receiver);
            let command_rx_idx = sel.recv(&self.command_receiver);

            if let Ok(selected_operation) = sel.try_ready() {
                drop(r_node);

                match selected_operation {
                    idx if idx == client_network_rx_idx => {
                        let event = match self.client_receiver.recv() {
                            Ok(ev) => ev,
                            Err(e) => panic!("FIXME: {:?}", e),
                        };
                        self.step_client(event);
                        _processed = true;
                    }
                    idx if idx == routing_event_rx_idx => {
                        let event = match self.event_receiver.recv() {
                            Ok(ev) => ev,
                            Err(e) => panic!("FIXME: {:?}", e),
                        };
                        self.step_routing(event);
                        _processed = true;
                    }
                    idx if idx == command_rx_idx => {
                        let command = match self.command_receiver.recv() {
                            Ok(ev) => ev,
                            Err(e) => panic!("FIXME: {:?}", e),
                        };
                        match command {
                            Command::Shutdown => (),
                        }
                        _processed = true;
                    }
                    idx => {
                        if let Err(err) = self
                            .routing_node
                            .borrow_mut()
                            .handle_selected_operation(idx)
                        {
                            warn!("Could not process operation: {}", err);
                            break;
                        }
                    }
                }
            } else {
                break;
            }
        }

        _processed
    }

    fn step_routing(&mut self, event: RoutingEvent) {
        debug!("Received routing event: {:?}", event);
        let mut maybe_action = self.handle_routing_event(event);
        while let Some(action) = maybe_action {
            maybe_action = self.handle_action(action);
        }
    }

    fn step_client(&mut self, event: ClientEvent) {
        let mut maybe_action = self.handle_client_event(event);
        while let Some(action) = maybe_action {
            maybe_action = self.handle_action(action);
        }
    }

    fn handle_routing_event(&mut self, event: RoutingEvent) -> Option<Action> {
        match event {
            RoutingEvent::Consensus(custom_event) => {
                match bincode::deserialize::<ConsensusAction>(&custom_event) {
                    Ok(consensus_action) => {
                        let client_handler = self.client_handler_mut()?;
                        client_handler.handle_consensused_action(consensus_action)
                    }
                    Err(e) => {
                        error!("Invalid ConsensusAction passed from Routing: {:?}", e);
                        None
                    }
                }
            }
            RoutingEvent::PromotedToAdult => self.promote_to_adult().map_or_else(
                |err| {
                    error!("Error when promoting Vault to Adult: {:?}", err);
                    None
                },
                |()| {
                    info!("Vault promoted to Adult");
                    None
                },
            ),
            RoutingEvent::PromotedToElder => self.promote_to_elder().map_or_else(
                |err| {
                    error!("Error when promoting Vault to Elder: {:?}", err);
                    None
                },
                |()| {
                    info!("Vault promoted to Elder");
                    None
                },
            ),
            RoutingEvent::MessageReceived { content, src, dst } => {
                info!(
                    "Received message: {:8?}\n Sent from {:?} to {:?}",
                    HexFmt(&content),
                    src,
                    dst
                );
                self.handle_routing_message(src, content)
            }
            RoutingEvent::MemberLeft { name, age: _u8 } => {
                trace!("A node has left the section. Node: {:?}", name);
                let get_copy_actions = self
                    .data_handler_mut()?
                    .trigger_chunk_duplication(XorName(name.0));
                if let Some(copy_actions) = get_copy_actions {
                    for action in copy_actions {
                        let _ = self.handle_action(action);
                    }
                };
                None
            }
            RoutingEvent::MemberJoined { .. } => {
                trace!("New member has joined the section");
                let elder_count = self.routing_node.borrow().our_elders().count();
                let adult_count = self.routing_node.borrow().our_adults().count();
                info!("No. of Elders: {}", elder_count);
                info!("No. of Adults: {}", adult_count);
                None
            }
            RoutingEvent::Connected(_) => {
                info!("Section has accepted the vault.");
                None
            }
            // Ignore all other events
            _ => None,
        }
    }

    fn accumulate_rpc(&mut self, src: SrcLocation, rpc: Rpc) -> Option<Action> {
        match rpc {
            Rpc::Request {
                message_id,
                proof: proof_share,
                request,
                requester,
            } => match self
                .accumulator_mut()?
                .add((request, message_id), proof_share.clone()?)
            {
                Ok(((request, message_id), proof)) => {
                    info!("Got enough signatures for {:?}", message_id);
                    let prefix = match src {
                        SrcLocation::Node(name) => xor_name::Prefix::new(32, name),
                        SrcLocation::Section(prefix) => prefix,
                    };
                    let accumulated_rpc = Rpc::Request {
                        request,
                        requester,
                        message_id,
                        proof: proof_share,
                    };
                    self.data_handler_mut()?.handle_vault_rpc(
                        SrcLocation::Section(prefix),
                        accumulated_rpc,
                        Some(proof),
                    )
                }
                Err(AccumulationError::NotEnoughShares) => {
                    info!("Not enough shares for {:?}", message_id);
                    None
                }
                Err(AccumulationError::AlreadyAccumulated) => {
                    info!("Already accumlated request with {:?}", message_id);
                    None
                }
                Err(AccumulationError::InvalidShare) => {
                    info!("Got invalid signature share for {:?}", message_id);
                    None
                }
                Err(err) => {
                    error!(
                        "Unexpected error when accumulating signatures for {:?}: {:?}",
                        message_id, err
                    );
                    None
                }
            },
            Rpc::Duplicate {
                message_id,
                proof: proof_share,
                address,
                holders,
            } => {
                let request = Request::IData(safe_nd::IDataRequest::Get(address));
                match self
                    .accumulator_mut()?
                    .add((request, message_id), proof_share.clone()?)
                {
                    Ok(((_, message_id), proof)) => {
                        info!("Got enough signatures for duplication {:?}", message_id);
                        let prefix = match src {
                            SrcLocation::Node(name) => xor_name::Prefix::new(32, name),
                            SrcLocation::Section(prefix) => prefix,
                        };
                        let accumulated_rpc = Rpc::Duplicate {
                            address,
                            holders,
                            message_id,
                            proof: proof_share,
                        };
                        self.data_handler_mut()?.handle_vault_rpc(
                            SrcLocation::Section(prefix),
                            accumulated_rpc,
                            Some(proof),
                        )
                    }
                    Err(AccumulationError::NotEnoughShares) => {
                        info!("Not enough shares for {:?}", message_id);
                        None
                    }
                    Err(AccumulationError::AlreadyAccumulated) => {
                        info!("Already accumlated request with {:?}", message_id);
                        None
                    }
                    Err(AccumulationError::InvalidShare) => {
                        info!("Got invalid signature share for {:?}", message_id);
                        None
                    }
                    Err(err) => {
                        error!(
                            "Unexpected error when accumulating signatures for {:?}: {:?}",
                            message_id, err
                        );
                        None
                    }
                }
            }
            rpc => {
                error!("Should not accumulate: {:?}", rpc);
                None
            }
        }
    }

    fn handle_routing_message(&mut self, src: SrcLocation, message: Vec<u8>) -> Option<Action> {
        match bincode::deserialize::<Rpc>(&message) {
            Ok(rpc) => match &rpc {
                Rpc::Request {
                    request,
                    requester,
                    proof,
                    ..
                } => {
                    debug!("Got {:?} from {:?}", request, requester);
                    if matches!(requester, PublicId::Node(_)) {
                        if let Some(ProofShare {
                            signature_share,
                            public_key_set,
                            ..
                        }) = proof
                        {
                            debug!("Got IDataGet request from a node for duplication");
                            let signature = signature_share.clone().0;
                            let public_key = public_key_set.public_key();
                            self.data_handler_mut()?.handle_vault_rpc(
                                src,
                                rpc,
                                Some(Proof {
                                    signature,
                                    public_key,
                                }),
                            )
                        } else {
                            error!("Signature missing from duplication GET request");
                            None
                        }
                    } else {
                        let id = *self.routing_node.borrow().id().name();
                        info!(
                            "{}: Accumulating signatures for {:?}",
                            &id,
                            rpc.message_id()
                        );
                        match request {
                            Request::IData(_) => self.accumulate_rpc(src, rpc),
                            other => unimplemented!("Should not receive: {:?}", other),
                        }
                    }
                }
                Rpc::Response { response, .. } => match response {
                    Response::Mutation(_) | Response::GetIData(_) => {
                        self.data_handler_mut()?.handle_vault_rpc(src, rpc, None)
                    }
                    _ => unimplemented!("Should not receive: {:?}", response),
                },
                Rpc::Duplicate { .. } => self.accumulate_rpc(src, rpc),
                Rpc::DuplicationComplete { .. } => {
                    self.data_handler_mut()?.handle_vault_rpc(src, rpc, None)
                }
            },
            Err(e) => {
                error!("Error deserializing routing message into Rpc type: {:?}", e);
                None
            }
        }
    }

    fn handle_client_event(&mut self, event: ClientEvent) -> Option<Action> {
        use ClientEvent::*;

        let mut rng = ChaChaRng::from_seed(self.rng.gen());

        let client_handler = self.client_handler_mut()?;
        match event {
            ConnectedTo { peer } => client_handler.handle_new_connection(peer.peer_addr()),
            ConnectionFailure { peer, .. } => {
                client_handler.handle_connection_failure(peer.peer_addr());
            }
            NewMessage { peer, msg } => {
                return client_handler.handle_client_message(peer.peer_addr(), &msg, &mut rng);
            }
            SentUserMessage { peer, .. } => {
                trace!(
                    "{}: Succesfully sent message to: {}",
                    self,
                    peer.peer_addr()
                );
            }
            UnsentUserMessage { peer, .. } => {
                info!("{}: Not sent message to: {}", self, peer.peer_addr());
            }
            BootstrapFailure | BootstrappedTo { .. } => {
                error!("unexpected bootstrapping client event")
            }
            Finish => {
                info!("{}: Received Finish event", self);
            }
        }
        None
    }

    #[allow(dead_code)]
    fn vote_for_action(&mut self, action: &ConsensusAction) -> Option<Action> {
        self.routing_node
            .borrow_mut()
            .vote_for_user_event(utils::serialise(&action))
            .map_or_else(
                |_err| {
                    error!("Cannot vote. Vault is not an elder");
                    None
                },
                |()| None,
            )
    }

    fn handle_action(&mut self, action: Action) -> Option<Action> {
        trace!("{} handle action {:?}", self, action);
        use Action::*;
        match action {
            // Bypass client requests
            // VoteFor(action) => self.vote_for_action(&action),
            VoteFor(action) => self.client_handler_mut()?.handle_consensused_action(action),
            ForwardClientRequest(rpc) => self.forward_client_request(rpc),
            ProxyClientRequest(rpc) => self.proxy_client_request(rpc),
            RespondToOurDataHandlers { rpc } => {
                // TODO - once Routing is integrated, we'll construct the full message to send
                //        onwards, and then if we're also part of the data handlers, we'll call that
                //        same handler which Routing will call after receiving a message.

                self.respond_to_data_handlers(rpc)
            }
            RespondToClientHandlers { sender, rpc } => {
                let client_name = utils::requester_address(&rpc);

                // TODO - once Routing is integrated, we'll construct the full message to send
                //        onwards, and then if we're also part of the client handlers, we'll call that
                //        same handler which Routing will call after receiving a message.
                debug!("Responded to client handlers with {:?}", &rpc);
                if self.self_is_handler_for(&client_name) {
                    return self.client_handler_mut()?.handle_vault_rpc(sender, rpc);
                }
                None
            }
            SendToPeers { targets, rpc } => {
                let mut next_action = None;
                for target in targets {
                    if target == *self.id.public_id().name() {
                        info!("Vault is one of the targets. Accumulating message locally");
                        next_action = self.accumulate_rpc(
                            SrcLocation::Node(xor_name::XorName(target.0)),
                            rpc.clone(),
                        );
                    } else {
                        // Always None
                        let _ = self.send_message_to_peer(target, rpc.clone());
                    }
                }
                next_action
            }
            RespondToClient {
                message_id,
                response,
            } => {
                self.client_handler_mut()?
                    .respond_to_client(message_id, response);
                None
            }
        }
    }

    fn respond_to_data_handlers(&self, rpc: Rpc) -> Option<Action> {
        let name = *self.routing_node.borrow().id().name();
        self.routing_node
            .borrow_mut()
            .send_message(
                SrcLocation::Node(name),
                DstLocation::Section(name),
                utils::serialise(&rpc),
            )
            .map_or_else(
                |err| {
                    error!("Unable to respond to our data handlers: {:?}", err);
                    None
                },
                |()| {
                    info!("Responded to our data handlers with: {:?}", &rpc);
                    None
                },
            )
    }

    fn send_message_to_peer(&self, target: XorName, rpc: Rpc) -> Option<Action> {
        let name = *self.routing_node.borrow().id().name();
        self.routing_node
            .borrow_mut()
            .send_message(
                SrcLocation::Node(name),
                DstLocation::Node(xor_name::XorName(target.0)),
                utils::serialise(&rpc),
            )
            .map_or_else(
                |err| {
                    error!("Unable to send message to Peer: {:?}", err);
                    None
                },
                |()| {
                    info!("Sent message to Peer {:?} from node {:?}", target, name);
                    None
                },
            )
    }

    fn forward_client_request(&mut self, rpc: Rpc) -> Option<Action> {
        trace!("{} received a client request {:?}", self, rpc);
        let requester_name = if let Rpc::Request {
            request: Request::LoginPacket(LoginPacketRequest::CreateFor { ref new_owner, .. }),
            ..
        } = rpc
        {
            XorName::from(*new_owner)
        } else {
            utils::requester_address(&rpc)
        };
        let dst_address = if let Rpc::Request { ref request, .. } = rpc {
            match request.dest_address() {
                Some(address) => address,
                None => {
                    if let Request::Client(ClientRequest::InsAuthKey { .. })
                    | Request::Client(ClientRequest::DelAuthKey { .. }) = request
                    {
                        Cow::Borrowed(self.id.public_id().name())
                    } else {
                        error!("{}: Logic error - no data handler address available.", self);
                        return None;
                    }
                }
            }
        } else {
            error!("{}: Logic error - unexpected RPC.", self);
            return None;
        };

        // TODO - once Routing is integrated, we'll construct the full message to send
        //        onwards, and then if we're also part of the data handlers, we'll call that
        //        same handler which Routing will call after receiving a message.

        if self.self_is_handler_for(&dst_address) {
            let dst_section_address = *dst_address.clone();
            // TODO - We need a better way for determining which handler should be given the
            //        message.
            if let Rpc::Request { request, .. } = &rpc {
                match request {
                    Request::LoginPacket(_) | Request::Coins(_) | Request::Client(_) => self
                        .client_handler_mut()?
                        .handle_vault_rpc(requester_name, rpc),
                    _data_request => self.data_handler_mut()?.handle_vault_rpc(
                        SrcLocation::Node(xor_name::XorName(dst_section_address.0)), // dummy xorname
                        rpc,
                        None,
                    ),
                }
            } else {
                error!("{}: Logic error - unexpected RPC.", self);
                None
            }
        } else {
            None
        }
    }

    fn proxy_client_request(&mut self, rpc: Rpc) -> Option<Action> {
        let requester_name = utils::requester_address(&rpc);
        let dst_address = if let Rpc::Request {
            request: Request::LoginPacket(LoginPacketRequest::CreateFor { ref new_owner, .. }),
            ..
        } = rpc
        {
            XorName::from(*new_owner)
        } else {
            error!("{}: Logic error - unexpected RPC.", self);
            return None;
        };

        // TODO - once Routing is integrated, we'll construct the full message to send
        //        onwards, and then if we're also part of the data handlers, we'll call that
        //        same handler which Routing will call after receiving a message.

        if self.self_is_handler_for(&dst_address) {
            return self
                .client_handler_mut()?
                .handle_vault_rpc(requester_name, rpc);
        }
        None
    }

    fn self_is_handler_for(&self, _address: &XorName) -> bool {
        true
    }

    // TODO - remove this
    #[allow(unused)]
    fn client_handler(&self) -> Option<&ClientHandler> {
        match &self.state {
            State::Infant => None,
            State::Elder {
                ref client_handler, ..
            } => Some(client_handler),
            State::Adult { .. } => None,
        }
    }

    fn client_handler_mut(&mut self) -> Option<&mut ClientHandler> {
        match &mut self.state {
            State::Infant => None,
            State::Elder {
                ref mut client_handler,
                ..
            } => Some(client_handler),
            State::Adult { .. } => None,
        }
    }

    #[allow(unused)]
    fn accumulator(&self) -> Option<&SignatureAccumulator<(Request, MessageId)>> {
        match &self.state {
            State::Infant => None,
            State::Elder {
                ref accumulator, ..
            } => Some(accumulator),
            State::Adult {
                ref accumulator, ..
            } => Some(accumulator),
        }
    }

    fn accumulator_mut(&mut self) -> Option<&mut SignatureAccumulator<(Request, MessageId)>> {
        match &mut self.state {
            State::Infant => None,
            State::Elder {
                ref mut accumulator,
                ..
            } => Some(accumulator),
            State::Adult {
                ref mut accumulator,
                ..
            } => Some(accumulator),
        }
    }

    // TODO - remove this
    #[allow(unused)]
    fn data_handler(&self) -> Option<&DataHandler> {
        match &self.state {
            State::Infant => None,
            State::Elder {
                ref data_handler, ..
            } => Some(data_handler),
            State::Adult {
                ref data_handler, ..
            } => Some(data_handler),
        }
    }

    fn data_handler_mut(&mut self) -> Option<&mut DataHandler> {
        match &mut self.state {
            State::Infant => None,
            State::Elder {
                ref mut data_handler,
                ..
            } => Some(data_handler),
            State::Adult {
                ref mut data_handler,
                ..
            } => Some(data_handler),
        }
    }

    fn dump_state(&self) -> Result<()> {
        let path = self.root_dir.join(STATE_FILENAME);
        let is_elder = matches!(self.state, State::Elder { .. });
        Ok(fs::write(path, utils::serialise(&(is_elder, &self.id)))?)
    }

    /// Returns Some((is_elder, ID)) or None if file doesn't exist.
    fn read_state(config: &Config) -> Result<Option<(bool, NodeFullId)>> {
        let path = config.root_dir()?.join(STATE_FILENAME);
        if !path.is_file() {
            return Ok(None);
        }
        let contents = fs::read(path)?;
        Ok(Some(bincode::deserialize(&contents)?))
    }
}

impl<R: CryptoRng + Rng> Display for Vault<R> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.public_id())
    }
}
