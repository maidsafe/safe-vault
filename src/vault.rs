// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::{Action, ConsensusAction},
    adult::Adult,
    client_handler::ClientHandler,
    data_handler::DataHandler,
    routing::{event::Event as RoutingEvent, NetworkEvent as ClientEvent, Node},
    rpc::Rpc,
    utils, Config, Result,
};
use crossbeam_channel::{Receiver, Select};
use log::{error, info, trace, warn};
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use safe_nd::{NodeFullId, Request, XorName};
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
    Elder {
        client_handler: ClientHandler,
        data_handler: DataHandler,
    },
    // TODO - remove this
    #[allow(unused)]
    Adult(Adult),
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
            (true, id)
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
            )?;
            State::Elder {
                client_handler,
                data_handler,
            }
        } else {
            let _adult = Adult::new(
                id.public_id().clone(),
                root_dir,
                config.max_capacity(),
                init_mode,
            )?;
            unimplemented!();
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

    #[cfg(feature = "mock_parsec")]
    /// Returns whether routing node is in elder state.
    pub fn is_elder(&mut self) -> bool {
        self.routing_node.borrow().is_elder()
    }

    /// Runs the main event loop. Blocks until the vault is terminated.
    // FIXME: remove when https://github.com/crossbeam-rs/crossbeam/issues/404 is resolved
    #[allow(clippy::zero_ptr, clippy::drop_copy)]
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
            // Ignore all other events
            _ => None,
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
            .vote_for(utils::serialise(&action));
        None
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
            RespondToOurDataHandlers { sender, rpc } => {
                // TODO - once Routing is integrated, we'll construct the full message to send
                //        onwards, and then if we're also part of the data handlers, we'll call that
                //        same handler which Routing will call after receiving a message.

                self.data_handler_mut()?.handle_vault_rpc(sender, rpc)
            }
            RespondToClientHandlers { sender, rpc } => {
                let client_name = utils::requester_address(&rpc);

                // TODO - once Routing is integrated, we'll construct the full message to send
                //        onwards, and then if we're also part of the client handlers, we'll call that
                //        same handler which Routing will call after receiving a message.

                if self.self_is_handler_for(client_name) {
                    return self.client_handler_mut()?.handle_vault_rpc(sender, rpc);
                }
                None
            }
            SendToPeers {
                sender,
                targets,
                rpc,
            } => {
                let mut next_action = None;
                for target in targets {
                    if target == *self.id.public_id().name() {
                        next_action = self
                            .data_handler_mut()?
                            .handle_vault_rpc(sender, rpc.clone());
                        // } else {
                        //     Send to target
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

    fn forward_client_request(&mut self, rpc: Rpc) -> Option<Action> {
        trace!("{} received a client request {:?}", self, rpc);
        let requester_name = if let Rpc::Request {
            request: Request::CreateLoginPacketFor { ref new_owner, .. },
            ..
        } = rpc
        {
            XorName::from(*new_owner)
        } else {
            *utils::requester_address(&rpc)
        };
        let dst_address = if let Rpc::Request { ref request, .. } = rpc {
            match utils::destination_address(&request) {
                Some(address) => address,
                None => {
                    if let Request::InsAuthKey { .. } | Request::DelAuthKey { .. } = request {
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
            // TODO - We need a better way for determining which handler should be given the
            //        message.
            return match rpc {
                Rpc::Request {
                    request: Request::CreateLoginPacket(_),
                    ..
                }
                | Rpc::Request {
                    request: Request::CreateLoginPacketFor { .. },
                    ..
                }
                | Rpc::Request {
                    request: Request::CreateBalance { .. },
                    ..
                }
                | Rpc::Request {
                    request: Request::TransferCoins { .. },
                    ..
                }
                | Rpc::Request {
                    request: Request::UpdateLoginPacket(..),
                    ..
                }
                | Rpc::Request {
                    request: Request::InsAuthKey { .. },
                    ..
                }
                | Rpc::Request {
                    request: Request::DelAuthKey { .. },
                    ..
                } => self
                    .client_handler_mut()?
                    .handle_vault_rpc(requester_name, rpc),
                _ => self
                    .data_handler_mut()?
                    .handle_vault_rpc(requester_name, rpc),
            };
        }
        None
    }

    fn proxy_client_request(&mut self, rpc: Rpc) -> Option<Action> {
        let requester_name = *utils::requester_address(&rpc);
        let dst_address = if let Rpc::Request {
            request: Request::CreateLoginPacketFor { ref new_owner, .. },
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
            State::Elder {
                ref client_handler, ..
            } => Some(client_handler),
            State::Adult(_) => None,
        }
    }

    fn client_handler_mut(&mut self) -> Option<&mut ClientHandler> {
        match &mut self.state {
            State::Elder {
                ref mut client_handler,
                ..
            } => Some(client_handler),
            State::Adult(_) => None,
        }
    }

    // TODO - remove this
    #[allow(unused)]
    fn data_handler(&self) -> Option<&DataHandler> {
        match &self.state {
            State::Elder {
                ref data_handler, ..
            } => Some(data_handler),
            State::Adult(_) => None,
        }
    }

    fn data_handler_mut(&mut self) -> Option<&mut DataHandler> {
        match &mut self.state {
            State::Elder {
                ref mut data_handler,
                ..
            } => Some(data_handler),
            State::Adult(_) => None,
        }
    }

    // TODO - remove this
    #[allow(unused)]
    fn adult(&self) -> Option<&Adult> {
        match &self.state {
            State::Elder { .. } => None,
            State::Adult(ref adult) => Some(adult),
        }
    }

    // TODO - remove this
    #[allow(unused)]
    fn adult_mut(&mut self) -> Option<&mut Adult> {
        match &mut self.state {
            State::Elder { .. } => None,
            State::Adult(ref mut adult) => Some(adult),
        }
    }

    fn dump_state(&self) -> Result<()> {
        let path = self.root_dir.join(STATE_FILENAME);
        let is_elder = match self.state {
            State::Elder { .. } => true,
            State::Adult(_) => false,
        };
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
