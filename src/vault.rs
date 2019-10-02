// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action,
    adult::Adult,
    client_handler::ClientHandler,
    coins_handler::CoinsHandler,
    data_handler::DataHandler,
    quic_p2p::{Event, NodeInfo},
    rpc::Rpc,
    utils, Config, Error, Result,
};
use bincode;
use crossbeam_channel::{select, Receiver};
use log::{error, info, trace};
use safe_nd::{NodeFullId, Request, XorName};
use std::{
    cell::Cell,
    fmt::{self, Display, Formatter},
    fs,
    path::PathBuf,
    rc::Rc,
};

const STATE_FILENAME: &str = "state";

#[allow(clippy::large_enum_variant)]
enum State {
    Elder {
        client_handler: ClientHandler,
        data_handler: DataHandler,
        coins_handler: CoinsHandler,
    },
    // TODO - remove this
    #[allow(unused)]
    Adult(Adult),
}

/// Specifies whether to try loading cached data from disk, or to just construct a new instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Init {
    Load,
    New,
}

/// Command that the user can send to a running vault to control its execution.
pub enum Command {
    /// Shutdown the vault
    Shutdown,
}

/// Main vault struct.
pub struct Vault {
    id: NodeFullId,
    root_dir: PathBuf,
    state: State,
    event_receiver: Receiver<Event>,
    command_receiver: Receiver<Command>,
}

impl Vault {
    /// Construct a new vault instance.
    pub fn new(config: Config, command_receiver: Receiver<Command>) -> Result<Self> {
        let mut init_mode = Init::Load;
        let (is_elder, id) = Self::read_state(&config)?.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let id = NodeFullId::new(&mut rng);
            init_mode = Init::New;
            (true, id)
        });

        let root_dir = config.root_dir()?;
        let root_dir = root_dir.as_path();

        let (state, event_receiver) = if is_elder {
            let total_used_space = Rc::new(Cell::new(0));
            let (client_handler, event_receiver) = ClientHandler::new(
                id.public_id().clone(),
                &config,
                &total_used_space,
                init_mode,
            )?;
            let data_handler = DataHandler::new(
                id.public_id().clone(),
                &config,
                &total_used_space,
                init_mode,
            )?;
            let coins_handler = CoinsHandler::new(id.public_id().clone(), root_dir, init_mode)?;
            (
                State::Elder {
                    client_handler,
                    data_handler,
                    coins_handler,
                },
                event_receiver,
            )
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
            command_receiver,
        };
        vault.dump_state()?;
        Ok(vault)
    }

    /// Returns our connection info.
    pub fn our_connection_info(&mut self) -> Result<NodeInfo> {
        match self.state {
            State::Elder {
                ref mut client_handler,
                ..
            } => client_handler.our_connection_info(),
            State::Adult { .. } => unimplemented!(),
        }
    }

    /// Runs the main event loop. Blocks until the vault is terminated.
    // FIXME: remove when https://github.com/crossbeam-rs/crossbeam/issues/404 is resolved
    #[allow(clippy::zero_ptr, clippy::drop_copy)]
    pub fn run(&mut self) {
        loop {
            select! {
                recv(self.event_receiver) -> event => {
                    if let Ok(event) = event {
                        self.step(event)
                    } else {
                        break
                    }
                }
                recv(self.command_receiver) -> command => {
                    if let Ok(Command::Shutdown) = command {
                        trace!("{}: Shutdown command received", self);
                        break
                    }
                }
            }
        }
    }

    /// Processes any outstanding network events and returns. Does not block.
    /// Returns whether at least one event was processed.
    pub fn poll(&mut self) -> bool {
        let mut processed = false;

        while let Ok(event) = self.event_receiver.try_recv() {
            self.step(event);
            processed = true;
        }

        processed
    }

    fn step(&mut self, event: Event) {
        let mut maybe_action = self.handle_quic_p2p_event(event);
        while let Some(action) = maybe_action {
            maybe_action = self.handle_action(action);
        }
    }

    fn handle_quic_p2p_event(&mut self, event: Event) -> Option<Action> {
        let client_handler = self.client_handler_mut()?;
        match event {
            Event::ConnectedTo { peer } => client_handler.handle_new_connection(peer),
            Event::ConnectionFailure { peer_addr, err } => {
                client_handler.handle_connection_failure(peer_addr, Error::from(err));
            }
            Event::NewMessage { peer_addr, msg } => {
                return client_handler.handle_client_message(peer_addr, msg);
            }
            Event::SentUserMessage { peer_addr, .. } => {
                trace!("{}: Succesfully sent message to: {}", self, peer_addr);
            }
            Event::UnsentUserMessage { peer_addr, .. } => {
                info!("{}: Not sent message to: {}", self, peer_addr);
            }
            Event::BootstrapFailure | Event::BootstrappedTo { .. } | Event::Finish => {
                info!("{}: Unexpected event: {}", self, event);
            }
        }
        None
    }

    fn handle_action(&mut self, action: Action) -> Option<Action> {
        use Action::*;
        match action {
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
        }
    }

    fn forward_client_request(&mut self, rpc: Rpc) -> Option<Action> {
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
                    error!("{}: Logic error - no data handler address available.", self);
                    return None;
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
    fn coins_handler(&self) -> Option<&CoinsHandler> {
        match &self.state {
            State::Elder {
                ref coins_handler, ..
            } => Some(coins_handler),
            State::Adult(_) => None,
        }
    }

    // TODO - remove this
    #[allow(unused)]
    fn coins_handler_mut(&mut self) -> Option<&mut CoinsHandler> {
        match &mut self.state {
            State::Elder {
                ref mut coins_handler,
                ..
            } => Some(coins_handler),
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

impl Display for Vault {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id.public_id())
    }
}
