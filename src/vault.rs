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
    coins_handler::CoinsHandler,
    destination_elder::DestinationElder,
    quic_p2p::{Event, NodeInfo},
    source_elder::SourceElder,
    utils, Config, Result,
};
use bincode;
use crossbeam_channel::Receiver;
use log::{error, info};
use safe_nd::{NodeFullId, XorName};
use std::{
    fmt::{self, Display, Formatter},
    fs,
    path::PathBuf,
};

const STATE_FILENAME: &str = "state";

#[allow(clippy::large_enum_variant)]
enum State {
    Elder {
        src: SourceElder,
        dst: DestinationElder,
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

/// Main vault struct.
pub struct Vault {
    id: NodeFullId,
    root_dir: PathBuf,
    state: State,
    event_receiver: Receiver<Event>,
}

// TODO - remove this
#[allow(unused)]
impl Vault {
    /// Construct a new vault instance.
    pub fn new(config: Config) -> Result<Self> {
        let mut init_mode = Init::Load;
        let (is_elder, id) = Self::read_state(&config)?.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let id = NodeFullId::new(&mut rng);
            init_mode = Init::New;
            (true, id)
        });

        let root_dir = config.root_dir();

        let (state, event_receiver) = if is_elder {
            let (src, event_receiver) = SourceElder::new(
                id.public_id().clone(),
                &root_dir,
                config.quic_p2p_config(),
                init_mode,
            )?;
            let dst = DestinationElder::new(
                id.public_id().clone(),
                &root_dir,
                config.max_capacity(),
                init_mode,
            )?;
            let coins_handler = CoinsHandler::new(id.public_id().clone(), &root_dir, init_mode)?;
            (
                State::Elder {
                    src,
                    dst,
                    coins_handler,
                },
                event_receiver,
            )
        } else {
            let _adult = Adult::new(
                id.public_id().clone(),
                &root_dir,
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
        };
        vault.dump_state()?;
        Ok(vault)
    }

    /// Returns our connection info.
    pub fn our_connection_info(&mut self) -> Result<NodeInfo> {
        match self.state {
            State::Elder { ref mut src, .. } => src.our_connection_info(),
            State::Adult { .. } => unimplemented!(),
        }
    }

    /// Runs the main event loop. Blocks until the vault is terminated.
    pub fn run(&mut self) {
        while let Ok(event) = self.event_receiver.recv() {
            self.step(event)
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
        let source_elder = self.source_elder_mut()?;
        match event {
            Event::ConnectedTo { peer } => source_elder.handle_new_connection(peer),
            Event::ConnectionFailure { peer_addr } => {
                source_elder.handle_connection_failure(peer_addr);
            }
            Event::NewMessage { peer_addr, msg } => {
                return source_elder.handle_client_message(peer_addr, msg);
            }
            event => {
                info!("{}: Unexpected event: {}", self, event);
            }
        }
        None
    }

    fn handle_action(&mut self, action: Action) -> Option<Action> {
        use Action::*;
        match action {
            ForwardClientRequest {
                client_name,
                request,
                message_id,
            } => {
                let dst_elders_address = match utils::dst_elders_address(&request) {
                    Some(address) => address,
                    None => {
                        error!("{}: Logic error - no dst address available.", self);
                        return None;
                    }
                };

                // TODO - once Routing is integrated, we'll construct the full message to send
                //        onwards, and then if we're also part of the dst elders, we'll call that
                //        same handler which Routing will call after receiving a message.

                if self.self_is_dst_elder_for(&dst_elders_address) {
                    return self.destination_elder_mut()?.handle_request(
                        client_name,
                        request,
                        message_id,
                    );
                }
                None
            }
            RespondToOurDstElders {
                sender,
                response,
                message_id,
            } => {
                // TODO - once Routing is integrated, we'll construct the full message to send
                //        onwards, and then if we're also part of the dst elders, we'll call that
                //        same handler which Routing will call after receiving a message.

                self.destination_elder_mut()?
                    .handle_response(sender, response, message_id)
            }
            ForwardResponseToClient {
                sender,
                response,
                message_id,
            } => {
                let dst_elders = sender;
                // TODO - simplification during phase 1
                let src_elders = *self.id.public_id().name();
                self.source_elder_mut()?
                    .handle_node_response(dst_elders, src_elders, response, message_id)
            }
        }
    }

    fn self_is_dst_elder_for(&self, _address: &XorName) -> bool {
        true
    }

    fn source_elder(&self) -> Option<&SourceElder> {
        match &self.state {
            State::Elder { ref src, .. } => Some(src),
            State::Adult(_) => None,
        }
    }

    fn source_elder_mut(&mut self) -> Option<&mut SourceElder> {
        match &mut self.state {
            State::Elder { ref mut src, .. } => Some(src),
            State::Adult(_) => None,
        }
    }

    fn destination_elder(&self) -> Option<&DestinationElder> {
        match &self.state {
            State::Elder { ref dst, .. } => Some(dst),
            State::Adult(_) => None,
        }
    }

    fn destination_elder_mut(&mut self) -> Option<&mut DestinationElder> {
        match &mut self.state {
            State::Elder { ref mut dst, .. } => Some(dst),
            State::Adult(_) => None,
        }
    }

    fn coins_handler(&self) -> Option<&CoinsHandler> {
        match &self.state {
            State::Elder {
                ref coins_handler, ..
            } => Some(coins_handler),
            State::Adult(_) => None,
        }
    }

    fn coins_handler_mut(&mut self) -> Option<&mut CoinsHandler> {
        match &mut self.state {
            State::Elder {
                ref mut coins_handler,
                ..
            } => Some(coins_handler),
            State::Adult(_) => None,
        }
    }

    fn adult(&self) -> Option<&Adult> {
        match &self.state {
            State::Elder { .. } => None,
            State::Adult(ref adult) => Some(adult),
        }
    }

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
        let path = config.root_dir().join(STATE_FILENAME);
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
