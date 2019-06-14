// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    action::Action, adult::Adult, coins_handler::CoinsHandler, destination_elder::DestinationElder,
    source_elder::SourceElder, Config, Result,
};
use bincode;
use crossbeam_channel::Receiver;
use log::{info, trace};
use pickledb::PickleDb;
use quic_p2p::{Config as QuickP2pConfig, Event, Peer};
use safe_nd::{Challenge, Message, NodeFullId, PublicId, Request, Signature};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
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
    event_receiver: Option<Receiver<Event>>,
}

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
            let (src, event_receiver) =
                SourceElder::new(&root_dir, config.quic_p2p_config(), init_mode)?;
            let dst = DestinationElder::new(&root_dir, config.max_capacity(), init_mode)?;
            let coins_handler = CoinsHandler::new(&root_dir, init_mode)?;
            (
                State::Elder {
                    src,
                    dst,
                    coins_handler,
                },
                Some(event_receiver),
            )
        } else {
            let _adult = Adult::new(&root_dir, config.max_capacity(), init_mode)?;
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

    /// Run the main event loop.  Blocks until the vault is terminated.
    pub fn run(&mut self) {
        if let Some(event_receiver) = self.event_receiver.take() {
            for event in event_receiver.iter() {
                let mut some_action = self.handle_quic_p2p_event(event);
                while let Some(action) = some_action {
                    some_action = self.handle_action(action);
                }
            }
        } else {
            info!("Event receiver not available!");
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
                info!("Unexpected event: {}", event);
            }
        }
        None
    }

    fn handle_action(&mut self, _action: Action) -> Option<Action> {
        None
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
        Ok(fs::write(path, bincode::serialize(&(is_elder, &self.id))?)?)
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
