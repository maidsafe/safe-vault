// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::state_db::Command;
use crossbeam_channel::{Receiver as Channel, Select};
use routing::{event::Event as RoutingEvent, Node as Routing, TransportEvent as ClientEvent};
use std::{cell::RefCell, rc::Rc};

///
pub struct Receiver {
    network_receiver: Channel<RoutingEvent>,
    client_receiver: Channel<ClientEvent>,
    command_receiver: Channel<Command>,
    routing: Rc<RefCell<Routing>>,
}

pub enum Received {
    Client(ClientEvent),
    Network(RoutingEvent),
    Shutdown,
    Unknown(ReceivingChannel),
}

pub struct ReceivingChannel {
    pub index: usize,
}

impl Receiver {
    ///
    pub fn new(
        network_receiver: Channel<RoutingEvent>,
        client_receiver: Channel<ClientEvent>,
        command_receiver: Channel<Command>,
        routing: Rc<RefCell<Routing>>,
    ) -> Self {
        Self {
            network_receiver,
            client_receiver,
            command_receiver,
            routing,
        }
    }

    /// Picks up next incoming event.
    pub fn next_event(&mut self) -> Received {
        let mut sel = Select::new();

        let mut r_node = self.routing.borrow_mut();
        r_node.register(&mut sel);
        let routing_event_index = sel.recv(&self.network_receiver);
        let client_network_index = sel.recv(&self.client_receiver);
        let command_index = sel.recv(&self.command_receiver);

        let selected_operation = sel.ready();
        drop(r_node);

        match selected_operation {
            index if index == client_network_index => {
                let event = match self.client_receiver.recv() {
                    Ok(ev) => ev,
                    Err(e) => panic!("FIXME: {:?}", e),
                };
                Received::Client(event)
            }
            index if index == routing_event_index => {
                let event = match self.network_receiver.recv() {
                    Ok(ev) => ev,
                    Err(e) => panic!("FIXME: {:?}", e),
                };
                Received::Network(event)
            }
            index if index == command_index => {
                let command = match self.command_receiver.recv() {
                    Ok(ev) => ev,
                    Err(e) => panic!("FIXME: {:?}", e),
                };
                match command {
                    Command::Shutdown => Received::Shutdown,
                }
            }
            index => Received::Unknown(ReceivingChannel { index }),
        }
    }
}
