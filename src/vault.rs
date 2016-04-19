// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#[cfg(not(feature = "use-mock-crust"))]
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
#[cfg(feature = "use-mock-crust")]
use std::sync::mpsc::Receiver;

use config_handler::{self, Config};
#[cfg(not(feature = "use-mock-crust"))]
use ctrlc::CtrlC;
#[cfg(feature = "use-mock-crust")]
use routing::DataIdentifier;
use routing::{Authority, Data, Event, RequestContent, RequestMessage, ResponseContent,
              ResponseMessage, RoutingMessage};
use xor_name::XorName;

use error::InternalError;
use personas::maid_manager::MaidManager;
use personas::data_manager::DataManager;

pub const CHUNK_STORE_PREFIX: &'static str = "safe-vault";
const DEFAULT_MAX_CAPACITY: u64 = 1024 * 1024 * 1024;

#[cfg(any(not(test), feature = "use-mock-crust"))]
pub use routing::Node as RoutingNode;

#[cfg(all(test, not(feature = "use-mock-crust")))]
pub use mock_routing::MockRoutingNode as RoutingNode;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    maid_manager: MaidManager,
    data_manager: DataManager,

    #[cfg(feature = "use-mock-crust")]
    routing_node: Option<RoutingNode>,
    #[cfg(feature = "use-mock-crust")]
    routing_receiver: Receiver<Event>,
}

// TODO: Consider specifying allowances in percent instead of using f64 to avoid floating point
// issues.
#[cfg_attr(feature="clippy", allow(cast_possible_truncation, cast_precision_loss, cast_sign_loss))]
fn init_components(optional_config: Option<Config>)
                   -> Result<(MaidManager, DataManager), InternalError> {
    ::sodiumoxide::init();

    let config = match optional_config {
        Some(config) => config,
        None => try!(config_handler::read_config_file()),
    };
    let max_capacity = config.max_capacity.unwrap_or(DEFAULT_MAX_CAPACITY);

    Ok((MaidManager::new(), try!(DataManager::new(max_capacity))))
}

impl Vault {
    /// Creates a network Vault instance.
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn new() -> Result<Self, InternalError> {
        let (maid_manager, data_manager) = try!(init_components(None));

        Ok(Vault {
            maid_manager: maid_manager,
            data_manager: data_manager,
        })
    }

    /// Creates a Vault instance for use with the mock-crust feature enabled.
    #[cfg(feature = "use-mock-crust")]
    pub fn new(config: Option<Config>) -> Result<Self, InternalError> {
        let (maid_manager, data_manager) = try!(init_components(config));

        let (routing_sender, routing_receiver) = mpsc::channel();
        let routing_node = try!(RoutingNode::new(routing_sender, false));

        Ok(Vault {
            maid_manager: maid_manager,
            data_manager: data_manager,
            routing_node: Some(routing_node),
            routing_receiver: routing_receiver,
        })
    }

    /// Run the event loop, processing events received from Routing.
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn run(&mut self) -> Result<(), InternalError> {
        let (routing_sender, routing_receiver) = mpsc::channel();
        let routing_node = try!(RoutingNode::new(routing_sender, true));
        let routing_node0 = Arc::new(Mutex::new(Some(routing_node)));
        let routing_node1 = routing_node0.clone();

        // Handle Ctrl+C to properly stop the vault instance.
        // TODO: do we really need this to terminate gracefully on Ctrl+C?
        CtrlC::set_handler(move || {
            // Drop the routing node to close the event channel which terminates
            // the receive loop and thus this whole function.
            let _ = routing_node0.lock().map(|mut node| node.take());
        });

        for event in routing_receiver.iter() {
            let routing_node = routing_node1.lock().expect("Node mutex poisoned.");

            if let Some(routing_node) = routing_node.as_ref() {
                self.process_event(routing_node, event);
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Non-blocking call to process any events in the event queue, returning true if
    /// any received, otherwise returns false.
    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
        let routing_node = self.routing_node.take().expect("routing_node should never be None");
        let mut result = routing_node.poll();

        while let Ok(event) = self.routing_receiver.try_recv() {
            self.process_event(&routing_node, event);
            result = true
        }

        self.routing_node = Some(routing_node);
        result
    }

    /// Get the names of all the data chunks stored in a personas' chunk store.
    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<DataIdentifier> {
        self.data_manager.get_stored_names()
    }

    /// Get the number of put requests the network processed for the given client.
    #[cfg(feature = "use-mock-crust")]
    pub fn get_maid_manager_put_count(&self, client_name: &XorName) -> Option<u64> {
        self.maid_manager.get_put_count(client_name)
    }

    fn process_event(&mut self, routing_node: &RoutingNode, event: Event) {
        trace!("Vault {} received an event from routing: {:?}",
               unwrap_result!(routing_node.name()),
               event);

        if let Err(error) = match event {
            Event::Request(request) => self.on_request(routing_node, request),
            Event::Response(response) => self.on_response(routing_node, response),
            Event::NodeAdded(node_added) => self.on_node_added(routing_node, node_added),
            Event::NodeLost(node_lost) => self.on_node_lost(routing_node, node_lost),
            Event::Connected => self.on_connected(),
            Event::Disconnected => self.on_disconnected(),
        } {
            warn!("Failed to handle event: {:?}", error);
        }
    }

    fn on_request(&mut self,
                  routing_node: &RoutingNode,
                  request: RequestMessage)
                  -> Result<(), InternalError> {
        match (&request.src, &request.dst, &request.content) {
            // ================== Get ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(ref data_id, ref msg_id)) => {
                self.data_manager.handle_get(routing_node, &request, data_id, msg_id)
            }
            // ================== Put ==================
            (&Authority::Client { .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(ref data, ref msg_id)) => {
                self.maid_manager.handle_put(routing_node, &request, data, msg_id)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(ref data, ref msg_id)) => {
                self.data_manager
                    .handle_put(routing_node, &request, data, msg_id)
            }
            // ================== Post ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Post(Data::Structured(ref data), ref msg_id)) => {
                self.data_manager.handle_post(routing_node, &request, data, msg_id)
            }
            // ================== Delete ==================
            (&Authority::Client { .. },
             &Authority::NaeManager(_),
             &RequestContent::Delete(Data::Structured(ref data), ref msg_id)) => {
                self.data_manager.handle_delete(routing_node, &request, data, msg_id)
            }
            // ================== Refresh ==================
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Refresh(ref serialised_msg, _)) => {
                self.maid_manager.handle_refresh(routing_node, serialised_msg)
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Refresh(ref serialised_msg, _)) => {
                self.data_manager.handle_refresh(routing_node, serialised_msg)
            }
            // ================== Invalid Request ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Request(request.clone()))),
        }
    }

    fn on_response(&mut self,
                   routing_node: &RoutingNode,
                   response: ResponseMessage)
                   -> Result<(), InternalError> {
        match (&response.src, &response.dst, &response.content) {
            // ================== PutSuccess ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutSuccess(ref data_id, ref msg_id)) => {
                self.maid_manager.handle_put_success(routing_node, data_id, msg_id)
            }
            // ================== PutFailure ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{
                    ref id,
                    request: RequestMessage {
                        content: RequestContent::Put(_, _), .. },
                    ref external_error_indicator }) => {
                self.maid_manager.handle_put_failure(routing_node, id, external_error_indicator)
            }
            // ================== Invalid Response ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Response(response.clone()))),
        }
    }

    fn on_node_added(&mut self,
                     routing_node: &RoutingNode,
                     node_added: XorName)
                     -> Result<(), InternalError> {
        self.maid_manager.handle_node_added(routing_node, &node_added);
        self.data_manager.handle_node_added(routing_node, &node_added);
        Ok(())
    }

    fn on_node_lost(&mut self,
                    routing_node: &RoutingNode,
                    node_lost: XorName)
                    -> Result<(), InternalError> {
        self.maid_manager.handle_node_lost(routing_node, &node_lost);
        self.data_manager.handle_node_lost(routing_node, &node_lost);
        Ok(())
    }

    fn on_connected(&self) -> Result<(), InternalError> {
        // TODO: what is expected to be done here?
        debug!("Vault connected");
        Ok(())
    }

    fn on_disconnected(&self) -> Result<(), InternalError> {
        // TODO: restart event loop with new routing object, discarding all current data
        debug!("Vault disconnected");
        Ok(())
    }
}
