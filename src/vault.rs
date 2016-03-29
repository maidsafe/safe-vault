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
use ctrlc::CtrlC;
use maidsafe_utilities::serialisation;
use routing::{Authority, Data, DataRequest, Event, RequestContent, RequestMessage,
              ResponseContent, ResponseMessage, RoutingMessage};
#[cfg(not(feature = "use-mock-crust"))]
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Sender};
#[cfg(feature = "use-mock-crust")]
use std::sync::mpsc::Receiver;
use xor_name::XorName;

use config_handler;
use error::InternalError;
use personas::immutable_data_manager::ImmutableDataManager;
use personas::maid_manager::MaidManager;
use personas::mpid_manager::MpidManager;
use personas::pmid_manager::PmidManager;
use personas::pmid_node::PmidNode;
use personas::structured_data_manager::StructuredDataManager;
use types::{Refresh, RefreshValue};

#[cfg(not(all(test, feature = "use-mock-routing")))]
pub type RoutingNode = ::routing::Node;

#[cfg(all(test, feature = "use-mock-routing"))]
pub type RoutingNode = ::mock_routing::MockRoutingNode;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    immutable_data_manager: ImmutableDataManager,
    maid_manager: MaidManager,
    mpid_manager: MpidManager,
    pmid_manager: PmidManager,
    pmid_node: PmidNode,
    structured_data_manager: StructuredDataManager,
    app_event_sender: Option<Sender<Event>>,

    #[cfg(feature = "use-mock-crust")] routing_node: Option<RoutingNode>,
    #[cfg(feature = "use-mock-crust")] routing_rx: Receiver<Event>,
}

fn init_components() -> Result<(ImmutableDataManager,
                                MaidManager,
                                MpidManager,
                                PmidManager,
                                PmidNode,
                                StructuredDataManager), InternalError> {
    ::sodiumoxide::init();

    let mut config = try!(config_handler::read_config_file());

    let pn_capacity = config.max_capacity.map_or(None, |max_capacity| Some(3 * max_capacity / 5));
    let sdm_capacity = config.max_capacity.map_or(None, |max_capacity| Some(3 * max_capacity / 10));
    let mpid_capacity = config.max_capacity.map_or(None, |max_capacity| Some(max_capacity / 10));

    if let Some(ref mut capacity) = config.max_capacity {
        *capacity = *capacity / 3;
    }

    Ok((ImmutableDataManager::new(),
        MaidManager::new(),
        MpidManager::new(&mpid_capacity),
        PmidManager::new(),
        try!(PmidNode::new(&pn_capacity)),
        StructuredDataManager::new(&sdm_capacity)))
}

impl Vault {
    #[cfg(not(feature = "use-mock-crust"))]
    pub fn new(app_event_sender: Option<Sender<Event>>) -> Result<Self, InternalError> {
        let (immutable_data_manager,
             maid_manager,
             mpid_manager,
             pmid_manager,
             pmid_node,
             structured_data_manager) = try!(init_components());

        Ok(Vault {
            immutable_data_manager: immutable_data_manager,
            maid_manager: maid_manager,
            mpid_manager: mpid_manager,
            pmid_manager: pmid_manager,
            pmid_node: pmid_node,
            structured_data_manager: structured_data_manager,
            app_event_sender: app_event_sender,
        })
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn new(app_event_sender: Option<Sender<Event>>) -> Result<Self, InternalError> {
        let (immutable_data_manager,
             maid_manager,
             mpid_manager,
             pmid_manager,
             pmid_node,
             structured_data_manager) = try!(init_components());

        let (routing_tx, routing_rx) = mpsc::channel();
        let routing_node = try!(RoutingNode::new(routing_tx));

        Ok(Vault {
            immutable_data_manager: immutable_data_manager,
            maid_manager: maid_manager,
            mpid_manager: mpid_manager,
            pmid_manager: pmid_manager,
            pmid_node: pmid_node,
            structured_data_manager: structured_data_manager,
            app_event_sender: app_event_sender,
            routing_node: Some(routing_node),
            routing_rx: routing_rx,
        })
    }

    #[cfg(not(feature = "use-mock-crust"))]
    pub fn run(&mut self) -> Result<(), InternalError> {
        let (routing_tx, routing_rx) = mpsc::channel();
        let routing_node = try!(RoutingNode::new(routing_tx));
        let routing_node0 = Arc::new(Mutex::new(Some(routing_node)));
        let routing_node1 = routing_node0.clone();

        // Handle Ctrl+C to properly stop the vault instance.
        // TODO: do we really need this to terminate gracefully on Ctrl+C?
        CtrlC::set_handler(move || {
            // Drop the routing node to close the event channel which terminates
            // the receive loop and thus this whole function.
            let _ = routing_node0.lock().unwrap().take();
        });

        for event in routing_rx.iter() {
            let routing_node = unwrap_result!(routing_node1.lock());

            if let Some(routing_node) = routing_node.as_ref() {
                self.process_event(routing_node, event);
            } else {
                break;
            }
        }

        Ok(())
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
        // Remove routing_node from self, so we can safely mutate self while
        // routing_node is borrowed.
        let mut routing_node = self.routing_node.take().unwrap();

        let result = if routing_node.poll() {
            while let Ok(event) = self.routing_rx.try_recv() {
                self.process_event(&routing_node, event);
            }

            true
        } else {
            false
        };

        // Put routing_node back to self as we are done with it.
        self.routing_node = Some(routing_node);
        result
    }

    fn process_event(&mut self, routing_node: &RoutingNode, event: Event) {
        trace!("Vault {} received an event from routing: {:?}",
               unwrap_result!(routing_node.name()),
               event);

        let _ = self.app_event_sender
                    .as_ref()
                    .map(|sender| sender.send(event.clone()));

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

        self.pmid_manager.check_timeout(routing_node);
    }

    fn on_request(&mut self,
                  routing_node: &RoutingNode,
                  request: RequestMessage)
                  -> Result<(), InternalError> {
        match (&request.src, &request.dst, &request.content) {
            // ================== Get ==================
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::Immutable(_, _), _)) => {
                self.immutable_data_manager.handle_get(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Get(DataRequest::Structured(_, _), _)) => {
                self.structured_data_manager.handle_get(routing_node, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Get(DataRequest::Immutable(_, _), _)) => {
                self.pmid_node.handle_get(routing_node, &request)
            }
            // ================== Put ==================
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) |
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Structured(_), _)) => {
                self.maid_manager.handle_put(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Plain(_), _)) |
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Put(Data::Plain(_), _)) => {
                self.mpid_manager.handle_put(routing_node, &request)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) => {
                self.immutable_data_manager.handle_put(routing_node, &request)
            }
            (&Authority::ClientManager(_),
             &Authority::NaeManager(_),
             &RequestContent::Put(Data::Structured(_), _)) => {
                self.structured_data_manager.handle_put(routing_node, &request)
            }
            (&Authority::NaeManager(_),
             &Authority::NodeManager(_),
             &RequestContent::Put(Data::Immutable(_), _)) => {
                self.pmid_manager.handle_put(routing_node, &request)
            }
            (&Authority::NodeManager(_),
             &Authority::ManagedNode(_),
             &RequestContent::Put(Data::Immutable(_), _)) => {
                self.pmid_node.handle_put(routing_node, &request)
            }
            // ================== Post ==================
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Post(Data::Structured(_), _)) => {
                self.structured_data_manager.handle_post(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Post(Data::Plain(_), _)) |
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RequestContent::Post(Data::Plain(_), _)) => {
                self.mpid_manager.handle_post(routing_node, &request)
            }
            // ================== Delete ==================
            (&Authority::Client{ .. },
             &Authority::ClientManager(_),
             &RequestContent::Delete(Data::Plain(_), _)) => {
                self.mpid_manager.handle_delete(routing_node, &request)
            }
            (&Authority::Client{ .. },
             &Authority::NaeManager(_),
             &RequestContent::Delete(Data::Structured(_), _)) => {
                self.structured_data_manager.handle_delete(routing_node, &request)
            }
            // ================== Refresh ==================
            (src, dst, &RequestContent::Refresh(ref serialised_refresh)) => {
                self.on_refresh(src, dst, serialised_refresh)
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
            // ================== GetSuccess ==================
            (&Authority::ManagedNode(_),
             &Authority::NaeManager(_),
             &ResponseContent::GetSuccess(Data::Immutable(_), _)) => {
                self.immutable_data_manager.handle_get_success(routing_node, &response)
            }
            // ================== GetFailure ==================
            (&Authority::ManagedNode(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::GetFailure{ ref id, ref request, ref external_error_indicator }) => {
                self.immutable_data_manager
                    .handle_get_failure(routing_node,
                                        pmid_node,
                                        id,
                                        request,
                                        external_error_indicator)
            }
            // ================== PutSuccess ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.maid_manager.handle_put_success(routing_node, message_id)
            }
            (&Authority::NodeManager(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.immutable_data_manager.handle_put_success(pmid_node, message_id)
            }
            (&Authority::ManagedNode(ref pmid_node),
             &Authority::NodeManager(_),
             &ResponseContent::PutSuccess(_, ref message_id)) => {
                self.pmid_manager.handle_put_success(routing_node, pmid_node, message_id)
            }
            // ================== PutFailure ==================
            (&Authority::NaeManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{
                    ref id,
                    request: RequestMessage {
                        content: RequestContent::Put(Data::Structured(_), _), .. },
                    ref external_error_indicator }) => {
                self.maid_manager.handle_put_failure(routing_node, id, external_error_indicator)
            }
            (&Authority::NodeManager(ref pmid_node),
             &Authority::NaeManager(_),
             &ResponseContent::PutFailure{ ref id, .. }) => {
                self.immutable_data_manager.handle_put_failure(routing_node, pmid_node, id)
            }
            (&Authority::ManagedNode(_),
             &Authority::NodeManager(_),
             &ResponseContent::PutFailure{ ref request, .. }) => {
                self.pmid_manager.handle_put_failure(routing_node, request)
            }
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &ResponseContent::PutFailure{ ref request, .. }) => {
                self.mpid_manager.handle_put_failure(routing_node, request)
            }
            // ================== Invalid Response ==================
            _ => Err(InternalError::UnknownMessageType(RoutingMessage::Response(response.clone()))),
        }
    }

    fn on_node_added(&mut self,
                     routing_node: &RoutingNode,
                     node_added: XorName)
                     -> Result<(), InternalError> {
        self.maid_manager.handle_churn(routing_node);
        self.immutable_data_manager.handle_node_added(routing_node, node_added);
        self.structured_data_manager.handle_churn(routing_node);
        self.pmid_manager.handle_churn(routing_node);
        self.pmid_node.handle_churn(routing_node);
        self.mpid_manager.handle_churn(routing_node);
        Ok(())
    }

    fn on_node_lost(&mut self,
                    routing_node: &RoutingNode,
                    node_lost: XorName)
                    -> Result<(), InternalError> {
        self.maid_manager.handle_churn(routing_node);
        self.immutable_data_manager.handle_node_lost(routing_node, node_lost);
        self.structured_data_manager.handle_churn(routing_node);
        self.pmid_manager.handle_churn(routing_node);
        self.pmid_node.handle_churn(routing_node);
        self.mpid_manager.handle_churn(routing_node);
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

    fn on_refresh(&mut self,
                  src: &Authority,
                  dst: &Authority,
                  serialised_refresh: &[u8])
                  -> Result<(), InternalError> {
        let refresh = try!(serialisation::deserialise::<Refresh>(serialised_refresh));
        match (src, dst, &refresh.value) {
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RefreshValue::MaidManagerAccount(ref account)) => {
                Ok(self.maid_manager.handle_refresh(refresh.name, account.clone()))
            }
            (&Authority::ClientManager(_),
             &Authority::ClientManager(_),
             &RefreshValue::MpidManagerAccount(ref account,
                                               ref stored_messages,
                                               ref received_headers)) => {
                Ok(self.mpid_manager
                       .handle_refresh(refresh.name, account, stored_messages, received_headers))
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RefreshValue::ImmutableDataManagerAccount(ref account)) => {
                Ok(self.immutable_data_manager.handle_refresh(refresh.name, account.clone()))
            }
            (&Authority::NaeManager(_),
             &Authority::NaeManager(_),
             &RefreshValue::StructuredDataManager(ref structured_data)) => {
                self.structured_data_manager.handle_refresh(structured_data.clone())
            }
            (&Authority::NodeManager(_),
             &Authority::NodeManager(_),
             &RefreshValue::PmidManagerAccount(ref account)) => {
                Ok(self.pmid_manager.handle_refresh(refresh.name, account.clone()))
            }
            _ => Err(InternalError::UnknownRefreshType(src.clone(), dst.clone(), refresh.clone())),
        }
    }
}

#[cfg(all(test, feature = "use-mock-crust"))]
mod tests {
    use super::*;
    use routing::mock_crust::{self, Network};

    #[test]
    fn how_to_use_mock_crust() {
        let network = Network::new();
        let service_handle = network.new_service_handle(None, None);

        let mut vault = mock_crust::make_current(&service_handle, || {
            unwrap_result!(Vault::new(None))
        });

        vault.poll();
    }
}

