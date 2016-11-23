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


use cache::Cache;
use config_handler::{self, Config};
use error::InternalError;
use personas::data_manager::DataManager;
#[cfg(feature = "use-mock-crust")]
use personas::data_manager::IdAndVersion;
use personas::maid_manager::MaidManager;
use routing::{Authority, Data, NodeBuilder, Prefix, Request, Response, XorName};
use rust_sodium;
use std::env;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver};

pub const CHUNK_STORE_DIR: &'static str = "safe_vault_chunk_store";
const DEFAULT_MAX_CAPACITY: u64 = 2 * 1024 * 1024 * 1024;

pub use routing::Event;
pub use routing::Node as RoutingNode;

/// Main struct to hold all personas and Routing instance
pub struct Vault {
    maid_manager: MaidManager,
    data_manager: DataManager,
    _routing_node: Rc<RoutingNode>,
    routing_receiver: Receiver<Event>,
}

impl Vault {
    /// Creates a network Vault instance.
    pub fn new(first_vault: bool, use_cache: bool) -> Result<Self, InternalError> {
        let config = match config_handler::read_config_file() {
            Ok(cfg) => cfg,
            Err(InternalError::FileHandler(e)) => {
                error!("Config file could not be parsed : {:?}", e);
                return Err(From::from(e));
            }
            Err(e) => return Err(From::from(e)),
        };
        let builder = RoutingNode::builder().first(first_vault).deny_other_local_nodes();
        match Self::vault_with_config(builder, use_cache, config.clone()) {
            Ok(vault) => Ok(vault),
            Err(InternalError::ChunkStore(e)) => {
                error!("Incorrect path {:?} for chunk_store_root : {:?}",
                       config.chunk_store_root,
                       e);
                Err(From::from(e))
            }
            Err(e) => Err(From::from(e)),
        }
    }

    /// Allow construct vault with config for mock-crust tests.
    #[cfg(feature = "use-mock-crust")]
    pub fn new_with_config(first_vault: bool,
                           use_cache: bool,
                           config: Config)
                           -> Result<Self, InternalError> {
        Self::vault_with_config(RoutingNode::builder().first(first_vault), use_cache, config)
    }

    /// Allow construct vault with config for mock-crust tests.
    fn vault_with_config(builder: NodeBuilder,
                         use_cache: bool,
                         config: Config)
                         -> Result<Self, InternalError> {
        rust_sodium::init();

        let mut chunk_store_root = match config.chunk_store_root {
            Some(path_str) => Path::new(&path_str).to_path_buf(),
            None => env::temp_dir(),
        };
        chunk_store_root.push(CHUNK_STORE_DIR);

        let (routing_sender, routing_receiver) = mpsc::channel();
        let routing_node = Rc::new(if use_cache {
            builder.cache(Box::new(Cache::new())).create(routing_sender)
        } else {
            builder.create(routing_sender)
        }?);

        Ok(Vault {
            maid_manager: MaidManager::new(routing_node.clone()),
            data_manager: DataManager::new(routing_node.clone(),
                                           chunk_store_root,
                                           config.max_capacity
                                               .unwrap_or(DEFAULT_MAX_CAPACITY))?,
            _routing_node: routing_node.clone(),
            routing_receiver: routing_receiver,
        })

    }

    /// Run the event loop, processing events received from Routing.
    pub fn run(&mut self) -> Result<bool, InternalError> {
        while let Ok(event) = self.routing_receiver.recv() {
            if let Some(terminate) = self.process_event(event) {
                return Ok(terminate);
            }
        }
        // FIXME: decide if we want to restart here (in which case return `Ok(false)`).
        Ok(true)
    }

    /// Non-blocking call to process any events in the event queue, returning true if
    /// any received, otherwise returns false.
    #[cfg(feature = "use-mock-crust")]
    pub fn poll(&mut self) -> bool {
        let mut result = self._routing_node.poll();

        while let Ok(event) = self.routing_receiver.try_recv() {
            let _ignored_for_mock = self.process_event(event);
            result = true
        }

        result
    }

    /// Get the names of all the data chunks stored in a personas' chunk store.
    #[cfg(feature = "use-mock-crust")]
    pub fn get_stored_names(&self) -> Vec<IdAndVersion> {
        self.data_manager.get_stored_names()
    }

    /// Get the number of put requests the network processed for the given client.
    #[cfg(feature = "use-mock-crust")]
    pub fn get_maid_manager_put_count(&self, client_name: &XorName) -> Option<u64> {
        self.maid_manager.get_put_count(client_name)
    }

    /// Resend all unacknowledged messages.
    #[cfg(feature = "use-mock-crust")]
    pub fn resend_unacknowledged(&self) -> bool {
        self._routing_node.resend_unacknowledged()
    }

    /// Clear routing node state.
    #[cfg(feature = "use-mock-crust")]
    pub fn clear_state(&self) {
        self._routing_node.clear_state()
    }

    /// Vault node name
    #[cfg(feature = "use-mock-crust")]
    pub fn name(&self) -> XorName {
        unwrap!(self._routing_node.name())
    }

    fn process_event(&mut self, event: Event) -> Option<bool> {
        let mut ret = None;

        if let Err(error) = match event {
            Event::Request { request, src, dst } => self.on_request(request, src, dst),
            Event::Response { response, src, dst } => self.on_response(response, src, dst),
            Event::RestartRequired => {
                warn!("Restarting Vault");
                ret = Some(false);
                Ok(())
            }
            Event::Terminate => {
                ret = Some(true);
                Ok(())
            }
            Event::NodeAdded(node_added) => {
                self.on_node_added(node_added)
            }
            Event::NodeLost(node_lost) => {
                self.on_node_lost(node_lost)
            }
            Event::GroupSplit(prefix) => {
                self.on_group_split(prefix)
            }
            Event::GroupMerge(_prefix) => {
                self.on_group_merge()
            }
            Event::Connected | Event::Tick => Ok(()),
        } {
            debug!("Failed to handle event: {:?}", error);
        }

        self.data_manager.check_timeouts();
        ret
    }

    fn on_request(&mut self,
                  request: Request,
                  src: Authority,
                  dst: Authority)
                  -> Result<(), InternalError> {
        match (src, dst, request) {
            // ================== Get ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Get(data_id, msg_id)) |
            (src @ Authority::ManagedNode(_),
             dst @ Authority::ManagedNode(_),
             Request::Get(data_id, msg_id)) => {
                self.data_manager.handle_get(src, dst, data_id, msg_id)
            }
            // ================== Put ==================
            (src @ Authority::Client { .. },
             dst @ Authority::ClientManager(_),
             Request::Put(data, msg_id)) => self.maid_manager.handle_put(src, dst, data, msg_id),
            (src @ Authority::ClientManager(_),
             dst @ Authority::NaeManager(_),
             Request::Put(data, msg_id)) => self.data_manager.handle_put(src, dst, data, msg_id),
            // ================== Post ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Post(data, msg_id)) => self.data_manager.handle_post(src, dst, data, msg_id),
            // ================== Delete ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Delete(Data::Structured(data), msg_id)) => {
                self.data_manager.handle_delete(src, dst, data, msg_id)
            }
            // ================== Append ==================
            (src @ Authority::Client { .. },
             dst @ Authority::NaeManager(_),
             Request::Append(wrapper, msg_id)) => {
                self.data_manager.handle_append(src, dst, wrapper, msg_id)
            }
            // ================== GetAccountInfo ==================
            (src @ Authority::Client { .. },
             dst @ Authority::ClientManager(_),
             Request::GetAccountInfo(msg_id)) => {
                self.maid_manager.handle_get_account_info(src, dst, msg_id)
            }
            // ================== Refresh ==================
            (Authority::ClientManager(_),
             Authority::ClientManager(_),
             Request::Refresh(serialised_msg, _)) => {
                self.maid_manager.handle_refresh(&serialised_msg)
            }
            (Authority::ManagedNode(src_name),
             Authority::ManagedNode(_),
             Request::Refresh(serialised_msg, _)) |
            (Authority::ManagedNode(src_name),
             Authority::NaeManager(_),
             Request::Refresh(serialised_msg, _)) => {
                self.data_manager.handle_refresh(src_name, &serialised_msg)
            }
            (Authority::NaeManager(_),
             Authority::NaeManager(_),
             Request::Refresh(serialised_msg, _)) => {
                self.data_manager.handle_group_refresh(&serialised_msg)
            }
            // ================== Invalid Request ==================
            (_, _, request) => Err(InternalError::UnknownRequestType(request)),
        }
    }

    fn on_response(&mut self,
                   response: Response,
                   src: Authority,
                   dst: Authority)
                   -> Result<(), InternalError> {
        match (src, dst, response) {
            // ================== GetSuccess ==================
            (Authority::ManagedNode(src_name),
             Authority::ManagedNode(_),
             Response::GetSuccess(data, _)) => self.data_manager.handle_get_success(src_name, data),
            // ================== GetFailure ==================
            (Authority::ManagedNode(src_name),
             Authority::ManagedNode(_),
             Response::GetFailure { data_id, .. }) => {
                self.data_manager.handle_get_failure(src_name, data_id)
            }
            // ================== PutSuccess ==================
            (Authority::NaeManager(_),
             Authority::ClientManager(_),
             Response::PutSuccess(data_id, msg_id)) => {
                self.maid_manager.handle_put_success(data_id, msg_id)
            }
            // ================== PutFailure ==================
            (Authority::NaeManager(_),
             Authority::ClientManager(_),
             Response::PutFailure { id, external_error_indicator, data_id }) => {
                self.maid_manager.handle_put_failure(id, data_id, &external_error_indicator)
            }
            // ================== Invalid Response ==================
            (_, _, response) => Err(InternalError::UnknownResponseType(response)),
        }
    }

    fn on_node_added(&mut self, node_added: XorName) -> Result<(), InternalError> {
        self.maid_manager.handle_node_added(&node_added);
        self.data_manager.handle_node_added(&node_added);
        Ok(())
    }

    fn on_node_lost(&mut self, node_lost: XorName) -> Result<(), InternalError> {
        self.data_manager.handle_node_lost(&node_lost);
        Ok(())
    }

    fn on_group_split(&mut self, prefix: Prefix<XorName>) -> Result<(), InternalError> {
        self.maid_manager.handle_group_split(&prefix);
        self.data_manager.handle_group_split(&prefix);
        Ok(())
    }

    fn on_group_merge(&mut self) -> Result<(), InternalError> {
        self.maid_manager.handle_group_merge();
        self.data_manager.handle_group_merge();
        Ok(())
    }
}
