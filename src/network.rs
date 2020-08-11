// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{Error, Result};
use bytes::Bytes;
use crossbeam_channel::RecvError;
use routing::{
    DstLocation, Node as RoutingLayer, P2pNode, PublicId, RoutingError, SectionProofChain,
    SrcLocation,
};
use std::{cell::RefCell, net::SocketAddr, rc::Rc};
use xor_name::{Prefix, XorName};

///
#[derive(Clone)]
pub struct Network {
    routing: Rc<RefCell<RoutingLayer>>,
}

impl Network {
    ///
    pub fn new(routing: Rc<RefCell<RoutingLayer>>) -> Self {
        Self { routing }
    }
}

impl Routing for Network {
    fn handle_selected_operation(&mut self, op_index: usize) -> Result<(), RecvError> {
        self.routing
            .borrow_mut()
            .handle_selected_operation(op_index)
    }

    fn is_running(&self) -> bool {
        self.routing.borrow().is_running()
    }

    fn id(&self) -> PublicId {
        *self.routing.borrow().id()
    }

    fn name(&self) -> XorName {
        *self.routing.borrow().name()
    }

    fn our_connection_info(&mut self) -> Result<SocketAddr> {
        self.routing
            .borrow_mut()
            .our_connection_info()
            .map_err(|e| Error::Routing(e))
    }

    fn our_prefix(&self) -> Option<Prefix> {
        self.routing.borrow().our_prefix().map(|c| *c)
    }

    fn matches_our_prefix(&self, name: &XorName) -> Result<bool> {
        self.routing
            .borrow()
            .matches_our_prefix(name)
            .map_err(|e| Error::Routing(e))
    }

    fn is_elder(&self) -> bool {
        self.routing.borrow().is_elder()
    }

    fn our_elders(&self) -> Vec<P2pNode> {
        self.routing
            .borrow()
            .our_elders()
            .into_iter()
            .cloned()
            .collect()
    }

    fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode> {
        let routing = self.routing.borrow();
        routing
            .our_elders_sorted_by_distance_to(name)
            .into_iter()
            .cloned()
            .collect()
    }

    fn our_adults(&self) -> Vec<P2pNode> {
        self.routing
            .borrow()
            .our_adults()
            .into_iter()
            .cloned()
            .collect()
    }

    fn our_adults_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode> {
        self.routing
            .borrow()
            .our_adults_sorted_by_distance_to(name)
            .into_iter()
            .cloned()
            .collect()
    }

    fn in_dst_location(&self, dst: &DstLocation) -> bool {
        self.routing.borrow().in_dst_location(dst)
    }

    fn vote_for_user_event(&mut self, event: Vec<u8>) -> Result<()> {
        self.routing
            .borrow_mut()
            .vote_for_user_event(event)
            .map_err(|e| Error::Routing(e))
    }

    fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Vec<u8>,
    ) -> Result<(), RoutingError> {
        self.routing.borrow_mut().send_message(src, dst, content)
    }

    fn send_message_to_client(&mut self, peer_addr: SocketAddr, msg: Bytes) -> Result<()> {
        self.routing
            .borrow_mut()
            .send_message_to_client(peer_addr, msg, 0)
            .map_err(|e| Error::Routing(e))
    }

    fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<()> {
        self.routing
            .borrow_mut()
            .disconnect_from_client(peer_addr)
            .map_err(|e| Error::Routing(e))
    }

    fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.routing
            .borrow()
            .public_key_set()
            .map_err(|e| Error::Routing(e))
            .map(|c| c.clone())
    }

    fn secret_key_share(&self) -> Result<bls::SecretKeyShare> {
        self.routing
            .borrow()
            .secret_key_share()
            .map_err(|e| Error::Routing(e))
            .map(|c| c.clone())
    }

    fn our_history(&self) -> Option<SectionProofChain> {
        self.routing.borrow().our_history().map(|c| c.clone())
    }

    fn our_index(&self) -> Result<usize> {
        self.routing
            .borrow()
            .our_index()
            .map_err(|e| Error::Routing(e))
    }
}

///
pub trait Routing {
    /// Processes events received externally from one of the channels.
    /// For this function to work properly, the node event channels need to
    /// be registered by calling [`ApprovedPeer::register`](#method.register).
    /// [`Select::ready`] needs to be called to get `op_index`, the event channel index.
    ///
    /// This function is non-blocking.
    ///
    /// Errors are permanent failures due to either: node termination, the permanent closing of one
    /// of the event channels, or an invalid (unknown) channel index.
    ///
    /// [`Select::ready`]: https://docs.rs/crossbeam-channel/0.3/crossbeam_channel/struct.Select.html#method.ready
    fn handle_selected_operation(&mut self, op_index: usize) -> Result<(), RecvError>;

    /// Returns whether this node is running or has been terminated.
    fn is_running(&self) -> bool;

    /// Returns the `PublicId` of this node.
    fn id(&self) -> PublicId;

    /// The name of this node.
    fn name(&self) -> XorName;

    /// Returns connection info of this node.
    fn our_connection_info(&mut self) -> Result<SocketAddr>;

    /// Our `Prefix` once we are a part of the section.
    fn our_prefix(&self) -> Option<Prefix>;

    /// Finds out if the given XorName matches our prefix. Returns error if we don't have a prefix
    /// because we haven't joined any section yet.
    fn matches_our_prefix(&self, name: &XorName) -> Result<bool>;

    /// Returns whether the node is Elder.
    fn is_elder(&self) -> bool;

    /// Returns the information of all the current section elders.
    fn our_elders(&self) -> Vec<P2pNode>;

    /// Returns the elders of our section sorted by their distance to `name` (closest first).
    fn our_elders_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode>;

    /// Returns the information of all the current section adults.
    fn our_adults(&self) -> Vec<P2pNode>;

    /// Returns the adults of our section sorted by their distance to `name` (closest first).
    /// If we are not elder or if there are no adults in the section, returns empty vec.
    fn our_adults_sorted_by_distance_to(&self, name: &XorName) -> Vec<P2pNode>;

    /// Checks whether the given location represents self.
    fn in_dst_location(&self, dst: &DstLocation) -> bool;

    /// Vote for a user-defined event.
    /// Returns `InvalidState` error if we are not an elder.
    fn vote_for_user_event(&mut self, event: Vec<u8>) -> Result<()>;

    /// Send a message.
    fn send_message(
        &mut self,
        src: SrcLocation,
        dst: DstLocation,
        content: Vec<u8>,
    ) -> Result<(), RoutingError>;

    /// Send a message to a client peer.
    fn send_message_to_client(&mut self, peer_addr: SocketAddr, msg: Bytes) -> Result<()>;

    /// Disconnect form a client peer.
    fn disconnect_from_client(&mut self, peer_addr: SocketAddr) -> Result<()>;

    /// Returns the current BLS public key set or `RoutingError::InvalidState` if we are not joined
    /// yet.
    fn public_key_set(&self) -> Result<bls::PublicKeySet>;

    /// Returns the current BLS secret key share or `RoutingError::InvalidState` if we are not
    /// elder.
    fn secret_key_share(&self) -> Result<bls::SecretKeyShare>;

    /// Returns our section proof chain, or `None` if we are not joined yet.
    fn our_history(&self) -> Option<SectionProofChain>;

    /// Returns our index in the current BLS group or `RoutingError::InvalidState` if section key was
    /// not generated yet.
    fn our_index(&self) -> Result<usize>;
}
