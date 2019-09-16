// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crossbeam_channel::TryRecvError;
use std::collections::VecDeque;

/// Interface for sending and receiving messages to and from other nodes, in the role of a full routing node.
pub struct Node {
    events: VecDeque<Vec<u8>>,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {}
    }

    /// Vote for an event.
    pub fn vote_for(&mut self, event: Vec<u8>) {
        self.events.push_back(event);
    }

    /// Try to read the next available event from the stream without blocking.
    ///
    /// Implementations should return an error if there are no items available, OR
    /// a real error occurs.
    pub fn try_next_ev(&mut self) -> Result<Event, TryRecvError> {
        if let Some(event) = self.events.pop_front() {
            Ok(Event::Consensus(event))
        } else {
            Err(TryRecvError::Empty)
        }
    }
}

/// A builder to configure and create a new `Node`.
pub struct NodeBuilder {}

impl NodeBuilder {
    /// Creates new `Node`.
    pub fn create(self) -> Result<Node, RoutingError> {
        Ok(Node {
            events: VecDeque::with_capacity(128),
        })
    }
}

/// Routing event.
pub enum Event {
    /// Event from PARSEC.
    Consensus(Vec<u8>),
}

/// The type of errors that can occur during handling of routing events.
#[derive(Debug)]
pub enum RoutingError {}
