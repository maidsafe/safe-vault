// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crossbeam_channel::TryRecvError;
use std::cell::RefCell;
use std::collections::{btree_set::BTreeSet, VecDeque};
use std::rc::{Rc, Weak};

/// Default events `VecDeque` pre-allocated capacity
const DEFAULT_EVENTS_CAP: usize = 64;

/// Consensus group reference
pub type ConsensusGroupRef = Rc<RefCell<ConsensusGroup>>;
type EventsRef = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Consensus
pub struct ConsensusGroup {
    event_buckets: Vec<EventsRef>,
    // A list to maintain already consensused event from
    // entering the consensus queue again
    processed_events: BTreeSet<Vec<u8>>,
}

impl ConsensusGroup {
    /// Creates a new consensus group.
    pub fn new() -> ConsensusGroupRef {
        Rc::new(RefCell::new(Self {
            event_buckets: Vec::new(),
            processed_events: BTreeSet::new(),
        }))
    }

    fn vote_for(&mut self, event: Vec<u8>) {
        // If the event is already consensused, we don't have to insert it again
        if !self.processed_events.contains(event.as_slice()) {
            for bucket in &self.event_buckets {
                let mut events = bucket.borrow_mut();
                events.push_back(event.clone());
            }
            // Push the event into the processed list.
            let _ = self.processed_events.insert(event.clone());
        }
    }
}

/// Interface for sending and receiving messages to and from other nodes, in the role of a full routing node.
pub struct Node {
    events: EventsRef,
    consensus_group: Option<Weak<RefCell<ConsensusGroup>>>,
}

impl Node {
    /// Creates a new builder to configure and create a `Node`.
    pub fn builder() -> NodeBuilder {
        NodeBuilder {}
    }

    /// Vote for an event.
    pub fn vote_for(&mut self, event: Vec<u8>) {
        if let Some(ref consensus_group) = self.consensus_group {
            let _ = consensus_group
                .upgrade()
                .map(|group| group.borrow_mut().vote_for(event));
        } else {
            self.events.borrow_mut().push_back(event);
        }
    }

    /// Try to read the next available event from the stream without blocking.
    ///
    /// Implementations should return an error if there are no items available, OR
    /// a real error occurs.
    pub fn try_next_ev(&mut self) -> Result<Event, TryRecvError> {
        if let Some(event) = self.events.borrow_mut().pop_front() {
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
            events: Rc::new(RefCell::new(VecDeque::with_capacity(DEFAULT_EVENTS_CAP))),
            consensus_group: None,
        })
    }

    /// Creates new `Node` within a section of nodes.
    pub fn create_within_group(
        self,
        consensus_group: ConsensusGroupRef,
    ) -> Result<Node, RoutingError> {
        let events = Rc::new(RefCell::new(VecDeque::with_capacity(DEFAULT_EVENTS_CAP)));

        consensus_group
            .borrow_mut()
            .event_buckets
            .push(events.clone());

        Ok(Node {
            events,
            consensus_group: Some(Rc::downgrade(&consensus_group)),
        })
    }
}

/// Routing event.
#[derive(Debug)]
pub enum Event {
    /// Event from PARSEC.
    Consensus(Vec<u8>),
}

/// The type of errors that can occur during handling of routing events.
#[derive(Debug)]
pub enum RoutingError {}
