// Copyright 2017 MaidSafe.net limited.
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

use super::STATUS_LOG_INTERVAL;
use super::data::{DataId, ImmutableDataId, MutableDataId};
use super::mutation::{self, Mutation};
use GROUP_SIZE;
use QUORUM;
use maidsafe_utilities::serialisation::serialised_size;
use routing::{Authority, MAX_MUTABLE_DATA_ENTRIES, MAX_MUTABLE_DATA_SIZE_IN_BYTES, MessageId,
              MutableData, RoutingTable, Value, XorName};
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::iter;
use std::time::Duration;
use utils::{self, HashMap, HashSet, Instant, SecureHash};

#[cfg(not(feature = "use-mock-crust"))]
/// The timeout for cached data from requests; if no consensus is reached, the data is dropped.
const PENDING_WRITE_TIMEOUT_SECS: u64 = 60;
#[cfg(feature = "use-mock-crust")]
/// The timeout for cached data from requests; if no consensus is reached, the data is dropped.
pub const PENDING_WRITE_TIMEOUT_SECS: u64 = 60;
/// The timeout for retrieving mutable data chunks.
const MUTABLE_CHUNK_REQUEST_TIMEOUT_SECS: u64 = 60;
/// The timeout for retrieving data fragments from individual peers.
const FRAGMENT_REQUEST_TIMEOUT_SECS: u64 = 60;

pub struct Cache {
    /// Immutable data chunks we are no longer responsible for. These can be deleted
    /// from the chunk store.
    unneeded_immutable_chunks: UnneededChunks,

    /// Maps data fragment holders to the list of data fragments we need from them.
    /// Also tracks any ongoing requests to retrieve those fragments.
    fragment_holders: HashMap<XorName, FragmentHolder>,
    /// Maps fragments to the list of holders that have it and tracks whether there
    /// is an ongoing request to retrieve it.
    fragment_index: FragmentIndex,

    /// Mutable data chunks we need, but have not requested yet.
    needed_mutable_chunks: HashSet<MutableDataId>,
    /// Mutable data chunk we are currently requesting (if any). Tracks the number of nodes
    /// we already received response from.
    needed_mutable_chunk_request: Option<ChunkRequest>,

    /// Maps data identifiers to the list of pending writes that affect that chunk.
    pending_writes: HashMap<DataId, Vec<PendingWrite>>,

    total_needed_fragments_count: usize,
    requested_needed_fragments_count: usize,
    logging_time: Instant,
}

impl Cache {
    // Returns IDs of all chunks we need.
    pub fn needed_chunks(&self) -> HashSet<DataId> {
        self.fragment_index
            .keys()
            .filter(|fragment| if let FragmentInfo::ImmutableData(ref name) =
                **fragment
            {
                !self.unneeded_immutable_chunks.contains(name)
            } else {
                true
            })
            .map(FragmentInfo::data_id)
            .chain(self.needed_mutable_chunks.iter().map(
                |id| DataId::Mutable(*id),
            ))
            .chain(self.needed_mutable_chunk_request.iter().map(|request| {
                DataId::Mutable(request.data_id)
            }))
            .collect()
    }

    /// Returns the next mutable data chunk we need (if any)
    pub fn needed_mutable_chunk(&mut self) -> Option<MutableDataId> {
        self.stop_expired_needed_mutable_chunk_request();

        if self.needed_mutable_chunk_request.is_some() {
            return None;
        }

        self.needed_mutable_chunks.iter().cloned().next()
    }

    /// Insert needed mutable data chunk.
    pub fn insert_needed_mutable_chunk(&mut self, data_id: MutableDataId) {
        if let Some(request) = self.needed_mutable_chunk_request.as_ref() {
            if request.data_id == data_id {
                return;
            }
        }

        let _ = self.needed_mutable_chunks.insert(data_id);
    }

    /// Mark the request to retrieve the given chunk as started.
    pub fn start_needed_mutable_chunk_request(
        &mut self,
        data_id: MutableDataId,
        msg_id: MessageId,
    ) {
        let _ = self.needed_mutable_chunks.remove(&data_id);
        self.needed_mutable_chunk_request = Some(ChunkRequest::new(data_id, msg_id));
    }

    /// Register successful response to a needed mutable chunk request. If we receive
    /// responses from at least `QUORUM` nodes, the request is considered to be successfully
    /// finished.
    pub fn handle_needed_mutable_chunk_success(
        &mut self,
        data_id: MutableDataId,
        src: XorName,
        msg_id: MessageId,
    ) {
        let done = self.needed_mutable_chunk_request.as_mut().map_or(
            false,
            |request| if request.data_id == data_id &&
                request.msg_id ==
                    msg_id
            {
                let _ = request.successes.insert(src);
                request.did_accumulate()
            } else {
                false
            },
        );

        if done {
            self.needed_mutable_chunk_request = None;
        }
    }

    pub fn handle_needed_mutable_chunk_failure(&mut self, src: XorName, msg_id: MessageId) {
        let done = self.needed_mutable_chunk_request.as_mut().map_or(
            false,
            |request| if request.msg_id ==
                msg_id
            {
                let _ = request.failures.insert(src);
                !request.can_accumulate()
            } else {
                false
            },
        );

        if done {
            self.needed_mutable_chunk_request = None;
        }
    }

    /// Returns data fragments we need and want to request from other nodes.
    pub fn needed_fragments(&mut self) -> Vec<(FragmentInfo, Vec<XorName>)> {
        self.stop_expired_fragment_requests();

        let mut result = HashMap::default();

        for (holder_name, holder) in &self.fragment_holders {
            if holder.is_requested() {
                continue;
            }

            for fragment in &holder.fragments {
                if let FragmentInfo::ImmutableData(ref name) = *fragment {
                    if self.unneeded_immutable_chunks.contains(name) {
                        continue;
                    }
                }

                if self.fragment_index.get(fragment).map_or(
                    false,
                    FragmentState::is_requested,
                )
                {
                    continue;
                }

                result
                    .entry(fragment.clone())
                    .or_insert_with(Vec::new)
                    .push(*holder_name);
            }
        }

        result.into_iter().collect()
    }

    /// Insert new needed fragment and register it with the given holder.
    pub fn insert_needed_fragment(&mut self, fragment: FragmentInfo, holder: XorName) {
        if self.fragment_holders
            .entry(holder)
            .or_insert_with(FragmentHolder::new)
            .fragments
            .insert(fragment.clone())
        {
            index_needed_fragment(&mut self.fragment_index, fragment, holder);
        }
    }

    /// Register the given fragment with the new holder, but only if we already
    /// have it registered with some other holder(s).
    pub fn register_needed_fragment_with_another_holder(
        &mut self,
        fragment: FragmentInfo,
        holder: XorName,
    ) -> bool {
        if let Some(state) = self.fragment_index.get_mut(&fragment) {
            if self.fragment_holders
                .entry(holder)
                .or_insert_with(FragmentHolder::new)
                .fragments
                .insert(fragment)
            {
                let _ = state.holders.insert(holder);
                return true;
            }
        }

        false
    }

    /// Register all existing needed fragments belonging to the given data with the new holder.
    pub fn register_needed_data_with_another_holder(&mut self, data_id: &DataId, holder: XorName) {
        let fragments: Vec<_> = self.fragment_index
            .keys()
            .filter_map(|fragment| if fragment.data_id() == *data_id {
                Some(fragment.clone())
            } else {
                None
            })
            .collect();

        if fragments.is_empty() {
            return;
        }

        let mut holder = self.fragment_holders.entry(holder).or_insert_with(
            FragmentHolder::new,
        );

        for fragment in fragments {
            let _ = holder.fragments.insert(fragment);
        }
    }

    pub fn start_needed_fragment_request(&mut self, fragment: &FragmentInfo, holder: &XorName) {
        if let Some(holder) = self.fragment_holders.get_mut(holder) {
            holder.start_request(fragment.clone());

            if let Some(state) = self.fragment_index.get_mut(fragment) {
                state.start_request();
            }
        }
    }

    pub fn stop_needed_fragment_request(&mut self, holder_name: &XorName) -> Option<FragmentInfo> {
        let mut result = None;
        let mut remove = false;

        if let Some(holder) = self.fragment_holders.get_mut(holder_name) {
            if let Some(fragment) = holder.stop_request() {
                let remove_index = self.fragment_index.get_mut(&fragment).map_or(
                    false,
                    |state| {
                        state.stop_request();
                        let _ = state.holders.remove(holder_name);
                        state.holders.is_empty()
                    },
                );

                if remove_index {
                    let _ = self.fragment_index.remove(&fragment);
                }

                result = Some(fragment);
                remove = holder.fragments.is_empty();
            }
        }

        if remove {
            let _ = self.fragment_holders.remove(holder_name);
        }

        result
    }

    /// Removes needed fragments that are no longer valid due to churn.
    /// Returns whether any of the pruned fragments had a request ongoing.
    pub fn prune_needed_fragments(&mut self, routing_table: &RoutingTable<XorName>) -> bool {
        let mut lost_holders = Vec::new();
        let mut result = false;

        for (holder_name, holder) in &mut self.fragment_holders {
            let (lost, retained) = holder.fragments.drain().partition(|fragment| {
                routing_table
                    .other_closest_names(fragment.name(), GROUP_SIZE)
                    .map_or(true, |group| !group.contains(&holder_name))
            });

            holder.fragments = retained;

            for fragment in &lost {
                if holder.stop_request_for(fragment) {
                    result = true;
                    break;
                }
            }

            for fragment in &lost {
                unindex_needed_fragment(&mut self.fragment_index, fragment, holder_name);
            }

            if holder.fragments.is_empty() {
                lost_holders.push(*holder_name);
            }
        }

        for holder in &lost_holders {
            let _ = self.fragment_holders.remove(holder);
        }

        result
    }

    // Removes the given fragment.
    pub fn remove_needed_fragment(&mut self, fragment: &FragmentInfo) {
        if let Some(state) = self.fragment_index.remove(fragment) {
            let mut empty_holders = Vec::new();

            for holder_name in state.holders {
                if let Some(holder) = self.fragment_holders.get_mut(&holder_name) {
                    holder.remove_fragment(fragment);
                    if holder.fragments.is_empty() {
                        empty_holders.push(holder_name);
                    }
                }
            }

            for holder_name in empty_holders {
                let _ = self.fragment_holders.remove(&holder_name);
            }
        }
    }

    pub fn is_in_unneeded(&self, data_id: &ImmutableDataId) -> bool {
        self.unneeded_immutable_chunks.contains(data_id.name())
    }

    pub fn add_as_unneeded(&mut self, data_id: ImmutableDataId) {
        self.unneeded_immutable_chunks.push(*data_id.name());
    }

    pub fn prune_unneeded_chunks(&mut self, routing_table: &RoutingTable<XorName>) -> u64 {
        let before = self.unneeded_immutable_chunks.len();

        self.unneeded_immutable_chunks.retain(|name| {
            !routing_table.is_closest(name, GROUP_SIZE)
        });

        (before - self.unneeded_immutable_chunks.len()) as u64
    }

    /// Inserts the given mutation as a pending write. If the mutation doesn't
    /// conflict with any existing pending mutations and is accepted (`rejected`
    /// is false), returns `MutationVote` to send to the other member of the group.
    /// Otherwise, returns `None`.
    pub fn insert_pending_write(
        &mut self,
        mutation: Mutation,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        msg_id: MessageId,
        rejected: bool,
    ) -> Option<MutationVote> {
        let hash = utils::secure_hash(&mutation);
        let data_id = mutation.data_id();

        self.pending_writes
            .entry(data_id)
            .or_insert_with(Vec::new)
            .push(PendingWrite {
                hash: hash,
                mutation: mutation,
                timestamp: Instant::now(),
                src: src,
                dst: dst,
                message_id: msg_id,
                rejected: rejected,
            });

        if rejected {
            None
        } else {
            Some(MutationVote {
                data_id: data_id,
                hash: hash,
            })
        }
    }

    /// Removes and returns the pending write for the specified data identifier
    /// and having the specified hash.
    pub fn take_pending_write(
        &mut self,
        data_id: &DataId,
        hash: &SecureHash,
    ) -> Option<PendingWrite> {
        // If there is more than one matching pending write, remove all of them,
        // but return only the non-rejected one.
        if let Entry::Occupied(mut entry) = self.pending_writes.entry(*data_id) {
            let mut accepted = Vec::new();
            let mut rejected = Vec::new();

            while let Some(index) = entry.get().iter().position(|write| write.hash == *hash) {
                let write = entry.get_mut().remove(index);
                if write.rejected {
                    rejected.push(write)
                } else {
                    accepted.push(write)
                }
            }

            if entry.get().is_empty() {
                let _ = entry.remove();
            }

            accepted.into_iter().next().or_else(
                || rejected.into_iter().next(),
            )
        } else {
            None
        }
    }

    /// Removes and returns all timed out pending writes.
    pub fn remove_expired_pending_writes(&mut self) -> Vec<PendingWrite> {
        let timeout = Duration::from_secs(PENDING_WRITE_TIMEOUT_SECS);
        let expired_writes: Vec<_> = self.pending_writes
            .iter_mut()
            .flat_map(|(_, writes)| {
                writes
                    .iter()
                    .position(|write| write.timestamp.elapsed() > timeout)
                    .map_or_else(Vec::new, |index| writes.split_off(index))
                    .into_iter()
            })
            .collect();

        let expired_keys: Vec<_> = self.pending_writes
            .iter_mut()
            .filter(|entry| entry.1.is_empty())
            .map(|(data_id, _)| *data_id)
            .collect();

        for data_id in expired_keys {
            let _ = self.pending_writes.remove(&data_id);
        }

        expired_writes
    }

    pub fn pop_unneeded_chunk(&mut self) -> Option<ImmutableDataId> {
        self.unneeded_immutable_chunks.pop().map(ImmutableDataId)
    }

    /// Validate that the new mutation can be applied to the given data together with
    /// all the pending mutations for that data.
    pub fn validate_concurrent_mutations(
        &self,
        existing_data: Option<&MutableData>,
        new_mutation: &Mutation,
    ) -> bool {
        let writes = if let Some(writes) = self.pending_writes.get(&new_mutation.data_id()) {
            writes
        } else {
            // Always accept if there are no other pending mutations.
            return true;
        };

        for write in writes {
            if !write.rejected && write.mutation.conflicts_with(new_mutation) {
                return false;
            }
        }

        let data = if let Some(data) = existing_data {
            data
        } else {
            return true;
        };

        // Allow the new mutation only if together with all the existing pending mutations
        // it increases the entry count and size by at most half the remaining allowance.
        // Only consider mutations that increase (as opposed to decrease) entry count
        // and/or size.

        let mutations = || {
            writes
                .iter()
                .filter(|w| !w.rejected)
                .map(|w| &w.mutation)
                .chain(iter::once(new_mutation))
        };

        let size_before = serialised_size(data);
        let size_after = mutation::compute_size_after_increase(data, mutations());

        if !check_limit(size_before, size_after, MAX_MUTABLE_DATA_SIZE_IN_BYTES) {
            return false;
        }

        let count_before = data.entries().len() as u64;
        let count_after = mutation::compute_entry_count_after_increase(data, mutations());

        if !check_limit(count_before, count_after, MAX_MUTABLE_DATA_ENTRIES) {
            return false;
        }

        true
    }

    pub fn print_stats(&mut self) {
        if self.logging_time.elapsed().as_secs() < STATUS_LOG_INTERVAL {
            return;
        }
        self.logging_time = Instant::now();

        let new_total = self.fragment_index.len();
        let new_requested = self.fragment_holders
            .iter()
            .filter(|&(_, holder)| holder.is_requested())
            .count();

        if new_total != self.total_needed_fragments_count ||
            new_requested != self.requested_needed_fragments_count
        {
            self.total_needed_fragments_count = new_total;
            self.requested_needed_fragments_count = new_requested;

            info!(
                "Cache Stats: {} requested / {} total needed fragments.",
                new_requested,
                new_total
            );
        }
    }

    fn stop_expired_needed_mutable_chunk_request(&mut self) {
        if self.needed_mutable_chunk_request.as_ref().map_or(
            false,
            ChunkRequest::is_expired,
        )
        {
            self.needed_mutable_chunk_request = None;
        }
    }

    fn stop_expired_fragment_requests(&mut self) {
        let mut empty_holders = Vec::new();

        for (holder_name, holder) in &mut self.fragment_holders {
            if let Some(fragment) = holder.stop_request_if_expired() {
                if holder.fragments.is_empty() {
                    empty_holders.push(*holder_name);
                }

                unindex_needed_fragment(&mut self.fragment_index, &fragment, holder_name);
            }
        }

        for holder in empty_holders {
            let _ = self.fragment_holders.remove(&holder);
        }
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
impl Cache {
    /// Clear the cache.
    pub fn clear(&mut self) {
        self.unneeded_immutable_chunks.clear();
        self.fragment_holders.clear();
        self.fragment_index.clear();
        self.needed_mutable_chunks.clear();
        self.needed_mutable_chunk_request = None;
        self.pending_writes.clear();
        self.total_needed_fragments_count = 0;
        self.requested_needed_fragments_count = 0;
    }
}

impl Default for Cache {
    fn default() -> Cache {
        Cache {
            unneeded_immutable_chunks: UnneededChunks::new(),
            fragment_holders: HashMap::default(),
            fragment_index: HashMap::default(),
            needed_mutable_chunks: HashSet::default(),
            needed_mutable_chunk_request: None,
            pending_writes: HashMap::default(),
            logging_time: Instant::now(),
            total_needed_fragments_count: 0,
            requested_needed_fragments_count: 0,
        }
    }
}


// A pending write to the chunk store. This is cached in memory until the group either reaches
// consensus and stores the chunk, or it times out and is dropped.
pub struct PendingWrite {
    pub mutation: Mutation,
    pub hash: SecureHash,
    timestamp: Instant,
    pub src: Authority<XorName>,
    pub dst: Authority<XorName>,
    pub message_id: MessageId,
    pub rejected: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct MutationVote {
    pub data_id: DataId,
    pub hash: SecureHash,
}

/// Information about a data fragment:
/// - immutable data,
/// - mutable data shell or,
/// - mutable data entry.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum FragmentInfo {
    ImmutableData(XorName),
    MutableDataShell {
        name: XorName,
        tag: u64,
        version: u64,
        hash: SecureHash,
    },
    MutableDataEntry {
        name: XorName,
        tag: u64,
        key: Vec<u8>,
        version: u64,
        hash: SecureHash,
    },
}

impl FragmentInfo {
    /// Create `FragmentInfo` for the shell of the given mutable data.
    pub fn mutable_data_shell(data: &MutableData) -> Self {
        let hash = utils::mdata_shell_hash(data);

        FragmentInfo::MutableDataShell {
            name: *data.name(),
            tag: data.tag(),
            version: data.version(),
            hash: hash,
        }
    }

    /// Create `FragmentInfo` for the given mutable data entry.
    pub fn mutable_data_entry(data: &MutableData, key: Vec<u8>, value: &Value) -> Self {
        let hash = utils::mdata_value_hash(value);

        FragmentInfo::MutableDataEntry {
            name: *data.name(),
            tag: data.tag(),
            key: key,
            version: value.entry_version,
            hash: hash,
        }
    }

    // Get all fragments for the given mutable data.
    pub fn mutable_data(data: &MutableData) -> Vec<Self> {
        let mut result = Vec::with_capacity(1 + data.entries().len());

        result.push(Self::mutable_data_shell(data));

        for (key, value) in data.entries() {
            result.push(Self::mutable_data_entry(data, key.clone(), value));
        }

        result
    }

    pub fn name(&self) -> &XorName {
        match *self {
            FragmentInfo::ImmutableData(ref name) |
            FragmentInfo::MutableDataShell { ref name, .. } |
            FragmentInfo::MutableDataEntry { ref name, .. } => name,
        }
    }

    pub fn data_id(&self) -> DataId {
        match *self {
            FragmentInfo::ImmutableData(name) => DataId::Immutable(ImmutableDataId(name)),
            FragmentInfo::MutableDataShell { name, tag, .. } |
            FragmentInfo::MutableDataEntry { name, tag, .. } => {
                DataId::Mutable(MutableDataId(name, tag))
            }
        }
    }
}

struct FragmentHolder {
    request: Option<FragmentRequest>,
    fragments: HashSet<FragmentInfo>,
}

impl FragmentHolder {
    fn new() -> Self {
        FragmentHolder {
            request: None,
            fragments: HashSet::default(),
        }
    }

    fn is_requested(&self) -> bool {
        self.request.is_some()
    }

    fn start_request(&mut self, fragment: FragmentInfo) {
        self.request = Some(FragmentRequest::new(fragment));
    }

    fn stop_request(&mut self) -> Option<FragmentInfo> {
        self.request.take().map(|request| {
            let _ = self.fragments.remove(&request.fragment);
            request.fragment
        })
    }

    // If there is an ongoing request for the given fragment, stops it and returns true,
    // otherwise does nothing and returns false.
    fn stop_request_for(&mut self, fragment: &FragmentInfo) -> bool {
        let checker = |request: &FragmentRequest| request.fragment == *fragment;
        if self.request.as_ref().map_or(false, checker) {
            let _ = self.fragments.remove(fragment);
            self.request = None;
            true
        } else {
            false
        }
    }

    // If the ongoing request expired, stops it and returns the requested fragment.
    fn stop_request_if_expired(&mut self) -> Option<FragmentInfo> {
        let request = if self.request.as_ref().map_or(
            false,
            FragmentRequest::is_expired,
        )
        {
            self.request.take()
        } else {
            None
        };

        request.map(|request| {
            let _ = self.fragments.remove(&request.fragment);
            request.fragment
        })
    }

    fn remove_fragment(&mut self, fragment: &FragmentInfo) {
        if !self.stop_request_for(fragment) {
            let _ = self.fragments.remove(fragment);
        }
    }
}

struct FragmentRequest {
    fragment: FragmentInfo,
    timestamp: Instant,
}

impl FragmentRequest {
    fn new(fragment: FragmentInfo) -> Self {
        FragmentRequest {
            fragment: fragment,
            timestamp: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.timestamp.elapsed().as_secs() > FRAGMENT_REQUEST_TIMEOUT_SECS
    }
}

struct FragmentState {
    holders: HashSet<XorName>,
    request_count: usize,
}

impl FragmentState {
    fn new() -> Self {
        FragmentState {
            holders: HashSet::default(),
            request_count: 0,
        }
    }

    fn is_requested(&self) -> bool {
        self.request_count > 0
    }

    fn start_request(&mut self) {
        self.request_count = self.request_count.saturating_add(1)
    }

    fn stop_request(&mut self) {
        self.request_count = self.request_count.saturating_sub(1)
    }
}

struct ChunkRequest {
    data_id: MutableDataId,
    msg_id: MessageId,
    successes: HashSet<XorName>,
    failures: HashSet<XorName>,
    timestamp: Instant,
}

impl ChunkRequest {
    fn new(data_id: MutableDataId, msg_id: MessageId) -> Self {
        ChunkRequest {
            data_id: data_id,
            msg_id: msg_id,
            successes: HashSet::default(),
            failures: HashSet::default(),
            timestamp: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.timestamp.elapsed().as_secs() > MUTABLE_CHUNK_REQUEST_TIMEOUT_SECS
    }

    fn can_accumulate(&self) -> bool {
        // `GROUP_SIZE - 1` means everyone in the group except us.
        GROUP_SIZE - 1 - self.failures.len() >= QUORUM
    }

    fn did_accumulate(&self) -> bool {
        self.successes.len() >= QUORUM
    }
}

// Structure that holds data chunk IDs in order but also allows efficient
// lookup.
struct UnneededChunks {
    queue: VecDeque<XorName>,
    set: HashSet<XorName>,
}

impl UnneededChunks {
    fn new() -> Self {
        UnneededChunks {
            queue: VecDeque::new(),
            set: HashSet::default(),
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn contains(&self, name: &XorName) -> bool {
        self.set.contains(name)
    }

    fn push(&mut self, name: XorName) {
        if self.set.insert(name) {
            self.queue.push_back(name);
        }
    }

    fn pop(&mut self) -> Option<XorName> {
        if let Some(name) = self.queue.pop_front() {
            let _ = self.set.remove(&name);
            Some(name)
        } else {
            None
        }
    }

    fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&XorName) -> bool,
    {
        let (retained, removed) = self.queue.drain(..).partition(f);
        self.queue = retained;
        for name in removed {
            let _ = self.set.remove(&name);
        }
    }

    #[cfg(all(test, feature = "use-mock-routing"))]
    fn clear(&mut self) {
        self.queue.clear();
        self.set.clear();
    }
}

type FragmentIndex = HashMap<FragmentInfo, FragmentState>;

fn index_needed_fragment(index: &mut FragmentIndex, fragment: FragmentInfo, holder: XorName) {
    let _ = index
        .entry(fragment)
        .or_insert_with(FragmentState::new)
        .holders
        .insert(holder);
}

fn unindex_needed_fragment(index: &mut FragmentIndex, fragment: &FragmentInfo, holder: &XorName) {
    let remove = if let Some(state) = index.get_mut(fragment) {
        let _ = state.holders.remove(holder);
        state.holders.is_empty()
    } else {
        false
    };

    if remove {
        let _ = index.remove(fragment);
    }
}

fn check_limit(before: u64, after: u64, max: u64) -> bool {
    let diff = after.saturating_sub(before);
    let remaining = max.saturating_sub(before);

    diff * 2 <= remaining + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake_clock::FakeClock;
    use rand::{self, Rng};

    #[test]
    fn needed_fragments() {
        let mut rng = rand::thread_rng();
        let mut cache = Cache::default();

        let holder0 = rng.gen();
        let holder1 = rng.gen();

        let fragment0 = FragmentInfo::ImmutableData(rand::random());

        assert!(cache.needed_fragments().is_empty());

        // Insert a single fragment. It should be present in the collection.
        cache.insert_needed_fragment(fragment0.clone(), holder0);
        let result = cache.needed_fragments();
        assert_eq!(result.len(), 1);
        assert_eq!(first(result), (fragment0.clone(), vec![holder0]));

        // Insert the same fragment with the same holder again. The collection
        // should not change.
        cache.insert_needed_fragment(fragment0.clone(), holder0);
        let result = cache.needed_fragments();
        assert_eq!(result.len(), 1);
        assert_eq!(first(result), (fragment0.clone(), vec![holder0]));

        // Insert the same fragment but with different holder. It should be present
        // in the collection only once, but with both holders.
        cache.insert_needed_fragment(fragment0.clone(), holder1);
        let result = cache.needed_fragments();
        assert_eq!(result.len(), 1);
        let item = first(result);
        assert_eq!(item.0, fragment0);
        assert_eq!(item.1.len(), 2);
        assert!(item.1.contains(&holder0));
        assert!(item.1.contains(&holder1));

        // Start request against one holder. The fragment should not appear among
        // the unrequested fragments even though this fragment is still unrequested
        // in different holder.
        cache.start_needed_fragment_request(&fragment0, &holder0);
        assert!(cache.needed_fragments().is_empty());

        // Stop the request. The fragment should be present in the collection again,
        // with the other holder.
        assert_eq!(
            unwrap!(cache.stop_needed_fragment_request(&holder0)),
            fragment0
        );
        let result = cache.needed_fragments();
        assert_eq!(result.len(), 1);
        assert_eq!(first(result), (fragment0.clone(), vec![holder1]));

        // Remove the fragment. It should remove it from all holders.
        cache.remove_needed_fragment(&fragment0);
        assert!(cache.needed_fragments().is_empty());

        // TODO: test that if the fragment is mutable data, it is returned even
        // if previously requested, because for mutable data we need to fire
        // one requests to every member of the group simultaneously.
    }

    #[test]
    fn needed_fragments_lifecycle() {
        let mut rng = rand::thread_rng();
        let mut cache = Cache::default();

        let fragment = FragmentInfo::ImmutableData(rng.gen());
        let holder0 = rng.gen();
        let holder1 = rng.gen();

        assert!(cache.fragment_holders.is_empty());
        assert!(cache.fragment_index.is_empty());

        // Start multiple requests, then stop them. Assert that the needed fragment
        // data structure remains empty afterwards.
        cache.insert_needed_fragment(fragment.clone(), holder0);
        cache.start_needed_fragment_request(&fragment, &holder0);

        cache.insert_needed_fragment(fragment.clone(), holder1);
        cache.start_needed_fragment_request(&fragment, &holder1);

        assert_eq!(cache.fragment_holders.len(), 2);
        assert_eq!(cache.fragment_index.len(), 1);

        assert_eq!(
            cache.stop_needed_fragment_request(&holder0),
            Some(fragment.clone())
        );
        assert_eq!(cache.fragment_holders.len(), 1);
        assert_eq!(cache.fragment_index.len(), 1);

        assert_eq!(
            cache.stop_needed_fragment_request(&holder1),
            Some(fragment.clone())
        );
        assert_eq!(cache.fragment_holders.len(), 0);
        assert_eq!(cache.fragment_index.len(), 0);

        // Now do the same, but instead of stopping, let one of the request expire.
        cache.insert_needed_fragment(fragment.clone(), holder0);
        cache.start_needed_fragment_request(&fragment, &holder0);

        cache.insert_needed_fragment(fragment.clone(), holder1);
        cache.start_needed_fragment_request(&fragment, &holder1);

        assert_eq!(cache.fragment_holders.len(), 2);
        assert_eq!(cache.fragment_index.len(), 1);

        assert_eq!(
            cache.stop_needed_fragment_request(&holder0),
            Some(fragment.clone())
        );
        assert_eq!(cache.fragment_holders.len(), 1);
        assert_eq!(cache.fragment_index.len(), 1);

        FakeClock::advance_time((FRAGMENT_REQUEST_TIMEOUT_SECS + 1) * 1000);
        cache.stop_expired_fragment_requests();
        assert_eq!(cache.fragment_holders.len(), 0);
        assert_eq!(cache.fragment_index.len(), 0);
    }

    fn first<I: IntoIterator<Item = T>, T>(i: I) -> T {
        unwrap!(i.into_iter().next())
    }
}
