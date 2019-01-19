mod cache;
mod data;
mod mutable_data_cache;
mod mutation;
#[cfg(all(test, feature = "use-mock-routing"))]
mod tests;

#[cfg(feature = "use-mock-crust")]
pub use self::cache::PENDING_WRITE_TIMEOUT_SECS;
use self::cache::{Cache, FragmentInfo, MutationVote, PendingWrite};
pub use self::data::{Data, DataId, ImmutableDataId, MutableDataId};
use self::mutable_data_cache::MutableDataCache;
use self::mutation::{Mutation, MutationType};
use self::rust_sodium::crypto::sign;
use crate::authority::ClientManagerAuthority;
#[cfg(feature = "use-mock-crust")]
use crate::chunk_store::Error as ChunkStoreError;
use crate::chunk_store::{Chunk, ChunkId, ChunkStore};
use crate::error::InternalError;
use crate::utils::{self, HashMap, HashSet, Instant};
use crate::vault::Refresh as VaultRefresh;
use crate::vault::RoutingNode;
use accumulator::Accumulator;
use log::{error, info, trace, warn};
use maidsafe_utilities::serialisation;
#[cfg(feature = "use-mock-crypto")]
use routing::mock_crypto::rust_sodium;
use routing::{
    Authority, ClientError, EntryAction, ImmutableData, MessageId, MutableData, PermissionSet,
    RoutingTable, User, Value, XorName, QUORUM_DENOMINATOR, QUORUM_NUMERATOR,
    TYPE_TAG_SESSION_PACKET,
};
#[cfg(not(feature = "use-mock-crypto"))]
use rust_sodium;
use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::From;
use std::fmt::{self, Debug, Formatter};
use std::time::Duration;
use tiny_keccak;
#[cfg(all(test, feature = "use-mock-routing"))]
use unwrap::unwrap;

const MAX_FULL_PERCENT: u64 = 50;
/// The timeout for accumulating refresh messages.
const ACCUMULATOR_TIMEOUT_SECS: u64 = 180;
/// The interval for print status log.
const STATUS_LOG_INTERVAL: u64 = 120;

macro_rules! log_status {
    ($dm:expr) => {
        if $dm.logging_time.elapsed().as_secs() > STATUS_LOG_INTERVAL {
            $dm.logging_time = Instant::now();
            info!("{:?}", $dm);
        }
    };
}

impl Chunk<DataId> for ImmutableData {
    type Id = ImmutableDataId;
}

impl ChunkId<DataId> for ImmutableDataId {
    type Chunk = ImmutableData;
    fn to_key(&self) -> DataId {
        DataId::Immutable(*self)
    }
}

impl Chunk<DataId> for MutableData {
    type Id = MutableDataId;
}

impl ChunkId<DataId> for MutableDataId {
    type Chunk = MutableData;
    fn to_key(&self) -> DataId {
        DataId::Mutable(*self)
    }
}

pub struct DataManager {
    group_size: usize,
    chunk_store: ChunkStore<DataId>,
    chunk_refresh_accumulator: Accumulator<MutableDataId, XorName>,
    fragment_refresh_accumulator: Accumulator<FragmentInfo, XorName>,
    cache: Cache,
    mdata_cache: MutableDataCache,
    immutable_data_count: u64,
    mutable_data_count: u64,
    client_get_requests: u64,
    logging_time: Instant,
    // This is only used in tests as a place to temporarily hold incoming group refresh messages in
    // order to delay handling them.
    _delayed_group_refresh_cache: Option<BTreeSet<Vec<u8>>>,
}

impl DataManager {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        group_size: usize,
        chunk_store_root: Option<String>,
        capacity: Option<u64>,
    ) -> Result<DataManager, InternalError> {
        let quorum = ((group_size * QUORUM_NUMERATOR) / QUORUM_DENOMINATOR) + 1;
        let chunk_store = ChunkStore::new(chunk_store_root, capacity)?;
        let accumulator_duration = Duration::from_secs(ACCUMULATOR_TIMEOUT_SECS);

        Ok(DataManager {
            group_size,
            chunk_store,
            chunk_refresh_accumulator: Accumulator::with_duration(quorum, accumulator_duration),
            fragment_refresh_accumulator: Accumulator::with_duration(quorum, accumulator_duration),
            cache: Cache::new(group_size),
            mdata_cache: MutableDataCache::new(group_size),
            immutable_data_count: 0,
            mutable_data_count: 0,
            client_get_requests: 0,
            logging_time: Instant::now(),
            // TODO: Once https://github.com/rust-lang/rust/issues/41681 is in stable we can
            // initialise this field under #[cfg(feature = "use-mock-crust")] and exclude the
            // member variable from the struct for production builds altogether.
            _delayed_group_refresh_cache: None,
        })
    }

    // When a new node joins a group, the other members of the group send it "refresh"
    // messages which contains info about the data chunks that this node needs to fetch
    // from them.
    //
    // Note: refresh is a message whose source is individual node, so its accumulation
    // must be performed manually.
    pub fn handle_serialised_refresh(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        serialised_refresh: &[u8],
    ) -> Result<(), InternalError> {
        let refreshes: Vec<Refresh> = serialisation::deserialise(serialised_refresh)?;
        self.handle_refreshes(routing_node, src, refreshes)
    }

    pub fn handle_refreshes(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        refreshes: Vec<Refresh>,
    ) -> Result<(), InternalError> {
        for refresh in refreshes {
            match refresh {
                Refresh::Chunk(data_id) => self.handle_chunk_refresh(src, data_id),
                Refresh::Fragment(fragment) => self.handle_fragment_refresh(src, fragment),
            }?
        }

        self.request_needed_data(routing_node)
    }

    // When a node in a group receives request to mutate some data it holds, it first sends
    // "group refresh" message to all the other members of the group. Only when the message
    // accumulates, the node applies the mutation to the data and updates it in the chunk
    // store.
    //
    // Note: group refresh is a message whose source is group, so the accumulation is
    // performed automatically by routing.
    pub fn handle_group_refresh(
        &mut self,
        routing_node: &mut RoutingNode,
        serialised_refresh: Vec<u8>,
    ) -> Result<(), InternalError> {
        #[cfg(feature = "use-mock-crust")]
        // If this returns `None` then the message has been cached for handling later to simulate a
        // network delay.
        let serialised_refresh = match self.handle_delayed_group_refresh(serialised_refresh) {
            Some(serialised_refresh) => serialised_refresh,
            None => return Ok(()),
        };

        let MutationVote { data_id, hash } = serialisation::deserialise(&serialised_refresh)?;
        let write = match self.cache.take_pending_write(&data_id, &hash) {
            Some(write) => write,
            None => return Ok(()),
        };

        let PendingWrite {
            mutation,
            src,
            dst,
            message_id,
            ..
        } = write;

        let mutation_type = mutation.mutation_type();
        let fragments =
            self.commit_pending_mutation(routing_node, src, dst, mutation, message_id)?;

        if fragments.is_empty() {
            // The commit wasn't successful.
            return Ok(());
        }

        match mutation_type {
            MutationType::PutIData => self.immutable_data_count += 1,
            MutationType::PutMData => self.mutable_data_count += 1,
            _ => (),
        }

        log_status!(self);

        let refreshes = fragments.into_iter().map(Refresh::Fragment).collect();
        self.send_refresh(
            routing_node,
            Authority::NaeManager(*data_id.name()),
            refreshes,
        )?;

        if let Some(group) = routing_node.close_group(*data_id.name(), self.group_size) {
            for node in &group {
                self.cache
                    .register_needed_data_with_another_holder(&data_id, *node);
            }

            self.request_needed_data(routing_node)?;
        }

        Ok(())
    }

    pub fn handle_get_idata(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);

        if let Ok(data) = self.chunk_store.get(&ImmutableDataId(name)) {
            trace!("As {:?} sending data {:?} to {:?}", dst, data, src);
            routing_node.send_get_idata_response(dst, src, Ok(data), msg_id)?;
        } else {
            trace!("DM sending get_idata_failure of {:?}", name);
            routing_node.send_get_idata_response(dst, src, Err(ClientError::NoSuchData), msg_id)?;
        }

        Ok(())
    }

    pub fn handle_get_idata_success(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        data: ImmutableData,
    ) -> Result<(), InternalError> {
        let mut valid = false;
        if let Some(fragment) = self.cache.stop_needed_fragment_request(&src) {
            if let FragmentInfo::ImmutableData(ref name) = fragment {
                if *name == *data.name() && *name == recompute_idata_name(&data) {
                    self.cache.remove_needed_fragment(&fragment);
                    valid = true;
                }
            }
        };

        self.request_needed_data(routing_node)?;

        if !valid {
            return Ok(());
        }

        // If we're no longer in the close group, return.
        if !close_to_address(routing_node, data.name()) {
            return Ok(());
        }

        let data_id = data.id();

        if self.chunk_store.has(&data_id) {
            return Ok(()); // data is already there.
        }

        self.clean_chunk_store();
        self.chunk_store.put(&data_id, &data)?;

        self.immutable_data_count += 1;
        log_status!(self);

        Ok(())
    }

    pub fn handle_get_idata_failure(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
    ) -> Result<(), InternalError> {
        if self.cache.stop_needed_fragment_request(&src).is_none() {
            return Err(InternalError::InvalidMessage);
        }

        self.request_needed_data(routing_node)
    }

    pub fn handle_put_idata(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        data: ImmutableData,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        if self.chunk_store.has(&data.id()) {
            trace!(
                "DM sending PutIData success for data {:?}, it already exists.",
                data.name()
            );
            routing_node.send_put_idata_response(dst, src, Ok(()), msg_id)?;
            return Ok(());
        }

        self.clean_chunk_store();

        if self.chunk_store_full() {
            let err = ClientError::NetworkFull;
            routing_node.send_put_idata_response(dst, src, Err(err.clone()), msg_id)?;
            return Err(From::from(err));
        }

        self.update_pending_writes(
            routing_node,
            Mutation::PutIData(data),
            src,
            dst,
            msg_id,
            false,
        )
    }

    pub fn handle_get_mdata(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);

        // Send the response as a node, to allow custom accumulation.
        let resp_src = Authority::ManagedNode(*routing_node.id()?.name());
        let resp_dst = src;

        let res = self.fetch_mdata(name, tag);
        trace!(
            "As {:?} sending GetMData response {:?} of {:?} to {:?}",
            resp_src,
            res,
            name,
            resp_dst
        );
        routing_node.send_get_mdata_response(resp_src, resp_dst, res, msg_id)?;

        Ok(())
    }

    pub fn handle_get_mdata_success(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        data: MutableData,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.cache
            .handle_needed_mutable_chunk_success(data.id(), src, msg_id);
        self.request_needed_data(routing_node)?;

        // If we're no longer in the close group, return.
        if !close_to_address(routing_node, data.name()) {
            return Ok(());
        }

        let data_id = data.id();
        let (shell, entries) = self.mdata_cache.accumulate(data, src);

        let (data, new) = match (shell, self.chunk_store.get(&data_id)) {
            (Some(mut shell), Ok(mut data)) => {
                if shell.version() > data.version() {
                    merge_mdata_entries(&mut shell, data.take_entries());
                    (Some(shell), false)
                } else {
                    (Some(data), false)
                }
            }
            (Some(mut shell), Err(_)) => {
                let entries = self.mdata_cache.take_entries(&data_id);
                merge_mdata_entries(&mut shell, entries);
                (Some(shell), true)
            }
            (None, Ok(data)) => (Some(data), false),
            (None, Err(_)) => (None, false),
        };

        if let Some(mut data) = data {
            merge_mdata_entries(&mut data, entries);
            self.clean_chunk_store();
            self.chunk_store.put(&data.id(), &data)?;
        } else {
            self.mdata_cache.insert_entries(data_id, entries);
        }

        if new {
            self.mutable_data_count += 1;
            log_status!(self);
        }

        Ok(())
    }

    pub fn handle_get_mdata_failure(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.cache.handle_needed_mutable_chunk_failure(src, msg_id);
        self.request_needed_data(routing_node)
    }

    pub fn handle_put_mdata(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        data: MutableData,
        msg_id: MessageId,
        _requester: sign::PublicKey,
    ) -> Result<(), InternalError> {
        let data_id = data.id();

        let res = if self.chunk_store.has(&data_id) {
            Err(ClientError::DataExists)
        } else {
            self.clean_chunk_store();

            if self.chunk_store_full() {
                Err(ClientError::NetworkFull)
            } else {
                Ok(())
            }
        };

        let mutation = Mutation::PutMData(data);
        let res = res.and_then(|_| self.validate_concurrent_mutations(None, &mutation));
        let rejected = if let Err(error) = res {
            trace!(
                "DM sending PutMData failure for data {:?}: {:?}",
                data_id,
                error
            );
            routing_node.send_put_mdata_response(dst, src, Err(error), msg_id)?;
            true
        } else {
            false
        };

        self.update_pending_writes(routing_node, mutation, src, dst, msg_id, rejected)
    }

    pub fn handle_get_mdata_shell(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self.fetch_mdata(name, tag).map(|data| data.shell());
        routing_node.send_get_mdata_shell_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_get_mdata_shell_success(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        mut shell: MutableData,
    ) -> Result<(), InternalError> {
        let valid = if let Some(fragment) = self.cache.stop_needed_fragment_request(&src) {
            let actual_hash = utils::mdata_shell_hash(&shell);

            match fragment {
                FragmentInfo::MutableDataShell { hash, .. } if hash == actual_hash => {
                    self.cache.remove_needed_fragment(&fragment);
                    true
                }
                _ => false,
            }
        } else {
            false
        };

        self.request_needed_data(routing_node)?;

        if !valid {
            return Ok(());
        }

        // If we're no longer in the close group, return.
        if !close_to_address(routing_node, shell.name()) {
            return Ok(());
        }

        let data_id = shell.id();
        let new = match self.chunk_store.get(&data_id) {
            Ok(ref old_data) if old_data.version() >= shell.version() => {
                // The data in the chunk store is already more recent than the
                // shell we received. Ignore it.
                return Ok(());
            }
            Ok(ref old_data) => {
                // The shell is more recent than the data in the chunk store.
                // Repace the data with the shell, but keep the entries.
                for (key, value) in old_data.entries() {
                    let _ = shell.mutate_entry_without_validation(key.clone(), value.clone());
                }

                false
            }
            Err(_) => {
                // If we have cached entries for this data, apply them.
                for (key, value) in self.mdata_cache.take_entries(&shell.id()) {
                    // OK to ingore the return value here because as the shell has no
                    // entries, this call can never fail.
                    let _ = shell.mutate_entry_without_validation(key, value);
                }

                true
            }
        };

        self.clean_chunk_store();
        self.chunk_store.put(&data_id, &shell)?;

        if new {
            self.mutable_data_count += 1;
            log_status!(self);
        }

        Ok(())
    }

    pub fn handle_get_mdata_shell_failure(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
    ) -> Result<(), InternalError> {
        if self.cache.stop_needed_fragment_request(&src).is_none() {
            return Err(InternalError::InvalidMessage);
        }

        self.request_needed_data(routing_node)
    }

    pub fn handle_get_mdata_version(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self.fetch_mdata(name, tag).map(|data| data.version());
        routing_node.send_get_mdata_version_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_list_mdata_entries(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self
            .fetch_mdata(name, tag)
            .map(|data| data.entries().clone());
        routing_node.send_list_mdata_entries_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_list_mdata_keys(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self
            .fetch_mdata(name, tag)
            .map(|data| data.entries().keys().cloned().collect());
        routing_node.send_list_mdata_keys_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_list_mdata_values(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self
            .fetch_mdata(name, tag)
            .map(|data| data.entries().values().cloned().collect());
        routing_node.send_list_mdata_values_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_get_mdata_value(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        key: Vec<u8>,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self
            .fetch_mdata(name, tag)
            .and_then(|data| data.get(&key).cloned().ok_or(ClientError::NoSuchEntry));
        routing_node.send_get_mdata_value_response(dst, src, res, msg_id)?;
        Ok(())
    }

    pub fn handle_get_mdata_value_success(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
        value: Value,
    ) -> Result<(), InternalError> {
        let info = if let Some(fragment) = self.cache.stop_needed_fragment_request(&src) {
            let actual_hash = utils::mdata_value_hash(&value);

            match fragment {
                FragmentInfo::MutableDataEntry {
                    name,
                    tag,
                    ref key,
                    hash,
                    ..
                } if hash == actual_hash => {
                    self.cache.remove_needed_fragment(&fragment);
                    Some((name, tag, key.clone()))
                }
                _ => None,
            }
        } else {
            None
        };

        self.request_needed_data(routing_node)?;

        let (name, tag, key) = if let Some(info) = info {
            info
        } else {
            return Ok(());
        };

        // If we're no longer in the close group, return.
        if !close_to_address(routing_node, &name) {
            return Ok(());
        }

        let data_id = MutableDataId(name, tag);
        match self.chunk_store.get(&data_id) {
            Ok(mut data) => {
                if data.mutate_entry_without_validation(key, value) {
                    self.clean_chunk_store();
                    self.chunk_store.put(&data_id, &data)?;
                }
            }
            Err(_) => {
                // We don't have the shell yet, so keep the entry around in the cache
                // until we receive the shell.
                self.mdata_cache.insert_entry(data_id, key, value);
            }
        }

        Ok(())
    }

    pub fn handle_get_mdata_value_failure(
        &mut self,
        routing_node: &mut RoutingNode,
        src: XorName,
    ) -> Result<(), InternalError> {
        if self.cache.stop_needed_fragment_request(&src).is_none() {
            return Err(InternalError::InvalidMessage);
        }

        self.request_needed_data(routing_node)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_mutate_mdata_entries(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InternalError> {
        let mutation = Mutation::MutateMDataEntries {
            name,
            tag,
            actions: actions.clone(),
        };
        let res = self.fetch_mdata(name, tag).and_then(|data| {
            data.clone().mutate_entries(actions.clone(), requester)?;
            self.validate_concurrent_mutations(Some(&data), &mutation)
        });

        self.start_pending_mutation(routing_node, src, dst, mutation, res, msg_id)
    }

    pub fn handle_list_mdata_permissions(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self
            .fetch_mdata(name, tag)
            .map(|data| data.permissions().clone());
        routing_node.send_list_mdata_permissions_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_list_mdata_user_permissions(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        self.update_request_stats(&src);
        let res = self
            .fetch_mdata(name, tag)
            .and_then(|data| data.user_permissions(&user).map(|p| *p));
        routing_node.send_list_mdata_user_permissions_response(dst, src, res, msg_id)?;
        Ok(())
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_set_mdata_user_permissions(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        permissions: PermissionSet,
        version: u64,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InternalError> {
        let mutation = Mutation::SetMDataUserPermissions {
            name,
            tag,
            user,
            permissions,
            version,
        };
        let res = self.fetch_mdata(name, tag).and_then(|data| {
            data.clone()
                .set_user_permissions(user, permissions, version, requester)?;
            self.validate_concurrent_mutations(Some(&data), &mutation)
        });
        self.start_pending_mutation(routing_node, src, dst, mutation, res, msg_id)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_del_mdata_user_permissions(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        user: User,
        version: u64,
        msg_id: MessageId,
        requester: sign::PublicKey,
    ) -> Result<(), InternalError> {
        let mutation = Mutation::DelMDataUserPermissions {
            name,
            tag,
            user,
            version,
        };
        let res = self.fetch_mdata(name, tag).and_then(|data| {
            data.clone()
                .del_user_permissions(&user, version, requester)?;
            self.validate_concurrent_mutations(Some(&data), &mutation)
        });
        self.start_pending_mutation(routing_node, src, dst, mutation, res, msg_id)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    pub fn handle_change_mdata_owner(
        &mut self,
        routing_node: &mut RoutingNode,
        src: ClientManagerAuthority,
        dst: Authority<XorName>,
        name: XorName,
        tag: u64,
        new_owners: BTreeSet<sign::PublicKey>,
        version: u64,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        let mutation = Mutation::ChangeMDataOwner {
            name,
            tag,
            new_owners: new_owners.clone(),
            version,
        };

        let res = self.fetch_mdata(name, tag).and_then(|data| {
            let new_owner = extract_owner(new_owners)?;

            if utils::verify_mdata_owner(&data, src.name()) {
                data.clone().change_owner(new_owner, version)?;
                self.validate_concurrent_mutations(Some(&data), &mutation)
            } else {
                Err(ClientError::AccessDenied)
            }
        });

        self.start_pending_mutation(routing_node, src.into(), dst, mutation, res, msg_id)
    }

    pub fn handle_node_added(
        &mut self,
        routing_node: &mut RoutingNode,
        node_name: &XorName,
        routing_table: &RoutingTable<XorName>,
    ) -> Result<(), InternalError> {
        if self.cache.prune_needed_fragments(routing_table) {
            let _ = self.request_needed_data(routing_node);
        }

        let mut refreshes = Vec::new();
        let mut has_pruned_data = false;

        for data_id in self.our_chunks() {
            // Only retain chunks for which we're still in the close group.
            match routing_table.other_closest_names(data_id.name(), self.group_size) {
                None => {
                    trace!("No longer a DM for {:?}", data_id);

                    match data_id {
                        DataId::Immutable(idata_id) => {
                            if self.chunk_store.has(&idata_id)
                                && !self.cache.is_in_unneeded(&idata_id)
                            {
                                self.immutable_data_count -= 1;
                                has_pruned_data = true;
                                self.cache.add_as_unneeded(idata_id);
                            }
                        }
                        DataId::Mutable(mdata_id) => {
                            if self.chunk_store.has(&mdata_id) {
                                self.mutable_data_count -= 1;
                                has_pruned_data = true;
                                let _ = self.chunk_store.delete(&mdata_id);
                            }
                        }
                    }
                }
                Some(close_group) => {
                    if close_group.contains(&node_name) {
                        refreshes.push(Refresh::from_data_id(data_id));
                    }
                }
            }
        }

        if !refreshes.is_empty() {
            let _ = self.send_refresh(routing_node, Authority::ManagedNode(*node_name), refreshes);
        }

        if has_pruned_data {
            log_status!(self);
        }

        Ok(())
    }

    /// Get all names and hashes of all data. // [TODO]: Can be optimised - 2016-04-23 09:11pm
    /// Send to all members of group of data.
    pub fn handle_node_lost(
        &mut self,
        routing_node: &mut RoutingNode,
        node_name: &XorName,
        routing_table: &RoutingTable<XorName>,
    ) -> Result<(), InternalError> {
        let pruned_unneeded_chunks = self.cache.prune_unneeded_chunks(routing_table);
        if pruned_unneeded_chunks != 0 {
            self.immutable_data_count += pruned_unneeded_chunks;
            log_status!(self);
        }

        if self.cache.prune_needed_fragments(routing_table) {
            self.request_needed_data(routing_node)?;
        }

        let mut refreshes = HashMap::default();
        for data_id in self.our_chunks() {
            match routing_table.other_closest_names(data_id.name(), self.group_size) {
                None => {
                    error!(
                        "Moved out of close group of {:?} in a NodeLost event.",
                        node_name
                    );
                }
                Some(close_group) => {
                    // If no new node joined the group due to this event, continue:
                    // If the group has fewer than `self.group_size` elements, the lost node was not
                    // replaced at all. Otherwise, if the group's last node is closer to the data
                    // than the lost node, the lost node was not in the group in the first place.
                    if let Some(&outer_node) = close_group.get(self.group_size.saturating_sub(2)) {
                        if data_id.name().closer(node_name, outer_node) {
                            refreshes
                                .entry(*outer_node)
                                .or_insert_with(Vec::new)
                                .push(Refresh::from_data_id(data_id))
                        }
                    }
                }
            }
        }

        for (node_name, refresh) in refreshes {
            let _ = self.send_refresh(routing_node, Authority::ManagedNode(node_name), refresh);
        }

        Ok(())
    }

    pub fn check_timeouts(&mut self, routing_node: &mut RoutingNode) {
        let _ = self.request_needed_data(routing_node);
    }

    fn fetch_mdata(&self, name: XorName, tag: u64) -> Result<MutableData, ClientError> {
        let data_id = MutableDataId(name, tag);
        if let Ok(data) = self.chunk_store.get(&data_id) {
            Ok(data)
        } else if tag == TYPE_TAG_SESSION_PACKET {
            Err(ClientError::NoSuchAccount)
        } else {
            Err(ClientError::NoSuchData)
        }
    }

    fn update_request_stats(&mut self, src: &Authority<XorName>) {
        if let Authority::Client { .. } = *src {
            self.client_get_requests += 1;
            log_status!(self);
        }
    }

    fn update_pending_writes(
        &mut self,
        routing_node: &mut RoutingNode,
        mutation: Mutation,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        message_id: MessageId,
        rejected: bool,
    ) -> Result<(), InternalError> {
        for PendingWrite {
            mutation,
            src,
            dst,
            message_id,
            ..
        } in self.cache.remove_expired_pending_writes()
        {
            let error = ClientError::from("Request expired.");
            trace!(
                "{:?} did not accumulate. Sending failure",
                mutation.data_id()
            );
            self.send_mutation_response(
                routing_node,
                src,
                dst,
                mutation.mutation_type(),
                mutation.data_id(),
                Err(error),
                message_id,
            )?;
        }

        let data_id = mutation.data_id();
        if let Some(refresh) = self
            .cache
            .insert_pending_write(mutation, src, dst, message_id, rejected)
        {
            self.send_group_refresh(routing_node, *data_id.name(), refresh, message_id)?;
        }

        Ok(())
    }

    fn start_pending_mutation(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        mutation: Mutation,
        res: Result<(), ClientError>,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        let mutation_type = mutation.mutation_type();
        let data_id = mutation.data_id();

        self.update_pending_writes(routing_node, mutation, src, dst, msg_id, res.is_err())?;

        if let Err(error) = res {
            self.send_mutation_response(
                routing_node,
                src,
                dst,
                mutation_type,
                data_id,
                Err(error),
                msg_id,
            )
        } else {
            Ok(())
        }
    }

    fn commit_pending_mutation(
        &mut self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        mutation: Mutation,
        msg_id: MessageId,
    ) -> Result<Vec<FragmentInfo>, InternalError> {
        let mutation_type = mutation.mutation_type();
        let data_id = mutation.data_id();

        let res = match mutation {
            Mutation::PutIData(data) => {
                let fragments = vec![FragmentInfo::ImmutableData(*data.name())];
                put_into_chunk_store(&mut self.chunk_store, &data).map(|_| fragments)
            }
            Mutation::PutMData(data) => {
                let fragments = FragmentInfo::mutable_data(&data);
                put_into_chunk_store(&mut self.chunk_store, &data).map(|_| fragments)
            }
            Mutation::MutateMDataEntries { name, tag, actions } => {
                self.with_mdata(name, tag, |data| {
                    let keys: Vec<_> = actions.keys().cloned().collect();
                    data.mutate_entries_without_validation(actions);
                    keys.into_iter()
                        .filter_map(|key| {
                            data.get(&key)
                                .map(|value| FragmentInfo::mutable_data_entry(data, key, value))
                        })
                        .collect()
                })
            }
            Mutation::SetMDataUserPermissions {
                name,
                tag,
                user,
                permissions,
                version,
            } => self.with_mdata(name, tag, |data| {
                let _ = data.set_user_permissions_without_validation(user, permissions, version);
                vec![FragmentInfo::mutable_data_shell(data)]
            }),
            Mutation::DelMDataUserPermissions {
                name,
                tag,
                user,
                version,
            } => self.with_mdata(name, tag, |data| {
                let _ = data.del_user_permissions_without_validation(&user, version);
                vec![FragmentInfo::mutable_data_shell(data)]
            }),
            Mutation::ChangeMDataOwner {
                name,
                tag,
                new_owners,
                version,
            } => self.with_mdata(name, tag, |data| {
                if let Some(new_owner) = new_owners.into_iter().next() {
                    let _ = data.change_owner_without_validation(new_owner, version);
                }
                vec![FragmentInfo::mutable_data_shell(data)]
            }),
        };

        let (res, fragments) = match res {
            Ok(fragments) => (Ok(()), fragments),
            Err(error) => (Err(error), Vec::new()),
        };

        self.send_mutation_response(routing_node, src, dst, mutation_type, data_id, res, msg_id)?;
        Ok(fragments)
    }

    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    fn send_mutation_response(
        &self,
        routing_node: &mut RoutingNode,
        src: Authority<XorName>,
        dst: Authority<XorName>,
        mutation_type: MutationType,
        data_id: DataId,
        res: Result<(), ClientError>,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        let res_string = match res {
            Ok(_) => "success".to_string(),
            Err(ref error) => format!("failure ({:?})", error),
        };

        match mutation_type {
            MutationType::PutIData => {
                trace!("DM sending PutIData {} for data {:?}", res_string, data_id);
                routing_node.send_put_idata_response(dst, src, res, msg_id)?
            }
            MutationType::PutMData => {
                trace!("DM sending PutMData {} for data {:?}", res_string, data_id);
                routing_node.send_put_mdata_response(dst, src, res, msg_id)?
            }
            MutationType::MutateMDataEntries => {
                trace!(
                    "DM sending MutateMDataEntries {} for data {:?}",
                    res_string,
                    data_id
                );
                routing_node.send_mutate_mdata_entries_response(dst, src, res, msg_id)?
            }
            MutationType::SetMDataUserPermissions => {
                trace!(
                    "DM sending SetMDataUserPermissions {} for data {:?}",
                    res_string,
                    data_id
                );
                routing_node.send_set_mdata_user_permissions_response(dst, src, res, msg_id)?
            }
            MutationType::DelMDataUserPermissions => {
                trace!(
                    "DM sending DelMDataUserPermissions {} for data {:?}",
                    res_string,
                    data_id
                );
                routing_node.send_del_mdata_user_permissions_response(dst, src, res, msg_id)?
            }
            MutationType::ChangeMDataOwner => {
                trace!(
                    "DM sending ChangeMDataOwner {} for data {:?}",
                    res_string,
                    data_id
                );
                routing_node.send_change_mdata_owner_response(dst, src, res, msg_id)?
            }
        }

        Ok(())
    }

    /// Returns whether our data uses more than `MAX_FULL_PERCENT` percent of available space.
    fn chunk_store_full(&self) -> bool {
        self.chunk_store.used_space() > (self.chunk_store.max_space() / 100) * MAX_FULL_PERCENT
    }

    /// Removes data chunks we are no longer responsible for until the chunk store is not full
    /// anymore.
    fn clean_chunk_store(&mut self) {
        while self.chunk_store_full() {
            if let Some(data_id) = self.cache.pop_unneeded_chunk() {
                if let Err(error) = self.chunk_store.delete(&data_id) {
                    warn!(
                        "DM failed to delete unneeded chunk {:?}: {:?}",
                        data_id, error
                    );
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn handle_fragment_refresh(
        &mut self,
        src: XorName,
        fragment: FragmentInfo,
    ) -> Result<(), InternalError> {
        if self
            .cache
            .register_needed_fragment_with_another_holder(fragment.clone(), src)
        {
            return Ok(());
        }

        let holders = match self
            .fragment_refresh_accumulator
            .add(fragment.clone(), src)
            .cloned()
        {
            Some(holders) => {
                self.fragment_refresh_accumulator.delete(&fragment);
                holders
            }
            None => return Ok(()),
        };

        let needed = match fragment {
            FragmentInfo::ImmutableData(name) => !self.chunk_store.has(&ImmutableDataId(name)),
            FragmentInfo::MutableDataShell {
                name, tag, version, ..
            } => match self.chunk_store.get(&MutableDataId(name, tag)) {
                Err(_) => true,
                Ok(data) => data.version() < version,
            },
            FragmentInfo::MutableDataEntry {
                name,
                tag,
                ref key,
                version,
                ..
            } => {
                if let Ok(data) = self.chunk_store.get(&MutableDataId(name, tag)) {
                    match data.get(key) {
                        None => true,
                        Some(value) => value.entry_version < version,
                    }
                } else {
                    true
                }
            }
        };

        if needed {
            for holder in holders {
                self.cache.insert_needed_fragment(fragment.clone(), holder);
            }
        }

        Ok(())
    }

    fn handle_chunk_refresh(
        &mut self,
        src: XorName,
        data_id: MutableDataId,
    ) -> Result<(), InternalError> {
        if self.chunk_refresh_accumulator.add(data_id, src).is_some() {
            self.chunk_refresh_accumulator.delete(&data_id);
            self.cache.insert_needed_mutable_chunk(data_id);
        }

        Ok(())
    }

    fn send_refresh(
        &self,
        routing_node: &mut RoutingNode,
        dst: Authority<XorName>,
        refreshes: Vec<Refresh>,
    ) -> Result<(), InternalError> {
        // FIXME - We need to handle >2MB chunks
        let src = Authority::ManagedNode(*routing_node.id()?.name());
        let payload = if dst.is_single() {
            serialisation::serialise(&VaultRefresh::DataManager(refreshes))?
        } else {
            serialisation::serialise(&refreshes)?
        };
        trace!("DM sending refresh to {:?}.", dst);
        routing_node.send_refresh_request(src, dst, payload, MessageId::new())?;
        Ok(())
    }

    fn send_group_refresh(
        &self,
        routing_node: &mut RoutingNode,
        name: XorName,
        refresh: MutationVote,
        msg_id: MessageId,
    ) -> Result<(), InternalError> {
        let payload = serialisation::serialise(&refresh)?;
        trace!("DM sending refresh data to group {:?}.", name);
        routing_node.send_refresh_request(
            Authority::NaeManager(name),
            Authority::NaeManager(name),
            payload,
            msg_id,
        )?;
        Ok(())
    }

    fn request_needed_data(&mut self, routing_node: &mut RoutingNode) -> Result<(), InternalError> {
        self.request_needed_chunks(routing_node)?;
        self.request_needed_fragments(routing_node)?;
        Ok(())
    }

    fn request_needed_chunks(
        &mut self,
        routing_node: &mut RoutingNode,
    ) -> Result<(), InternalError> {
        if let Some(data_id) = self.cache.needed_mutable_chunk() {
            let MutableDataId(name, tag) = data_id;
            let src = Authority::ManagedNode(*routing_node.id()?.name());
            let dst = Authority::NaeManager(name);
            let msg_id = MessageId::new();

            routing_node.send_get_mdata_request(src, dst, name, tag, msg_id)?;
            self.cache
                .start_needed_mutable_chunk_request(data_id, msg_id);
        }

        Ok(())
    }

    fn request_needed_fragments(
        &mut self,
        routing_node: &mut RoutingNode,
    ) -> Result<(), InternalError> {
        let src = Authority::ManagedNode(*routing_node.id()?.name());
        let candidates = self.cache.needed_fragments();

        // Set of holders we already sent a request to. Used to prevent sending
        // multiple request to a single holder.
        let mut busy_holders = HashSet::default();

        // For each fragment type except `MutableData`, send at most one request.
        // For `MutableData`, send a request to each member of its close group.
        for (fragment, holders) in candidates {
            for holder in holders {
                if !is_in_close_group(routing_node, fragment.name(), &holder) {
                    continue;
                }

                if !busy_holders.insert(holder) {
                    continue;
                }

                self.cache.start_needed_fragment_request(&fragment, &holder);

                let dst = Authority::ManagedNode(holder);
                let msg_id = MessageId::new();

                match fragment {
                    FragmentInfo::ImmutableData(name) => {
                        routing_node.send_get_idata_request(src, dst, name, msg_id)?;
                        break;
                    }
                    FragmentInfo::MutableDataShell { name, tag, .. } => {
                        routing_node.send_get_mdata_shell_request(src, dst, name, tag, msg_id)?;
                        break;
                    }
                    FragmentInfo::MutableDataEntry { name, tag, key, .. } => {
                        routing_node
                            .send_get_mdata_value_request(src, dst, name, tag, key, msg_id)?;
                        break;
                    }
                }
            }
        }

        self.cache.print_stats();
        Ok(())
    }

    // Get IDs of all the data chunks we are responsible for, regardless of whether
    // we already have them or not.
    fn our_chunks(&self) -> HashSet<DataId> {
        let mut result = self.cache.needed_chunks();
        result.extend(self.chunk_store.keys());
        result
    }

    // Load mutable data from the chunk store, apply the given function to it put it back.
    fn with_mdata<F, R>(&mut self, name: XorName, tag: u64, f: F) -> Result<R, ClientError>
    where
        F: FnOnce(&mut MutableData) -> R,
    {
        let mut data = get_from_chunk_store(&self.chunk_store, &MutableDataId(name, tag))?;
        let result = f(&mut data);
        put_into_chunk_store(&mut self.chunk_store, &data)?;
        Ok(result)
    }

    fn validate_concurrent_mutations(
        &self,
        existing_data: Option<&MutableData>,
        new_mutation: &Mutation,
    ) -> Result<(), ClientError> {
        if self
            .cache
            .validate_concurrent_mutations(existing_data, new_mutation)
        {
            Ok(())
        } else {
            // TODO: consider adding `Conflict` variant to `ClientError`.
            Err(ClientError::from("Conflicting concurrent mutation"))
        }
    }
}

#[cfg(feature = "use-mock-crust")]
impl DataManager {
    pub fn get_stored_ids_and_versions(&self) -> Result<Vec<(DataId, u64)>, ChunkStoreError> {
        let data_ids = self.chunk_store.keys();
        let mut result = Vec::with_capacity(data_ids.len());

        for data_id in data_ids {
            if let DataId::Immutable(ref id) = data_id {
                if self.cache.is_in_unneeded(id) {
                    continue;
                }
            }

            let version = self.get_version(&data_id)?;
            result.push((data_id, version));
        }

        Ok(result)
    }

    pub fn delay_group_refreshes(&mut self, routing_node: &mut RoutingNode, delayed: bool) {
        if let Some(cache) = self._delayed_group_refresh_cache.clone() {
            for delayed_refresh in cache {
                let _ = self.handle_group_refresh(routing_node, delayed_refresh);
            }
        }
        self._delayed_group_refresh_cache = if delayed { Some(BTreeSet::new()) } else { None };
    }

    // If `serialised_refresh` has not been previously handled here, it is added to the cache for
    // later and the function returns `None`.  If it has been seen before, it is popped from the
    // cache and returned.
    fn handle_delayed_group_refresh(&mut self, serialised_refresh: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(cache) = self._delayed_group_refresh_cache.as_mut() {
            if !cache.remove(&serialised_refresh) {
                let _ = cache.insert(serialised_refresh);
                return None;
            }
        }
        Some(serialised_refresh)
    }

    // In real network, the group_refresh is sent in the highest priority and shall not be dropped.
    // However, it may get severely delayed for particular node, hence being processed out-of-order.
    pub fn pop_group_refresh(&mut self, routing_node: &mut RoutingNode) {
        use itertools::Itertools;
        use maidsafe_utilities::SeededRng;
        use rand::Rng;

        let _ = self
            ._delayed_group_refresh_cache
            .as_ref()
            .and_then(|cache| {
                let mut rng = SeededRng::thread_rng();
                if rng.gen_weighted_bool(10) {
                    let chosen = rng.choose(&cache.iter().collect_vec()).cloned();
                    chosen.cloned()
                } else {
                    None
                }
            })
            .map(|delayed_refresh| self.handle_group_refresh(routing_node, delayed_refresh));
    }

    fn get_version(&self, data_id: &DataId) -> Result<u64, ChunkStoreError> {
        match *data_id {
            DataId::Immutable(_) => Ok(0),
            DataId::Mutable(ref data_id) => {
                self.chunk_store.get(data_id).map(|data| data.version())
            }
        }
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
impl DataManager {
    /// For testing only - put the given data directly into the chunks store.
    pub fn put_into_chunk_store<T, I>(&mut self, data: T)
    where
        T: Chunk<DataId, Id = I> + Data<Id = I>,
        I: ChunkId<DataId>,
    {
        unwrap!(self.chunk_store.put(&data.id(), &data))
    }

    /// For testing only - retrieve data with the given ID from the chunk store.
    pub fn get_from_chunk_store<T: ChunkId<DataId>>(&self, data_id: &T) -> Option<T::Chunk> {
        self.chunk_store.get(data_id).ok()
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.mdata_cache.clear();
    }
}

impl Debug for DataManager {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "This vault has received {} Client Get requests. Chunks stored: Immutable: {}, \
             Mutable: {}. Total stored: {} bytes.",
            self.client_get_requests,
            self.immutable_data_count,
            self.mutable_data_count,
            self.chunk_store.used_space()
        )
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub enum Refresh {
    Chunk(MutableDataId),
    Fragment(FragmentInfo),
}

impl Refresh {
    fn from_data_id(id: DataId) -> Self {
        match id {
            DataId::Immutable(ImmutableDataId(name)) => {
                Refresh::Fragment(FragmentInfo::ImmutableData(name))
            }
            DataId::Mutable(id) => Refresh::Chunk(id),
        }
    }
}

fn close_to_address(routing_node: &mut RoutingNode, address: &XorName) -> bool {
    routing_node
        .close_group(*address, routing_node.min_section_size())
        .is_some()
}

// Is `name` in the close group of `group_name`?
fn is_in_close_group(routing_node: &mut RoutingNode, group_name: &XorName, name: &XorName) -> bool {
    routing_node
        .close_group(*group_name, routing_node.min_section_size())
        .map_or(false, |group| group.contains(name))
}

fn recompute_idata_name(data: &ImmutableData) -> XorName {
    XorName(tiny_keccak::sha3_256(data.value()))
}

/// Merges the entries that are currently in the data with the new entries.
/// Entries that are not present in the data are inserted. Those that are present
/// are overwritten if the new version is higher than the old version, otherwise
/// ignored.
fn merge_mdata_entries<I>(data: &mut MutableData, entries: I)
where
    I: IntoIterator<Item = (Vec<u8>, Value)>,
{
    for (key, value) in entries {
        let _ = data.mutate_entry_without_validation(key, value);
    }
}

// `owners` must have exactly 1 element.
fn extract_owner(owners: BTreeSet<sign::PublicKey>) -> Result<sign::PublicKey, ClientError> {
    let len = owners.len();
    match owners.into_iter().next() {
        Some(owner) if len == 1 => Ok(owner),
        Some(_) | None => Err(ClientError::InvalidOwners),
    }
}

fn get_from_chunk_store<T: ChunkId<DataId> + Debug>(
    chunk_store: &ChunkStore<DataId>,
    data_id: &T,
) -> Result<T::Chunk, ClientError> {
    chunk_store.get(data_id).map_err(|error| {
        trace!(
            "DM failed to load {:?} from chunkstore: {:?}",
            data_id,
            error
        );
        ClientError::from(format!("Failed to load chunk: {:?}", error))
    })
}

fn put_into_chunk_store<T, I>(
    chunk_store: &mut ChunkStore<DataId>,
    data: &T,
) -> Result<(), ClientError>
where
    T: Chunk<DataId, Id = I> + Data<Id = I>,
    I: ChunkId<DataId> + Debug,
{
    chunk_store.put(&data.id(), data).map_err(|error| {
        trace!(
            "DM failed to store {:?} in chunkstore: {:?}",
            data.id(),
            error
        );
        ClientError::from(format!("Failed to store chunk: {:?}", error))
    })
}
