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

use std::mem;
use std::convert::From;
use std::collections::{HashMap, HashSet};

use error::InternalError;
use itertools::Itertools;
use kademlia_routing_table::GROUP_SIZE;
use safe_network_common::client_errors::GetError;
use timed_buffer::TimedBuffer;
use maidsafe_utilities::serialisation;
use routing::{self, Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId,
              PlainData, RequestContent, RequestMessage, ResponseContent, ResponseMessage};
use time::Duration;
use types::{Refresh, RefreshValue};
use vault::RoutingNode;
use xor_name::{self, XorName};

pub const REPLICANTS: usize = 4;

// This is the name of a PmidNode which has been chosen to store the data on.  It is associated with
// a specific piece of `ImmutableData`.  It is marked as `Pending` until the response of the Put
// request is received, when it is then marked as `Good` or `Failed` depending on the response
// result.  It remains `Good` until it fails a Get request, at which time it is deemed `Failed`, or
// until it disconnects or moves out of the close group for the chunk, when it is removed from the
// list of holders.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, RustcEncodable, RustcDecodable)]
pub enum DataHolderState {
    Good,
    Failed,
    Pending,
}


// Collection of PmidNodes holding a copy of the chunk
#[derive(Clone, PartialEq, Eq, Debug, RustcEncodable, RustcDecodable)]
pub struct Account {
    data_type: ImmutableDataType,
    data_holders: HashMap<XorName, DataHolderState>,
}

impl Account {
    pub fn new(data_type: &ImmutableDataType, data_holders: Vec<XorName>) -> Account {
        Account {
            data_type: data_type.clone(),
            data_holders: data_holders.into_iter()
                                      .map(|name| (name, DataHolderState::Pending))
                                      .collect(),
        }
    }
}


#[derive(Clone, PartialEq, Eq, Debug)]
struct MetadataForGetRequest {
    // This will be the ID of the first client request to trigger the Get, or of the churn event if
    // it wasn't triggered by a client request.
    pub message_id: MessageId,
    // The incoming requests that need to be responded to once we receive the data.
    pub requests: Vec<(MessageId, RequestMessage)>,
    pub data_holders: HashMap<XorName, DataHolderState>,
    pub data: Option<ImmutableData>,
    pub requested_data_type: ImmutableDataType,
    // Whether we already received a `GetFailure` from the IDM of one of the two other data types.
    pub secondary_location_failed: bool,
}

impl MetadataForGetRequest {
    pub fn new(message_id: &MessageId, account: &Account) -> MetadataForGetRequest {
        Self::construct(message_id, vec![], account)
    }

    pub fn with_message(message_id: &MessageId,
                        request: &RequestMessage,
                        account: &Account)
                        -> MetadataForGetRequest {
        Self::construct(message_id,
                        vec![(message_id.clone(), request.clone()); 1],
                        account)
    }

    pub fn send_get_requests(&self,
                             routing_node: &RoutingNode,
                             data_name: &XorName,
                             message_id: MessageId) {
        let src = Authority::NaeManager(*data_name);
        let log = |data_type: &ImmutableDataType, data_name: &XorName, dst: &Authority| {
            trace!("ImmutableDataManager {} sending get {:?}({}) to {:?}",
                   unwrap_result!(routing_node.name()),
                   data_type,
                   data_name,
                   dst);
        };

        if self.data_holders.is_empty() {
            // There are no "Good" holders for this type, so send Get to other types' DMs
            let mut msg_id = message_id;
            let (normal_name, backup_name, sacrificial_name) = match self.requested_data_type {
                ImmutableDataType::Normal => {
                    (None,
                     Some(routing::normal_to_backup(data_name)),
                     Some(routing::normal_to_sacrificial(data_name)))
                }
                ImmutableDataType::Backup => {
                    (Some(routing::backup_to_normal(data_name)),
                     None,
                     Some(routing::backup_to_sacrificial(data_name)))
                }
                ImmutableDataType::Sacrificial => {
                    (Some(routing::sacrificial_to_normal(data_name)),
                     Some(routing::sacrificial_to_backup(data_name)),
                     None)
                }
            };
            if let Some(normal_name) = normal_name {
                let dst = Authority::NaeManager(normal_name);
                let data_type = ImmutableDataType::Normal;
                log(&data_type, &normal_name, &dst);
                let data_request = DataRequest::Immutable(normal_name, data_type);
                msg_id = MessageId::increment_first_byte(&msg_id);
                let _ = routing_node.send_get_request(src.clone(), dst, data_request, msg_id);
            }
            if let Some(backup_name) = backup_name {
                let dst = Authority::NaeManager(backup_name);
                let data_type = ImmutableDataType::Backup;
                log(&data_type, &backup_name, &dst);
                let data_request = DataRequest::Immutable(backup_name, data_type);
                msg_id = MessageId::increment_first_byte(&msg_id);
                let _ = routing_node.send_get_request(src.clone(), dst, data_request, msg_id);
            }
            if let Some(sacrificial_name) = sacrificial_name {
                let dst = Authority::NaeManager(sacrificial_name);
                let data_type = ImmutableDataType::Sacrificial;
                log(&data_type, &sacrificial_name, &dst);
                let data_request = DataRequest::Immutable(sacrificial_name, data_type);
                msg_id = MessageId::increment_first_byte(&msg_id);
                let _ = routing_node.send_get_request(src.clone(), dst, data_request, msg_id);
            }
        } else {
            // Send to data_holders (which should be "Good" holders)
            for (good_node, _) in &self.data_holders {
                let dst = Authority::ManagedNode(*good_node);
                let data_request = DataRequest::Immutable(*data_name,
                                                          self.requested_data_type.clone());
                log(&self.requested_data_type, data_name, &dst);
                let _ = routing_node.send_get_request(src.clone(), dst, data_request, message_id);
            }
        }
    }

    fn construct(message_id: &MessageId,
                 requests: Vec<(MessageId, RequestMessage)>,
                 account: &Account)
                 -> MetadataForGetRequest {
        // We only want to try and get data from "good" holders
        let good_nodes = account.data_holders
                                .iter()
                                .filter_map(|(name, state)| {
                                    match *state {
                                        DataHolderState::Good => {
                                            Some((*name, DataHolderState::Pending))
                                        }
                                        DataHolderState::Failed | DataHolderState::Pending => None,
                                    }
                                })
                                .collect();

        MetadataForGetRequest {
            message_id: *message_id,
            requests: requests,
            data_holders: good_nodes,
            data: None,
            requested_data_type: account.data_type.clone(),
            secondary_location_failed: false,
        }
    }

    fn reply_with_data_else_cache_request(&mut self,
                                          routing_node: &RoutingNode,
                                          request: &RequestMessage,
                                          message_id: &MessageId) {
        // If we've already received the chunk, send it to the new requester.  Otherwise add the
        // request to the others for later handling.
        if let Some(ref data) = self.data {
            let src = request.dst.clone();
            let dst = request.src.clone();
            let _ = routing_node.send_get_success(src,
                                                  dst,
                                                  Data::Immutable(data.clone()),
                                                  *message_id);
        } else {
            self.requests.push((*message_id, request.clone()));
        }
    }
}



pub struct ImmutableDataManager {
    // <Data name, PmidNodes holding a copy of the data>
    accounts: HashMap<XorName, Account>,
    // key is chunk_name
    ongoing_gets: TimedBuffer<XorName, MetadataForGetRequest>,
    data_cache: HashMap<XorName, ImmutableData>,
}

impl ImmutableDataManager {
    pub fn new() -> ImmutableDataManager {
        ImmutableDataManager {
            accounts: HashMap::new(),
            ongoing_gets: TimedBuffer::new(Duration::minutes(5)),
            data_cache: HashMap::new(),
        }
    }

    pub fn handle_get(&mut self,
                      routing_node: &RoutingNode,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data_name, message_id) =
            if let RequestContent::Get(DataRequest::Immutable(ref data_name, _), ref message_id) =
                   request.content {
                (data_name, message_id)
            } else {
                unreachable!("Error in vault demuxing")
            };

        // If the data doesn't exist, respond with GetFailure
        let account = if let Some(account) = self.accounts.get(&data_name) {
            account
        } else {
            let src = request.dst.clone();
            let dst = request.src.clone();
            let error = GetError::NoSuchData;
            let external_error_indicator = try!(serialisation::serialise(&error));
            let _ = routing_node.send_get_failure(src,
                                                  dst,
                                                  request.clone(),
                                                  external_error_indicator,
                                                  *message_id);
            return Err(From::from(error));
        };

        // If there's an ongoing Put operation, get the data from the cached copy there and return
        if let Some(immutable_data) = self.data_cache.get(data_name) {
            let src = request.dst.clone();
            let dst = request.src.clone();
            let _ = routing_node.send_get_success(src,
                                                  dst,
                                                  Data::Immutable(immutable_data.clone()),
                                                  *message_id);
            return Ok(());
        }

        // If there's already a cached get request, handle it here and return
        if let Some(mut metadata) = self.ongoing_gets.get_mut(&data_name) {
            return Ok(metadata.reply_with_data_else_cache_request(routing_node,
                                                                  request,
                                                                  message_id));
        }

        // This is new cache entry
        let entry = MetadataForGetRequest::with_message(message_id, request, account);
        entry.send_get_requests(routing_node, &data_name, *message_id);
        let _ = self.ongoing_gets.insert(*data_name, entry);
        Ok(())
    }

    pub fn handle_put(&mut self,
                      routing_node: &RoutingNode,
                      full_pmid_nodes: &HashSet<XorName>,
                      request: &RequestMessage)
                      -> Result<(), InternalError> {
        let (data, message_id) = if let RequestContent::Put(Data::Immutable(ref data),
                                                            ref message_id) = request.content {
            (data, message_id)
        } else {
            unreachable!("Error in vault demuxing");
        };

        let data_name = data.name();
        // Only send success response if src is MaidManager.
        if let Authority::ClientManager(_) = request.src {
            let src = request.dst.clone();
            let dst = request.src.clone();
            let _ = routing_node.send_put_success(src, dst, data_name, *message_id);
        }

        // If the data already exists, send success and finish.
        if self.accounts.contains_key(&data_name) {
            return Ok(());
        }

        // Choose the PmidNodes to store the data on, and add them in a new database entry.
        // This can potentially return an empty list if all the nodes are full.
        let target_data_holders = try!(self.choose_initial_data_holders(routing_node,
                                                                        full_pmid_nodes,
                                                                        &data_name));
        trace!("ImmutableDataManager chosen {:?} as data_holders for chunk {:?}",
               target_data_holders,
               data);
        let _ = self.accounts.insert(data_name,
                                     Account::new(data.get_type_tag(),
                                                  target_data_holders.clone()));
        let _ = self.data_cache.insert(data_name, data.clone());

        // Send the message on to the PmidNodes' managers.
        for pmid_node in target_data_holders {
            let src = Authority::NaeManager(data_name);
            let dst = Authority::NodeManager(pmid_node);
            let _ = routing_node.send_put_request(src,
                                                  dst,
                                                  Data::Immutable(data.clone()),
                                                  *message_id);
        }

        // // If this is a "Normal" copy, we need to Put the "Backup" and "Sacrificial" copies too.
        // if let ImmutableDataType::Normal = *data.get_type_tag() {
        //     let backup = ImmutableData::new(ImmutableDataType::Backup, data.value().clone());
        //     let _ = routing_node.send_put_request(request.dst.clone(),
        //                                           Authority::NaeManager(backup.name()),
        //                                           Data::Immutable(backup),
        //                                           *message_id);
        //     let sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial,
        //                                          data.value().clone());
        //     let _ = routing_node.send_put_request(request.dst.clone(),
        //                                           Authority::NaeManager(sacrificial.name()),
        //                                           Data::Immutable(sacrificial),
        //                                           *message_id);
        // }

        Ok(())
    }

    pub fn handle_get_success(&mut self,
                              routing_node: &RoutingNode,
                              response: &ResponseMessage)
                              -> Result<(), InternalError> {
        let data_name;
        let message_id;
        {
            let (data, metadata) = try!(self.find_ongoing_get_after_success(response));
            data_name = data.name();
            message_id = metadata.message_id;

            // Reply to any unanswered requests
            while let Some((original_message_id, request)) = metadata.requests.pop() {
                let src = request.dst.clone();
                let dst = request.src;
                trace!("Sending GetSuccess back to {:?}", dst);
                let _ = routing_node.send_get_success(src,
                                                      dst,
                                                      Data::Immutable(data.clone()),
                                                      original_message_id);
            }

            if Some(&DataHolderState::Pending) == metadata.data_holders.get(response.src.name()) {
                let _ = metadata.data_holders.insert(*response.src.name(), DataHolderState::Good);
            }

            // Keep the data with the cached metadata in case further get requests arrive for it
            if metadata.data.is_none() {
                metadata.data = Some(data);
            }
            trace!("Metadata for Get {} updated to {:?}", data_name, metadata);
        }

        self.check_and_replicate_after_get(routing_node, &data_name, &message_id)
    }

    pub fn handle_get_failure(&mut self,
                              routing_node: &RoutingNode,
                              pmid_node: &XorName,
                              message_id: &MessageId,
                              request: &RequestMessage,
                              _external_error_indicator: &[u8])
                              -> Result<(), InternalError> {
        let mut metadata_message_id = None;
        let data_name = if let Ok((data_name, metadata)) =
                               self.find_ongoing_get_after_failure(request) {
            metadata_message_id = Some(metadata.message_id);

            if Some(&DataHolderState::Pending) == metadata.data_holders.get(request.dst.name()) {
                let _ = metadata.data_holders.insert(*request.dst.name(), DataHolderState::Failed);
            }
            trace!("Metadata for Get {} updated to {:?}", data_name, metadata);
            data_name
        } else {
            if let RequestContent::Get(ref data_request, _) = request.content {
                data_request.name()
            } else {
                return Err(InternalError::InvalidResponse);
            }
        };

        // Mark the responder as "failed" in the account if it was previously marked "good"
        if let Some(account) = self.accounts.get_mut(&data_name) {
            if Some(&DataHolderState::Good) == account.data_holders.get(pmid_node) {
                let _ = account.data_holders.insert(*pmid_node, DataHolderState::Failed);
                // Notify the failed PN's managers
                let src = Authority::NaeManager(data_name);
                let dst = Authority::NodeManager(*pmid_node);
                // TODO: This should be send_delete_request, after the API has been changed.
                let _ = routing_node.send_post_request(src,
                                                       dst,
                                                       Data::Plain(PlainData::new(data_name,
                                                                                  vec![])),
                                                       *message_id);
            }
            trace!("Account for {} updated to {:?}", data_name, account);
        }

        if let Some(msg_id) = metadata_message_id {
            try!(self.check_and_replicate_after_get(routing_node, &data_name, &msg_id));
            Ok(())
        } else {
            Err(InternalError::FailedToFindCachedRequest(*message_id))
        }
    }

    pub fn handle_get_from_other_location_failure(&mut self,
                                                  routing_node: &RoutingNode,
                                                  request: &RequestMessage)
                                                  -> Result<(), InternalError> {
        let mut to_remove = None;
        {
            let (data_name, metadata) = try!(self.find_ongoing_get_after_failure(request));
            warn!("Other location failed to provide ImmutableData {} - original request: {:?}",
                  data_name,
                  request);
            if metadata.requested_data_type == ImmutableDataType::Normal {
                // This Vault is the "Normal" DM.  If we've already had one secondary location
                // failed, reply to requesters as we've exhausted all options
                if metadata.secondary_location_failed {
                    Self::send_get_failures(routing_node, metadata);
                    // Entry can be removed from cache now.
                    to_remove = Some(data_name);
                } else {
                    metadata.secondary_location_failed = true;
                }
            }
        }

        if let Some(data_name) = to_remove {
            let _ = self.ongoing_gets.remove(&data_name);
        }
        Ok(())
    }

    pub fn handle_put_success(&mut self,
                              pmid_node: &XorName,
                              data_name: &XorName)
                              -> Result<(), InternalError> {
        // TODO: Check that the data_name is correct.
        let account = if let Some(account) = self.accounts.get_mut(&data_name) {
            account
        } else {
            debug!("Don't have account for {}", data_name);
            return Err(InternalError::InvalidResponse);
        };

        if Some(&DataHolderState::Pending) != account.data_holders.get(pmid_node) {
            debug!("Failed to update {} - {:?}", pmid_node, account);
            return Err(InternalError::InvalidResponse);
        }
        let _ = account.data_holders.insert(*pmid_node, DataHolderState::Good);
        let _ = self.data_cache.remove(&data_name);

        Ok(())
    }

    pub fn handle_put_failure(&mut self,
                              routing_node: &RoutingNode,
                              pmid_node: &XorName,
                              immutable_data: &ImmutableData,
                              message_id: &MessageId)
                              -> Result<(), InternalError> {
        let account = if let Some(account) = self.accounts.get_mut(&immutable_data.name()) {
            account
        } else {
            debug!("Don't have account for {}", immutable_data.name());
            return Err(InternalError::InvalidResponse);
        };

        // Mark the holder as Failed
        if Some(&DataHolderState::Pending) != account.data_holders.get(pmid_node) {
            debug!("Failed to update {} - {:?}", pmid_node, account);
            return Err(InternalError::InvalidResponse);
        }
        let _ = account.data_holders.insert(*pmid_node, DataHolderState::Failed);

        // Find a replacement - first node in close_group not already tried
        let data_name = immutable_data.name();
        let target_data_holders = match try!(routing_node.close_group(data_name)) {
            None => return Err(InternalError::NotInCloseGroup),
            Some(target_data_holders) => target_data_holders,
        };

        if let Some(new_holder) = target_data_holders.iter()
                                                     .find(|elt| {
                                                         !account.data_holders
                                                                 .contains_key(elt)
                                                     }) {
            let src = Authority::NaeManager(immutable_data.name());
            let dst = Authority::NodeManager(*new_holder);
            let data = Data::Immutable(immutable_data.clone());
            let _ = routing_node.send_put_request(src, dst, data, *message_id);
            let _ = account.data_holders.insert(*new_holder, DataHolderState::Pending);
        } else {
            error!("Failed to find a new storage node for {}.", data_name);
            return Err(InternalError::UnableToAllocateNewPmidNode);
        }

        Ok(())
    }

    pub fn check_timeout(&mut self, routing_node: &RoutingNode) {
        for data_name in &self.ongoing_gets.get_expired() {
            let message_id;
            {
                // Safe to unwrap here as we just got all these keys via `get_expired`
                let metadata = self.ongoing_gets
                                   .get_mut(data_name)
                                   .expect("Logic error in TimedBuffer");
                let pending_nodes = metadata.data_holders
                                            .iter()
                                            .filter(|&(_, state)| {
                                                *state == DataHolderState::Pending
                                            })
                                            .map(|(name, _)| *name)
                                            .collect_vec();
                for name in pending_nodes {
                    warn!("PmidNode {} failed to reply to Get request for {}.",
                          name,
                          data_name);
                    // Mark it as "failed" in the account if it was previously marked "good"
                    if let Some(account) = self.accounts.get_mut(data_name) {
                        if Some(&DataHolderState::Good) == account.data_holders.get(&name) {
                            let _ = account.data_holders.insert(name, DataHolderState::Failed);
                        }
                    }
                }
                message_id = metadata.message_id;
            }
            // let _ = self.ongoing_gets.insert(*data_name, metadata);
            let _ = self.check_and_replicate_after_get(routing_node, data_name, &message_id);
        }
    }

    pub fn handle_refresh(&mut self, data_name: XorName, account: Account) {
        let _ = self.accounts.insert(data_name, account);
    }

    pub fn handle_node_added(&mut self, routing_node: &RoutingNode, node_name: &XorName) {
        let message_id = MessageId::from_added_node(*node_name);
        // Remove entries from `data_cache` that we are not responsible for any more.
        let data_cache = mem::replace(&mut self.data_cache, HashMap::new());
        self.data_cache = data_cache.into_iter()
                                    .filter(|&(ref data_name, _)| {
                                        self.close_group_to(routing_node, data_name)
                                            .is_some()
                                    })
                                    .collect();
        // Remove entries from `ongoing_gets` that we are not responsible for any more.
        self.ongoing_gets
            .remove_keys(|&data_name| {
                match routing_node.close_group(*data_name) {
                    Ok(Some(_)) => false,
                    _ => true,
                }
            });
        // Only retain accounts for which we're still in the close group.
        let accounts = mem::replace(&mut self.accounts, HashMap::new());
        self.accounts = accounts.into_iter()
                                .filter_map(|(data_name, mut account)| {
                                    let close_group = if let Some(group) =
                                                             self.close_group_to(routing_node,
                                                                                 &data_name) {
                                        group
                                    } else {
                                        return None;
                                    };
                                    if close_group.contains(node_name) {
                                        account.data_holders =
                    account.data_holders
                           .iter()
                           .filter_map(|(pmid_name, state)| {
                               // Remove this data holder if it has been pushed out of the close
                               // group by the new node, i. e. if it is now too far away from the
                               // data. If Routing would suppress NodeAdded events on the side of
                               // the joining node, we could instead do this here:
                               // close_group.contains(pmid_node.name())
                               if close_group.get(GROUP_SIZE - 1).into_iter().all(|name| {
                                   xor_name::closer_to_target_or_equal(pmid_name,
                                                                       name,
                                                                       &data_name)
                               }) {
                                   Some((*pmid_name, *state))
                               } else {
                                   None
                               }
                           })
                           .collect();
                                    }
                                    let _ = self.handle_churn_for_account(routing_node,
                                                                          &data_name,
                                                                          &message_id,
                                                                          close_group,
                                                                          &mut account);
                                    Some((data_name, account))
                                })
                                .collect();
    }

    pub fn handle_node_lost(&mut self, routing_node: &RoutingNode, node_name: &XorName) {
        let message_id = MessageId::from_lost_node(*node_name);
        let mut accounts = mem::replace(&mut self.accounts, HashMap::new());
        accounts.iter_mut().foreach(|(data_name, account)| {
            account.data_holders = account.data_holders
                                          .iter()
                                          .filter_map(|(pmid_name, state)| if pmid_name ==
                                                                              node_name {
                                              None
                                          } else {
                                              Some((*pmid_name, *state))
                                          })
                                          .collect();
            if let Some(close_group) = self.close_group_to(routing_node, &data_name) {
                let _ = self.handle_churn_for_account(routing_node,
                                                      data_name,
                                                      &message_id,
                                                      close_group,
                                                      account);
            }
        });
        let _ = mem::replace(&mut self.accounts, accounts);
    }

    // This is used when handling Get responses since we don't know the data name of the original
    // request if the response is from a NaeManager.  In this case it will (very likely) be for a
    // different type to the ones this Vault is currently managing, so we try to find an entry in
    // the ongoing_gets which matches the response's name converted to each of the other two types.
    //
    // If this Vault is a manager for two types for that particular chunk, there could be more than
    // one entry which matches this response.  As such, we need to match the entry which contains no
    // "Good" holders, as that will be the one which triggered the Get for the different chunk type.
    //
    // It is assumed that a Vault will never be a manager for all three types, so we don't have to
    // look for more than one entry which matches.
    fn find_ongoing_get_after_success
        (&mut self,
         response: &ResponseMessage)
         -> Result<(ImmutableData, &mut MetadataForGetRequest), InternalError> {
        let (data, message_id) = if let ResponseContent::GetSuccess(Data::Immutable(ref data),
                                                                    ref message_id) =
                                        response.content {
            (data, message_id)
        } else {
            unreachable!("Error in vault demuxing")
        };
        let data_name = data.name();
        if let Authority::NaeManager(_) = response.src {
            let (normal_name, backup_name, sacrificial_name) = match *data.get_type_tag() {
                ImmutableDataType::Normal => {
                    (None,
                     Some(routing::normal_to_backup(&data_name)),
                     Some(routing::normal_to_sacrificial(&data_name)))
                }
                ImmutableDataType::Backup => {
                    (Some(routing::backup_to_normal(&data_name)),
                     None,
                     Some(routing::backup_to_sacrificial(&data_name)))
                }
                ImmutableDataType::Sacrificial => {
                    (Some(routing::sacrificial_to_normal(&data_name)),
                     Some(routing::sacrificial_to_backup(&data_name)),
                     None)
                }
            };
            let mut found = None;
            if let Some(normal_name) = normal_name {
                if self.ongoing_gets.contains_key(&normal_name) {
                    found = Some((normal_name,
                                  ImmutableData::new(ImmutableDataType::Normal,
                                                     data.value().clone())));
                }
            }
            if let Some(backup_name) = backup_name {
                if found.is_none() && self.ongoing_gets.contains_key(&backup_name) {
                    found = Some((backup_name,
                                  ImmutableData::new(ImmutableDataType::Backup,
                                                     data.value().clone())));
                }
            }
            if let Some(sacrificial_name) = sacrificial_name {
                if found.is_none() && self.ongoing_gets.contains_key(&sacrificial_name) {
                    found = Some((sacrificial_name,
                                  ImmutableData::new(ImmutableDataType::Sacrificial,
                                                     data.value().clone())));
                }
            }
            if let Some((found_name, converted_data)) = found {
                let metadata = self.ongoing_gets.get_mut(&found_name).expect("Must exist");
                return Ok((converted_data, metadata));
            }
        } else {
            if let Some(metadata) = self.ongoing_gets.get_mut(&data_name) {
                return Ok((data.clone(), metadata));
            }
        }
        warn!("Failed to find metadata for Get response of {} with msg ID {:?}",
              data_name,
              message_id);
        Err(InternalError::FailedToFindCachedRequest(*message_id))
    }

    // See comments for find_ongoing_get_after_success
    fn find_ongoing_get_after_failure
        (&mut self,
         request: &RequestMessage)
         -> Result<(XorName, &mut MetadataForGetRequest), InternalError> {
        let (data_request, message_id) = if let RequestContent::Get(ref data_request,
                                                                    ref message_id) =
                                                request.content {
            (data_request, message_id)
        } else {
            warn!("Request type doesn't correspond to response type: {:?}",
                  request);
            return Err(InternalError::InvalidResponse);
        };

        if let Authority::NaeManager(_) = request.dst {
            let mut found = None;
            let (normal_name, backup_name, sacrificial_name) = match *data_request {
                DataRequest::Immutable(ref data_name, ImmutableDataType::Normal) => {
                    (None,
                     Some(routing::normal_to_backup(data_name)),
                     Some(routing::normal_to_sacrificial(data_name)))
                }
                DataRequest::Immutable(ref data_name, ImmutableDataType::Backup) => {
                    (Some(routing::backup_to_normal(data_name)),
                     None,
                     Some(routing::backup_to_sacrificial(data_name)))
                }
                DataRequest::Immutable(ref data_name, ImmutableDataType::Sacrificial) => {
                    (Some(routing::sacrificial_to_normal(data_name)),
                     Some(routing::sacrificial_to_backup(data_name)),
                     None)
                }
                _ => unreachable!(),  // Safe to use this here since response is from a group
            };
            if let Some(normal_name) = normal_name {
                if self.ongoing_gets.contains_key(&normal_name) {
                    found = Some(normal_name);
                }
            }
            if let Some(backup_name) = backup_name {
                if found.is_none() && self.ongoing_gets.contains_key(&backup_name) {
                    found = Some(backup_name);
                }
            }
            if let Some(sacrificial_name) = sacrificial_name {
                if found.is_none() && self.ongoing_gets.contains_key(&sacrificial_name) {
                    found = Some(sacrificial_name);
                }
            }
            if let Some(found_name) = found {
                let metadata = self.ongoing_gets.get_mut(&found_name).expect("Must exist");
                return Ok((found_name, metadata));
            }
        } else {
            if let Some(metadata) = self.ongoing_gets.get_mut(&data_request.name()) {
                return Ok((data_request.name(), metadata));
            }
        }
        warn!("Failed to find metadata for Get response of {} with msg ID {:?}",
              data_request.name(),
              message_id);
        Err(InternalError::FailedToFindCachedRequest(*message_id))
    }

    fn handle_churn_for_account(&mut self,
                                routing_node: &RoutingNode,
                                data_name: &XorName,
                                message_id: &MessageId,
                                close_group: Vec<XorName>,
                                account: &mut Account)
                                -> Option<(XorName, Account)> {
        trace!("Churning for {} - holders after: {:?}", data_name, account);

        // Check to see if the chunk should be replicated
        let new_replicants_count = Self::new_replicants_count(&account);
        if new_replicants_count > 0 {
            trace!("Need {} more replicant(s) for {}",
                   new_replicants_count,
                   data_name);
            if !self.handle_churn_for_ongoing_puts(routing_node,
                                                   data_name,
                                                   message_id,
                                                   account,
                                                   &close_group,
                                                   new_replicants_count) &&
               !self.handle_churn_for_ongoing_gets(data_name, &close_group) {
                // Create a new entry and send Get requests to each of the current holders
                let entry = MetadataForGetRequest::new(message_id, &account);
                trace!("Created ongoing get entry for {} - {:?}", data_name, entry);
                entry.send_get_requests(routing_node, data_name, *message_id);
                let _ = self.ongoing_gets.insert(*data_name, entry);
            }
        }

        self.send_refresh(routing_node, &data_name, &account, &message_id);
        Some((*data_name, account.clone()))
    }

    fn close_group_to(&self,
                      routing_node: &RoutingNode,
                      data_name: &XorName)
                      -> Option<Vec<XorName>> {
        match routing_node.close_group(*data_name) {
            Ok(None) => {
                trace!("No longer a DM for {}", data_name);
                None
            }
            Ok(Some(close_group)) => Some(close_group),
            Err(error) => {
                error!("Failed to get close group: {:?} for {}", error, data_name);
                None
            }
        }
    }

    fn new_replicants_count(account: &Account) -> usize {
        let holder_count = account.data_holders
                                  .iter()
                                  .filter(|&(_, state)| *state == DataHolderState::Good)
                                  .count();
        REPLICANTS.saturating_sub(holder_count)
    }

    fn handle_churn_for_ongoing_puts(&mut self,
                                     routing_node: &RoutingNode,
                                     data_name: &XorName,
                                     message_id: &MessageId,
                                     account: &mut Account,
                                     close_group: &[XorName],
                                     mut new_replicants_count: usize)
                                     -> bool {
        let data = match self.data_cache.get(data_name) {
            Some(data) => data,
            None => return false,
        };

        // We have an entry in the `data_cache`, so replicate to new peers
        for group_member in close_group {
            if account.data_holders.contains_key(&group_member) {
                // This is already a holder - skip
                continue;
            }
            trace!("Replicating {} - sending Put to {}",
                   data_name,
                   group_member);
            let src = Authority::NaeManager(*data_name);
            let dst = Authority::NodeManager(*group_member);
            let _ = routing_node.send_put_request(src,
                                                  dst,
                                                  Data::Immutable(data.clone()),
                                                  *message_id);
            let _ = account.data_holders.insert(*group_member, DataHolderState::Pending);
            new_replicants_count -= 1;
            if new_replicants_count == 0 {
                return true;
            }
        }
        warn!("Failed to find a new close group member to replicate {} to",
              data_name);
        true
    }

    fn handle_churn_for_ongoing_gets(&mut self,
                                     data_name: &XorName,
                                     close_group: &[XorName])
                                     -> bool {
        if let Some(mut metadata) = self.ongoing_gets.get_mut(&data_name) {
            trace!("Already getting {} - {:?}", data_name, metadata);
            // Remove any holders which no longer belong in the cache entry
            let lost_holders =
                metadata.data_holders
                        .iter()
                        .filter_map(|(pmid_name, _)| {
                            if close_group.get(GROUP_SIZE - 1).into_iter().all(|name| {
                                xor_name::closer_to_target_or_equal(pmid_name, name, data_name)
                            }) {
                                None
                            } else {
                                Some(*pmid_name)
                            }
                        })
                        .collect_vec();
            for lost_holder in lost_holders {
                let _ = metadata.data_holders.remove(&lost_holder);
            }
            trace!("Updated ongoing get for {} to {:?}", data_name, metadata);
            true
        } else {
            false
        }
    }

    fn send_refresh(&self,
                    routing_node: &RoutingNode,
                    data_name: &XorName,
                    account: &Account,
                    message_id: &MessageId) {
        let src = Authority::NaeManager(*data_name);
        let refresh = Refresh::new(data_name,
                                   RefreshValue::ImmutableDataManagerAccount(account.clone()));
        if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
            trace!("ImmutableDataManager sending refresh for account {:?}",
                   src.name());
            let _ = routing_node.send_refresh_request(src.clone(),
                                                      src.clone(),
                                                      serialised_refresh,
                                                      *message_id);
        }
    }

    fn check_and_replicate_after_get(&mut self,
                                     routing_node: &RoutingNode,
                                     data_name: &XorName,
                                     message_id: &MessageId)
                                     -> Result<(), InternalError> {
        let mut finished = false;
        let mut new_data_holders = Vec::<XorName>::new();
        if let Some(metadata) = self.ongoing_gets.get_mut(&data_name) {
            // Count the good holders, but just return from this function if any queried holders
            // haven't responded yet
            let mut good_holder_count = 0;
            for (_, state) in &metadata.data_holders {
                match *state {
                    DataHolderState::Pending => return Ok(()),
                    DataHolderState::Good => good_holder_count += 1,
                    DataHolderState::Failed => (),
                }
            }
            trace!("Have {} good holders for {}", good_holder_count, data_name);

            if good_holder_count >= REPLICANTS {
                // We can now delete this cached get request with no need for further action
                finished = true;
            } else if let Some(ref data) = metadata.data {
                assert_eq!(*data_name, data.name());
                // Put to new close peers and delete this cached get request
                new_data_holders = try!(Self::replicate_after_get(routing_node,
                                                                  data,
                                                                  &metadata.data_holders,
                                                                  message_id));
                finished = true;
            } else {
                // Recover the data from backup and/or sacrificial locations
                Self::recover_from_other_locations(routing_node, metadata, data_name, message_id);
            }
        } else {
            warn!("Failed to find metadata for check_and_replicate_after_get of {}",
                  data_name);
        }

        if finished {
            let _ = self.ongoing_gets.remove(data_name);
        }

        if !new_data_holders.is_empty() {
            trace!("Replicating {} - new holders: {:?}",
                   data_name,
                   new_data_holders);
            if let Some(account) = self.accounts.get_mut(data_name) {
                trace!("Replicating {} - account before: {:?}", data_name, account);
                for new_holder in new_data_holders {
                    let _ = account.data_holders.insert(new_holder, DataHolderState::Pending);
                }
                trace!("Replicating {} - account after:  {:?}", data_name, account);
            }
        }

        Ok(())
    }

    fn replicate_after_get(routing_node: &RoutingNode,
                           data: &ImmutableData,
                           queried_data_holders: &HashMap<XorName, DataHolderState>,
                           message_id: &MessageId)
                           -> Result<Vec<XorName>, InternalError> {
        let mut good_nodes = HashSet::<XorName>::new();
        let mut nodes_to_exclude = HashSet::<XorName>::new();
        for (name, state) in queried_data_holders {
            match *state {
                DataHolderState::Good => {
                    let _ = good_nodes.insert(*name);
                    let _ = nodes_to_exclude.insert(*name);
                }
                DataHolderState::Failed => {
                    let _ = nodes_to_exclude.insert(*name);
                }
                DataHolderState::Pending => unreachable!(),
            }
        }
        let data_name = data.name();
        trace!("Replicating {} - good nodes: {:?}", data_name, good_nodes);
        trace!("Replicating {} - nodes to be excluded: {:?}",
               data_name,
               nodes_to_exclude);
        let target_data_holders = match try!(routing_node.close_group(data_name)) {
            Some(target_data_holders) => {
                target_data_holders.into_iter()
                                   .filter(|elt| !nodes_to_exclude.contains(elt))
                                   .take(REPLICANTS - good_nodes.len())
                                   .collect_vec()
            }
            None => return Err(InternalError::NotInCloseGroup),
        };

        trace!("Replicating {} - target nodes: {:?}",
               data_name,
               target_data_holders);
        for new_pmid_name in &target_data_holders {
            trace!("Replicating {} - sending Put to {}",
                   data_name,
                   new_pmid_name);
            let src = Authority::NaeManager(data_name);
            let dst = Authority::NodeManager(*new_pmid_name);
            let _ = routing_node.send_put_request(src,
                                                  dst,
                                                  Data::Immutable(data.clone()),
                                                  *message_id);
        }
        Ok(target_data_holders)
    }

    fn recover_from_other_locations(routing_node: &RoutingNode,
                                    metadata: &mut MetadataForGetRequest,
                                    data_name: &XorName,
                                    message_id: &MessageId) {
        metadata.data_holders.clear();
        // If this Vault is a Backup or Sacrificial manager just return failure to any requesters
        // waiting for responses.
        match metadata.requested_data_type {
            ImmutableDataType::Backup |
            ImmutableDataType::Sacrificial => {
                Self::send_get_failures(routing_node, metadata);
            }
            _ => (),
        }
        metadata.send_get_requests(routing_node, data_name, *message_id);
    }

    fn send_get_failures(routing_node: &RoutingNode, metadata: &mut MetadataForGetRequest) {
        while let Some((original_message_id, request)) = metadata.requests.pop() {
            let src = request.dst.clone();
            let dst = request.src.clone();
            trace!("Sending GetFailure back to {:?}", dst);
            let error = GetError::NoSuchData;
            if let Ok(external_error_indicator) = serialisation::serialise(&error) {
                let _ = routing_node.send_get_failure(src,
                                                      dst,
                                                      request,
                                                      external_error_indicator,
                                                      original_message_id);
            }
        }
    }

    fn choose_initial_data_holders(&self,
                                   routing_node: &RoutingNode,
                                   _full_pmid_nodes: &HashSet<XorName>,
                                   data_name: &XorName)
                                   -> Result<Vec<XorName>, InternalError> {
        match try!(routing_node.close_group(*data_name)) {
            Some(mut target_data_holders) => {
                // target_data_holders.retain(|target| !full_pmid_nodes.contains(target));
                target_data_holders.truncate(REPLICANTS);
                Ok(target_data_holders)
            }
            None => Err(InternalError::NotInCloseGroup),
        }
    }
}

impl Default for ImmutableDataManager {
    fn default() -> ImmutableDataManager {
        ImmutableDataManager::new()
    }
}



#[cfg(test)]
#[cfg_attr(feature="clippy", allow(indexing_slicing))]
#[cfg(not(feature="use-mock-crust"))]
mod test {
    use super::*;

    use std::collections::HashSet;
    use std::mem;
    use std::sync::mpsc;

    use maidsafe_utilities::{log, serialisation};
    use rand::distributions::{IndependentSample, Range};
    use rand::{random, thread_rng};
    use routing::{Authority, Data, DataRequest, ImmutableData, ImmutableDataType, MessageId,
                  RequestContent, RequestMessage, ResponseContent, ResponseMessage};
    use safe_network_common::client_errors::GetError;
    use sodiumoxide::crypto::sign;
    use types::{Refresh, RefreshValue};
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;

    struct PutEnvironment {
        pub client_manager: Authority,
        pub im_data: ImmutableData,
        pub message_id: MessageId,
        pub incoming_request: RequestMessage,
        pub outgoing_requests: Vec<RequestMessage>,
        pub initial_holders: HashSet<DataHolder>,
    }

    struct GetEnvironment {
        pub client: Authority,
        pub message_id: MessageId,
        pub request: RequestMessage,
    }

    struct Environment {
        pub routing: RoutingNode,
        pub immutable_data_manager: ImmutableDataManager,
    }

    impl Environment {
        pub fn new() -> Environment {
            let _ = log::init(false);
            let env = Environment {
                routing: unwrap_result!(RoutingNode::new(mpsc::channel().0, false)),
                immutable_data_manager: ImmutableDataManager::new(),
            };
            env
        }

        pub fn get_close_data(&self) -> ImmutableData {
            loop {
                let im_data = ImmutableData::new(ImmutableDataType::Normal,
                                                 generate_random_vec_u8(1024));
                if let Ok(Some(_)) = self.routing.close_group(im_data.name()) {
                    return im_data;
                }
            }
        }

        pub fn get_close_node(&self) -> XorName {
            loop {
                let name = random::<XorName>();
                if let Ok(Some(_)) = self.routing.close_group(name) {
                    return name;
                }
            }
        }

        fn lose_close_node(&self, target: &XorName) -> XorName {
            if let Ok(Some(close_group)) = self.routing.close_group(*target) {
                let mut rng = thread_rng();
                let range = Range::new(0, close_group.len());
                let our_name = if let Ok(ref name) = self.routing.name() {
                    *name
                } else {
                    unreachable!()
                };
                loop {
                    let index = range.ind_sample(&mut rng);
                    if close_group[index] != our_name {
                        return close_group[index];
                    }
                }
            } else {
                random::<XorName>()
            }
        }

        pub fn put_im_data(&mut self) -> PutEnvironment {
            let im_data = self.get_close_data();
            let message_id = MessageId::new();
            let content = RequestContent::Put(Data::Immutable(im_data.clone()), message_id);
            let client_manager = Authority::ClientManager(random());
            let client_request = RequestMessage {
                src: client_manager.clone(),
                dst: Authority::NaeManager(im_data.name()),
                content: content.clone(),
            };
            let full_pmid_nodes = HashSet::new();
            unwrap_result!(self.immutable_data_manager
                               .handle_put(&self.routing, &full_pmid_nodes, &client_request));
            let outgoing_requests = self.routing.put_requests_given();
            assert_eq!(outgoing_requests.len(), REPLICANTS + 2);
            let initial_holders = outgoing_requests.iter()
                                                   .map(|put_request| {
                                                       DataHolder::Pending(put_request.dst
                                                                                      .name()
                                                                                      .clone())
                                                   })
                                                   .take(REPLICANTS)
                                                   .collect();
            PutEnvironment {
                client_manager: client_manager,
                im_data: im_data,
                message_id: message_id,
                incoming_request: client_request,
                outgoing_requests: outgoing_requests,
                initial_holders: initial_holders,
            }
        }

        pub fn get_im_data(&mut self, data_name: XorName) -> GetEnvironment {
            let message_id = MessageId::new();
            let content = RequestContent::Get(DataRequest::Immutable(data_name.clone(),
                                                                     ImmutableDataType::Normal),
                                              message_id);
            let keys = sign::gen_keypair();
            let from = random();
            let client = Authority::Client {
                client_key: keys.0,
                peer_id: random(),
                proxy_node_name: from,
            };
            let request = RequestMessage {
                src: client.clone(),
                dst: Authority::NaeManager(data_name.clone()),
                content: content.clone(),
            };
            let _ = self.immutable_data_manager.handle_get(&self.routing, &request);
            GetEnvironment {
                client: client,
                message_id: message_id,
                request: request,
            }
        }
    }

    #[test]
    fn handle_put() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        for (index, req) in put_env.outgoing_requests.iter().enumerate() {
            assert_eq!(req.src, Authority::NaeManager(put_env.im_data.name()));
            if index < REPLICANTS {
                if let Authority::NodeManager(_) = req.dst {} else {
                    panic!()
                }
                assert_eq!(req.content,
                           RequestContent::Put(Data::Immutable(put_env.im_data.clone()),
                                               put_env.message_id.clone()));
            } else if index == REPLICANTS {
                let backup = ImmutableData::new(ImmutableDataType::Backup,
                                                put_env.im_data.value().clone());
                assert_eq!(req.dst, Authority::NaeManager(backup.name()));
                assert_eq!(req.content,
                           RequestContent::Put(Data::Immutable(backup), put_env.message_id));
            } else {
                let sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial,
                                                     put_env.im_data.value().clone());
                assert_eq!(req.dst, Authority::NaeManager(sacrificial.name()));
                assert_eq!(req.content,
                           RequestContent::Put(Data::Immutable(sacrificial), put_env.message_id));
            }
        }
        let put_successes = env.routing.put_successes_given();
        assert_eq!(put_successes.len(), 1);
        assert_eq!(put_successes[0].content,
                   ResponseContent::PutSuccess(put_env.im_data.name(), put_env.message_id));
        assert_eq!(put_env.client_manager, put_successes[0].dst);
        assert_eq!(Authority::NaeManager(put_env.im_data.name()),
                   put_successes[0].src);
    }

    #[test]
    fn get_non_existing_data() {
        let mut env = Environment::new();
        let im_data = env.get_close_data();
        let get_env = env.get_im_data(im_data.name());
        assert!(env.routing.get_requests_given().is_empty());
        assert!(env.routing.get_successes_given().is_empty());
        let get_failure = env.routing.get_failures_given();
        assert_eq!(get_failure.len(), 1);
        if let ResponseContent::GetFailure { ref external_error_indicator, ref id, .. } =
               get_failure[0].content.clone() {
            assert_eq!(get_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise(external_error_indicator));
            assert_eq!(GetError::NoSuchData, parsed_error);
        } else {
            panic!("Received unexpected response {:?}", get_failure[0]);
        }
        assert_eq!(get_env.client, get_failure[0].dst);
        assert_eq!(Authority::NaeManager(im_data.name()), get_failure[0].src);
    }

    #[test]
    fn get_immediately_after_put() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();

        let get_env = env.get_im_data(put_env.im_data.name());
        assert!(env.routing.get_requests_given().is_empty());
        assert!(env.routing.get_failures_given().is_empty());
        let get_success = env.routing.get_successes_given();
        assert_eq!(get_success.len(), 1);
        if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, id), .. } =
               get_success[0].clone() {
            assert_eq!(Data::Immutable(put_env.im_data.clone()), response_data);
            assert_eq!(get_env.message_id, id);
        } else {
            panic!("Received unexpected response {:?}", get_success[0]);
        }
    }

    #[test]
    fn get_after_put_success() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        for data_holder in &put_env.initial_holders {
            let _ = env.immutable_data_manager
                       .handle_put_success(data_holder.name(), &put_env.im_data.name());
        }

        let get_env = env.get_im_data(put_env.im_data.name());
        assert!(env.routing.get_successes_given().is_empty());
        assert!(env.routing.get_failures_given().is_empty());
        let get_requests = env.routing.get_requests_given();
        assert_eq!(get_requests.len(), REPLICANTS);
        for get_request in &get_requests {
            if let RequestContent::Get(data_request, message_id) = get_request.content.clone() {
                assert_eq!(put_env.im_data.name(), data_request.name());
                assert_eq!(get_env.message_id, message_id);
            } else {
                panic!("Received unexpected request {:?}", get_request);
            }
            assert_eq!(Authority::NaeManager(put_env.im_data.name()),
                       get_request.src);
            assert!(put_env.initial_holders
                           .contains(&DataHolder::Pending(*get_request.dst.name())));
        }
    }

    #[test]
    fn handle_put_failure() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        let mut current_put_request_count = put_env.outgoing_requests.len();
        let mut current_holders = put_env.initial_holders.clone();
        for data_holder in &put_env.initial_holders {
            let _ = env.immutable_data_manager
                       .handle_put_failure(&env.routing,
                                           data_holder.name(),
                                           &put_env.im_data,
                                           &put_env.message_id);
            let put_requests = env.routing.put_requests_given();
            let last_put_request = unwrap_option!(put_requests.last(), "");
            assert_eq!(put_requests.len(), current_put_request_count + 1);
            assert_eq!(last_put_request.src,
                       Authority::NaeManager(put_env.im_data.name()));
            assert_eq!(last_put_request.content,
                       RequestContent::Put(Data::Immutable(put_env.im_data.clone()),
                                           put_env.message_id.clone()));
            let new_holder = DataHolder::Pending(last_put_request.dst.name().clone());
            assert!(!current_holders.contains(&new_holder));
            current_put_request_count += 1;
            current_holders.insert(new_holder);
        }
    }

    #[test]
    fn handle_get_failure() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        for data_holder in &put_env.initial_holders {
            let _ = env.immutable_data_manager
                       .handle_put_success(data_holder.name(), &put_env.im_data.name());
        }

        let get_env = env.get_im_data(put_env.im_data.name());
        let mut get_requests = env.routing.get_requests_given();
        assert_eq!(get_requests.len(), REPLICANTS);

        // The first holder responds with failure - no further Puts or Gets triggered
        {
            let get_request = unwrap_option!(get_requests.first(), "");
            unwrap_result!(env.immutable_data_manager.handle_get_failure(&env.routing,
                                                                         get_request.dst.name(),
                                                                         &get_env.message_id,
                                                                         &get_request,
                                                                         &[]));
            assert_eq!(env.routing.put_requests_given().len(), REPLICANTS + 2);
            assert_eq!(env.routing.get_requests_given().len(), REPLICANTS);
            assert!(env.routing.get_successes_given().is_empty());
            assert!(env.routing.get_failures_given().is_empty());
        }

        // The second holder responds with failure - should trigger Gets from Backup and Sacrificial
        // DMs
        {
            let get_request = unwrap_option!(get_requests.get(1), "");
            unwrap_result!(env.immutable_data_manager.handle_get_failure(&env.routing,
                                                                         get_request.dst.name(),
                                                                         &get_env.message_id,
                                                                         &get_request,
                                                                         &[]));
        }
        assert_eq!(env.routing.put_requests_given().len(), REPLICANTS + 2);
        assert!(env.routing.get_successes_given().is_empty());
        assert!(env.routing.get_failures_given().is_empty());
        get_requests = env.routing.get_requests_given();
        assert_eq!(get_requests.len(), REPLICANTS + 2);

        let backup_get_request = unwrap_option!(get_requests.get(REPLICANTS), "");
        let backup = ImmutableData::new(ImmutableDataType::Backup, put_env.im_data.value().clone());
        assert_eq!(backup_get_request.dst, Authority::NaeManager(backup.name()));
        let mut expected_message_id = MessageId::increment_first_byte(&get_env.message_id);
        assert_eq!(backup_get_request.content,
                   RequestContent::Get(DataRequest::Immutable(backup.name(),
                                                              ImmutableDataType::Backup),
                                       expected_message_id));

        let sacrificial_get_request = unwrap_option!(get_requests.last(), "");
        let sacrificial = ImmutableData::new(ImmutableDataType::Sacrificial,
                                             put_env.im_data.value().clone());
        assert_eq!(sacrificial_get_request.dst,
                   Authority::NaeManager(sacrificial.name()));
        expected_message_id = MessageId::increment_first_byte(&expected_message_id);
        assert_eq!(sacrificial_get_request.content,
                   RequestContent::Get(DataRequest::Immutable(sacrificial.name(),
                                                              ImmutableDataType::Sacrificial),
                                       expected_message_id));

        // The Sacrificial holder responds with failure - should trigger no further messages
        unwrap_result!(env.immutable_data_manager
                          .handle_get_from_other_location_failure(&env.routing,
                                                                  &sacrificial_get_request));
        assert_eq!(env.routing.put_requests_given().len(), REPLICANTS + 2);
        assert_eq!(env.routing.get_requests_given().len(), REPLICANTS + 2);
        assert!(env.routing.get_successes_given().is_empty());
        assert!(env.routing.get_failures_given().is_empty());

        // The Backup holder responds with failure - should trigger failure response to Client since
        // the original request was for Normal data
        unwrap_result!(env.immutable_data_manager
                          .handle_get_from_other_location_failure(&env.routing,
                                                                  &backup_get_request));
        assert_eq!(env.routing.put_requests_given().len(), REPLICANTS + 2);
        assert_eq!(env.routing.get_requests_given().len(), REPLICANTS + 2);
        assert!(env.routing.get_successes_given().is_empty());

        let get_failures = env.routing.get_failures_given();
        assert_eq!(get_failures.len(), 1);
        let get_failure = unwrap_option!(get_failures.first(), "");
        if let ResponseContent::GetFailure { ref external_error_indicator, ref id, .. } =
               get_failure.content.clone() {
            assert_eq!(get_env.message_id, *id);
            let parsed_error = unwrap_result!(serialisation::deserialise(external_error_indicator));
            if let GetError::NoSuchData = parsed_error {} else {
                panic!("Received unexpected external_error_indicator with parsed error as {:?}",
                       parsed_error);
            }
        } else {
            panic!("Received unexpected response {:?}", get_failure);
        }
        assert_eq!(get_env.client, get_failure.dst);
        assert_eq!(Authority::NaeManager(put_env.im_data.name()),
                   get_failure.src);
    }

    #[test]
    fn handle_get_success() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        for data_holder in &put_env.initial_holders {
            let _ = env.immutable_data_manager
                       .handle_put_success(data_holder.name(), &put_env.im_data.name());
        }

        let get_env = env.get_im_data(put_env.im_data.name());
        let get_requests = env.routing.get_requests_given();
        assert_eq!(get_requests.len(), REPLICANTS);
        let mut success_count = 0;
        for get_request in &get_requests {
            let response = ResponseMessage {
                src: get_request.dst.clone(),
                dst: get_request.src.clone(),
                content: ResponseContent::GetSuccess(Data::Immutable(put_env.im_data.clone()),
                                                     get_env.message_id),
            };
            let _ = env.immutable_data_manager.handle_get_success(&env.routing, &response);
            success_count += 1;
            assert_eq!(env.routing.put_requests_given().len(), REPLICANTS + 2);
            assert_eq!(env.routing.get_requests_given().len(), REPLICANTS);
            assert!(env.routing.get_failures_given().is_empty());
            if success_count == 1 {
                let get_success = env.routing.get_successes_given();
                assert_eq!(get_success.len(), 1);
                if let ResponseMessage {
                    content: ResponseContent::GetSuccess(response_data, id),
                    ..
                } = get_success[0].clone() {
                    assert_eq!(Data::Immutable(put_env.im_data.clone()), response_data);
                    assert_eq!(get_env.message_id, id);
                } else {
                    panic!("Received unexpected response {:?}", get_success[0]);
                }
            } else {
                assert_eq!(env.routing.get_successes_given().len(), 1);
            }
        }
    }

    #[test]
    fn handle_refresh() {
        let mut env = Environment::new();
        let data = env.get_close_data();
        let mut data_holders: HashSet<DataHolder> = HashSet::new();
        for _ in 0..REPLICANTS {
            data_holders.insert(DataHolder::Good(env.get_close_node()));
        }
        let _ = env.immutable_data_manager.handle_refresh(data.name(),
                                                          Account::new(&ImmutableDataType::Normal,
                                                                       data_holders.clone()));
        let _get_env = env.get_im_data(data.name());
        let get_requests = env.routing.get_requests_given();
        assert_eq!(get_requests.len(), REPLICANTS);
        let pmid_nodes: Vec<XorName> = get_requests.into_iter()
                                                   .map(|request| *request.dst.name())
                                                   .collect();
        for data_holder in &data_holders {
            assert!(pmid_nodes.contains(data_holder.name()));
        }
    }

    #[test]
    fn churn_during_put() {
        let _ = ::maidsafe_utilities::log::init(false);
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        let mut account = Account::new(&ImmutableDataType::Normal, put_env.initial_holders.clone());
        let mut churn_count = 0;
        let mut replicants = REPLICANTS;
        let mut put_request_len = REPLICANTS + 2;
        let mut replication_put_message_id: MessageId;
        for data_holder in &put_env.initial_holders {
            churn_count += 1;
            if churn_count % 2 == 0 {
                let lost_node = env.lose_close_node(&put_env.im_data.name());
                let _ = env.immutable_data_manager
                           .handle_put_success(data_holder.name(), &put_env.im_data.name());
                env.routing.remove_node_from_routing_table(&lost_node);
                let _ = env.immutable_data_manager.handle_node_lost(&env.routing, &lost_node);
                let temp_account = mem::replace(&mut account,
                                                Account::new(&ImmutableDataType::Normal,
                                                             HashSet::new()));
                *account.data_holders_mut() =
                    temp_account.data_holders()
                                .into_iter()
                                .filter_map(|holder| {
                                    if *holder.name() == lost_node {
                                        if let DataHolder::Failed(_) = *holder {} else {
                                            replicants -= 1;
                                        }
                                        None
                                    } else if holder == data_holder {
                                        Some(DataHolder::Good(*holder.name()))
                                    } else {
                                        Some(*holder)
                                    }
                                })
                                .collect();
                replication_put_message_id = MessageId::from_lost_node(lost_node);
            } else {
                let new_node = env.get_close_node();
                let data = put_env.im_data.clone();
                let _ = env.immutable_data_manager.handle_put_failure(&env.routing,
                                                                      data_holder.name(),
                                                                      &data,
                                                                      &put_env.message_id);
                env.routing.add_node_into_routing_table(&new_node);
                let _ = env.immutable_data_manager.handle_node_added(&env.routing, &new_node);

                if let Ok(None) = env.routing.close_group(put_env.im_data.name()) {
                    // No longer being the DM of the data, expecting no refresh request
                    assert_eq!(env.routing.refresh_requests_given().len(), churn_count - 1);
                    return;
                }

                let temp_account = mem::replace(&mut account,
                                                Account::new(&ImmutableDataType::Normal,
                                                             HashSet::new()));
                *account.data_holders_mut() =
                    temp_account.data_holders()
                                .into_iter()
                                .filter_map(|holder| {
                                    if holder == data_holder {
                                        replicants -= 1;
                                        Some(DataHolder::Failed(*holder.name()))
                                    } else {
                                        Some(*holder)
                                    }
                                })
                                .collect();
                replication_put_message_id = put_env.message_id.clone();
            }
            if replicants < REPLICANTS {
                put_request_len += REPLICANTS - replicants;
                replicants += 1;
                let requests = env.routing.put_requests_given();
                assert_eq!(requests.len(), put_request_len);
                let put_request = unwrap_option!(requests.last(), "");
                assert_eq!(put_request.src,
                           Authority::NaeManager(put_env.im_data.name()));
                assert_eq!(put_request.content,
                           RequestContent::Put(Data::Immutable(put_env.im_data.clone()),
                                               replication_put_message_id));
                account.data_holders_mut().insert(DataHolder::Pending(*put_request.dst.name()));
            }

            let refreshs = env.routing.refresh_requests_given();
            assert_eq!(refreshs.len(), churn_count);
            let received_refresh = unwrap_option!(refreshs.last(), "");
            if let RequestContent::Refresh(received_serialised_refresh, _) =
                   received_refresh.content.clone() {
                let parsed_refresh = unwrap_result!(serialisation::deserialise::<Refresh>(
                        &received_serialised_refresh[..]));
                assert_eq!(parsed_refresh.value,
                           RefreshValue::ImmutableDataManagerAccount(account.clone()));
            } else {
                panic!("Received unexpected refresh {:?}", received_refresh);
            }
        }
    }

    #[test]
    fn churn_after_put() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        let mut good_holders = HashSet::new();
        for data_holder in &put_env.initial_holders {
            unwrap_result!(env.immutable_data_manager
                              .handle_put_success(data_holder.name(), &put_env.im_data.name()));
            good_holders.insert(DataHolder::Good(*data_holder.name()));
        }

        let mut account = Account::new(&ImmutableDataType::Normal, good_holders.clone());
        let mut churn_count = 0;
        let mut get_message_id: MessageId;
        let mut get_requests_len = 0;
        let mut replicants = REPLICANTS;
        for _data_holder in &good_holders {
            churn_count += 1;
            if churn_count % 2 == 0 {
                let lost_node = env.lose_close_node(&put_env.im_data.name());
                env.routing.remove_node_from_routing_table(&lost_node);
                let _ = env.immutable_data_manager.handle_node_lost(&env.routing, &lost_node);
                get_message_id = MessageId::from_lost_node(lost_node);

                let temp_account = mem::replace(&mut account,
                                                Account::new(&ImmutableDataType::Normal,
                                                             HashSet::new()));
                *account.data_holders_mut() = temp_account.data_holders()
                                                          .into_iter()
                                                          .filter_map(|holder| {
                                                              if *holder.name() == lost_node {
                                                                  replicants -= 1;
                                                                  None
                                                              } else {
                                                                  Some(*holder)
                                                              }
                                                          })
                                                          .collect();
            } else {
                let new_node = env.get_close_node();
                env.routing.add_node_into_routing_table(&new_node);
                let _ = env.immutable_data_manager.handle_node_added(&env.routing, &new_node);
                get_message_id = MessageId::from_added_node(new_node);

                if let Ok(None) = env.routing.close_group(put_env.im_data.name()) {
                    // No longer being the DM of the data, expecting no refresh request
                    assert_eq!(env.routing.refresh_requests_given().len(), churn_count - 1);
                    return;
                }
            }

            if replicants < REPLICANTS && get_requests_len == 0 {
                get_requests_len = account.data_holders().len();
                let get_requests = env.routing.get_requests_given();
                assert_eq!(get_requests.len(), get_requests_len);
                for get_request in &get_requests {
                    assert_eq!(get_request.src,
                               Authority::NaeManager(put_env.im_data.name()));
                    assert_eq!(get_request.content,
                               RequestContent::Get(DataRequest::Immutable(put_env.im_data.name(),
                                                                     ImmutableDataType::Normal),
                                                   get_message_id));
                }
            } else {
                assert_eq!(env.routing.get_requests_given().len(), get_requests_len);
            }

            let refreshs = env.routing.refresh_requests_given();
            assert_eq!(refreshs.len(), churn_count);
            let received_refresh = unwrap_option!(refreshs.last(), "");
            if let RequestContent::Refresh(received_serialised_refresh, _) =
                   received_refresh.content.clone() {
                let parsed_refresh = unwrap_result!(serialisation::deserialise::<Refresh>(
                        &received_serialised_refresh[..]));
                assert_eq!(parsed_refresh.value,
                           RefreshValue::ImmutableDataManagerAccount(account.clone()));
            } else {
                panic!("Received unexpected refresh {:?}", received_refresh);
            }
        }
    }

    #[test]
    fn churn_during_get() {
        let mut env = Environment::new();
        let put_env = env.put_im_data();
        let mut good_holders = HashSet::new();
        for data_holder in &put_env.initial_holders {
            unwrap_result!(env.immutable_data_manager
                              .handle_put_success(data_holder.name(), &put_env.im_data.name()));
            good_holders.insert(DataHolder::Good(*data_holder.name()));
        }

        let get_env = env.get_im_data(put_env.im_data.name());
        let get_requests = env.routing.get_requests_given();

        let mut account = Account::new(&ImmutableDataType::Normal, good_holders.clone());
        let mut churn_count = 0;
        let mut get_response_len = 0;
        for get_request in &get_requests {
            churn_count += 1;
            if churn_count % 2 == 0 {
                let lost_node = env.lose_close_node(&put_env.im_data.name());
                let get_response = ResponseMessage {
                    src: get_request.dst.clone(),
                    dst: get_request.src.clone(),
                    content: ResponseContent::GetSuccess(Data::Immutable(put_env.im_data.clone()),
                                                         get_env.message_id.clone()),
                };
                let _ = env.immutable_data_manager.handle_get_success(&env.routing, &get_response);
                env.routing.remove_node_from_routing_table(&lost_node);
                let _ = env.immutable_data_manager.handle_node_lost(&env.routing, &lost_node);
                let temp_account = mem::replace(&mut account,
                                                Account::new(&ImmutableDataType::Normal,
                                                             HashSet::new()));
                *account.data_holders_mut() = temp_account.data_holders()
                                                          .into_iter()
                                                          .filter_map(|holder| {
                                                              if *holder.name() == lost_node {
                                                                  None
                                                              } else {
                                                                  Some(*holder)
                                                              }
                                                          })
                                                          .collect();
                get_response_len = 1;
            } else {
                let new_node = env.get_close_node();
                let _ = env.immutable_data_manager.handle_get_failure(&env.routing,
                                                                      get_request.dst.name(),
                                                                      &get_env.message_id,
                                                                      &get_request,
                                                                      &[]);
                env.routing.add_node_into_routing_table(&new_node);
                let _ = env.immutable_data_manager.handle_node_added(&env.routing, &new_node);

                if let Ok(None) = env.routing.close_group(put_env.im_data.name()) {
                    // No longer being the DM of the data, expecting no refresh request
                    assert_eq!(env.routing.refresh_requests_given().len(), churn_count - 1);
                    return;
                }

                let temp_account = mem::replace(&mut account,
                                                Account::new(&ImmutableDataType::Normal,
                                                             HashSet::new()));
                *account.data_holders_mut() =
                    temp_account.data_holders()
                                .into_iter()
                                .filter_map(|holder| {
                                    if holder.name() == get_request.dst.name() {
                                        Some(DataHolder::Failed(*holder.name()))
                                    } else {
                                        Some(*holder)
                                    }
                                })
                                .collect();
            }
            if get_response_len == 1 {
                let get_success = env.routing.get_successes_given();
                assert_eq!(get_success.len(), 1);
                if let ResponseMessage { content: ResponseContent::GetSuccess(response_data,
                                                                              id), .. } =
                       get_success[0].clone() {
                    assert_eq!(Data::Immutable(put_env.im_data.clone()), response_data);
                    assert_eq!(get_env.message_id, id);
                } else {
                    panic!("Received unexpected response {:?}", get_success[0]);
                }
            }
            assert_eq!(env.routing.get_successes_given().len(), get_response_len);

            let refreshs = env.routing.refresh_requests_given();
            assert_eq!(refreshs.len(), churn_count);
            let received_refresh = unwrap_option!(refreshs.last(), "");
            if let RequestContent::Refresh(received_serialised_refresh, _) =
                   received_refresh.content.clone() {
                let parsed_refresh = unwrap_result!(serialisation::deserialise::<Refresh>(
                        &received_serialised_refresh[..]));
                if let RefreshValue::ImmutableDataManagerAccount(received_account) =
                       parsed_refresh.value.clone() {
                    if churn_count == REPLICANTS ||
                       env.immutable_data_manager.ongoing_gets.len() == 0 {
                        // A replication after ongoing_get get cleared picks up a new data_holder.
                        assert_eq!(env.routing.put_requests_given().len(), (2 * REPLICANTS) + 1);
                        assert!(received_account.data_holders().len() >= REPLICANTS);
                        return;
                    } else {
                        assert_eq!(received_account, account);
                    }
                } else {
                    panic!("Received unexpected refresh value {:?}", parsed_refresh);
                }
            } else {
                panic!("Received unexpected refresh {:?}", received_refresh);
            }
        }
    }
}
