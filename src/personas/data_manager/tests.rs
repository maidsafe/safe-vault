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

use super::*;
use QUORUM;
use maidsafe_utilities::SeededRng;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use mock_routing::RequestWrapper;
use rand::{self, Rng};
use routing::{Action, EntryActions, Request, Response, User};
use std::env;
use test_utils;
use vault::Refresh as VaultRefresh;

const CHUNK_STORE_CAPACITY: u64 = 1024 * 1024;
const CHUNK_STORE_DIR: &'static str = "test_safe_vault_chunk_store";

const TEST_TAG: u64 = 12345678;

#[test]
fn idata_basics() {
    let mut rng = SeededRng::new();

    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let data = test_utils::gen_immutable_data(10, &mut rng);
    let nae_manager = Authority::NaeManager(*data.name());

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    // Get non-existent data fails.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_get_idata(&mut node, client.into(), nae_manager, *data.name(), msg_id));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(
            message.response,
            Response::GetIData { res: Err(ClientError::NoSuchData), .. });

    // Put immutable data sends refresh to the NAE manager.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_put_idata(&mut node,
                                client_manager.into(),
                                nae_manager,
                                data.clone(),
                                msg_id));

    let message = unwrap!(node.sent_requests.remove(&msg_id));
    let refresh = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    assert_eq!(message.src, nae_manager);
    assert_eq!(message.dst, nae_manager);

    // Simulate receiving the refresh. This should result in the data being
    // put into the chunk store.
    unwrap!(dm.handle_group_refresh(&mut node, &refresh));

    // Get the data back and assert its the same data we put in originally.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_get_idata(&mut node, client.into(), nae_manager, *data.name(), msg_id));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    let retrieved_data =
        assert_match!(message.response, Response::GetIData { res: Ok(data), .. } => data);
    assert_eq!(retrieved_data, data);
}

#[test]
fn mdata_basics() {
    let mut rng = SeededRng::new();

    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key, &mut rng);
    let data_name = *data.name();
    let nae_manager = Authority::NaeManager(data_name);

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    // Attempt to list entries of non-existent data fails.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_list_mdata_entries(&mut node,
                                         client.into(),
                                         nae_manager,
                                         data_name,
                                         TEST_TAG,
                                         msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(
            message.response,
            Response::ListMDataEntries { res: Err(ClientError::NoSuchData), .. });

    // Put mutable data sends refresh to the NAE manager.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_put_mdata(&mut node,
                                client_manager.into(),
                                nae_manager,
                                data,
                                msg_id,
                                client_key));

    let message = unwrap!(node.sent_requests.remove(&msg_id));
    let refresh = assert_match!(message.request, Request::Refresh(payload, _) => payload);

    // Simulate receiving the refresh. This should result in the data being
    // put into the chunk store.
    unwrap!(dm.handle_group_refresh(&mut node, &refresh));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response, Response::PutMData { res: Ok(()), .. });

    // Now list the data entries - should successfuly respond with empty list.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_list_mdata_entries(&mut node,
                                         client.into(),
                                         nae_manager,
                                         data_name,
                                         TEST_TAG,
                                         msg_id));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    let entries = assert_match!(
            message.response,
            Response::ListMDataEntries { res: Ok(entries), .. } => entries);
    assert!(entries.is_empty());
}

#[test]
fn mdata_mutations() {
    let mut rng = SeededRng::new();

    let (client, client_key) = test_utils::gen_client_authority();
    let client_manager = test_utils::gen_client_manager_authority(client_key);

    let data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key, &mut rng);
    let data_name = *data.name();
    let nae_manager = Authority::NaeManager(data_name);

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    // Put the data.
    dm.put_into_chunk_store(data);

    // Initially, the entries should be empty.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_list_mdata_entries(&mut node,
                                         client.into(),
                                         nae_manager,
                                         data_name,
                                         TEST_TAG,
                                         msg_id));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    let entries = assert_match!(
            message.response,
            Response::ListMDataEntries { res: Ok(entries), .. } => entries);
    assert!(entries.is_empty());

    // Mutate the entries and simulate refresh.
    let key_0 = test_utils::gen_vec(10, &mut rng);
    let content_0 = test_utils::gen_vec(10, &mut rng);

    let key_1 = test_utils::gen_vec(10, &mut rng);
    let content_1 = test_utils::gen_vec(10, &mut rng);

    let actions = EntryActions::new()
        .ins(key_0.clone(), content_0.clone(), 0)
        .ins(key_1.clone(), content_1.clone(), 0)
        .into();
    let msg_id = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager.into(),
                                           nae_manager,
                                           data_name,
                                           TEST_TAG,
                                           actions,
                                           msg_id,
                                           client_key));

    let message = unwrap!(node.sent_requests.remove(&msg_id));
    let refresh = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &refresh));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    // The data should now contain the previously inserted two entries.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_list_mdata_entries(&mut node,
                                         client.into(),
                                         nae_manager,
                                         data_name,
                                         TEST_TAG,
                                         msg_id));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    let entries = assert_match!(
            message.response,
            Response::ListMDataEntries { res: Ok(entries), .. } => entries);

    let value_0 = Value {
        content: content_0,
        entry_version: 0,
    };
    let value_1 = Value {
        content: content_1,
        entry_version: 0,
    };

    assert_eq!(entries, vec![(key_0, value_0), (key_1, value_1)].into_iter().collect());
}

#[test]
fn mdata_change_owner() {
    let mut rng = SeededRng::new();

    let (_, client_key_0) = test_utils::gen_client_authority();
    let client_manager_0 = test_utils::gen_client_manager_authority(client_key_0);

    let data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key_0, &mut rng);
    let data_name = *data.name();
    let nae_manager = Authority::NaeManager(data_name);

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    // Put the data.
    dm.put_into_chunk_store(data);

    let (_, client_key_1) = test_utils::gen_client_authority();
    let client_manager_1 = test_utils::gen_client_manager_authority(client_key_1);

    let (_, client_key_2) = test_utils::gen_client_authority();

    // Attempt to change the owner by a non-owner fails.
    let mut new_owners = BTreeSet::new();
    let _ = new_owners.insert(client_key_2);

    let msg_id = MessageId::new();
    unwrap!(dm.handle_change_mdata_owner(&mut node,
                                         client_manager_1,
                                         nae_manager,
                                         data_name,
                                         TEST_TAG,
                                         new_owners.clone(),
                                         1,
                                         msg_id));
    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(
            message.response,
            Response::ChangeMDataOwner { res: Err(ClientError::AccessDenied), .. });

    dm.clear_cache();

    // Changing the owner by the current owner succeeds.
    let msg_id = MessageId::new();
    unwrap!(dm.handle_change_mdata_owner(&mut node,
                                         client_manager_0,
                                         nae_manager,
                                         data_name,
                                         TEST_TAG,
                                         new_owners,
                                         1,
                                         msg_id));
    let message = unwrap!(node.sent_requests.remove(&msg_id));
    let refresh = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &refresh));

    let message = unwrap!(node.sent_responses.remove(&msg_id));
    assert_match!(message.response, Response::ChangeMDataOwner { res: Ok(()), .. });
}

#[test]
fn handle_node_added() {
    let mut rng = SeededRng::new();

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    let new_node_name = rand::random();
    node.add_to_routing_table(new_node_name);

    let (_, client_key) = test_utils::gen_client_authority();
    let data0 = test_utils::gen_immutable_data(10, &mut rng);
    let data1 = test_utils::gen_mutable_data(TEST_TAG, 2, client_key, &mut rng);

    dm.put_into_chunk_store(data0.clone());
    dm.put_into_chunk_store(data1.clone());

    // Node receives NodeAdded event. It should send IDs of the data chunks it has
    // to the new node in a Refresh message.
    let rt = unwrap!(node.routing_table()).clone();
    unwrap!(dm.handle_node_added(&mut node, &new_node_name, &rt));

    assert_eq!(node.sent_requests.len(), 1);

    let (_, message) = unwrap!(node.sent_requests.drain().next());

    assert_eq!(message.src, Authority::ManagedNode(*unwrap!(node.id()).name()));
    assert_eq!(message.dst, Authority::ManagedNode(new_node_name));

    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    let refreshes: VaultRefresh = unwrap!(deserialise(&payload));
    let refreshes = assert_match!(refreshes, VaultRefresh::DataManager(refreshes) => refreshes);

    assert_eq!(refreshes.len(), 2);

    let check = refreshes
        .iter()
        .any(|refresh| match *refresh {
                 Refresh::Fragment(FragmentInfo::ImmutableData(ref name)) if name ==
                                                                             data0.name() => true,
                 _ => false,
             });
    assert!(check);

    let check = refreshes
        .iter()
        .any(|refresh| match *refresh {
                 Refresh::Chunk(MutableDataId(ref name, tag)) if name == data1.name() &&
                                                                 tag == data1.tag() => true,
                 _ => false,
             });
    assert!(check);

    // TODO: test also that the refresh contains fragments that the node doesn't
    // yet have, but needs.
}

// Test how immutable data is replicated from nodes that hold it to a newly
// joined node during churn.
//
// 1) New node X joins a group that holds an immutable data.
// 2) Existing nodes from the group send refresh to X with the info about the data.
// 3) X accumualtes the refresh and send request to retrieve the data
// 4) X receives response failure. Retries the request.
// 5) X receives response with wrong data. Retries the request.
// 6) X receives good response. It puts the data into the chunk store and sends
//    no more requests.
#[test]
fn idata_with_churn() {
    let mut rng = SeededRng::new();

    let (mut new_node, mut new_dm, old_node_names) = setup_churn(&mut rng);

    let data = test_utils::gen_immutable_data(10, &mut rng);

    let refresh = Refresh::Fragment(FragmentInfo::ImmutableData(*data.name()));
    let refresh_payload = unwrap!(serialise(&vec![refresh]));

    // New node receives the refresh message from one of the old nodes. The message
    // should not accumulate yet.
    unwrap!(new_dm.handle_serialised_refresh(&mut new_node, old_node_names[0], &refresh_payload));
    assert!(new_node.sent_requests.is_empty());

    // New node receives the refresh from at least QUORUM other nodes. The message
    // should now accumulate.
    for name in old_node_names.iter().skip(1).take(QUORUM - 1) {
        unwrap!(new_dm.handle_serialised_refresh(&mut new_node, *name, &refresh_payload));
    }

    // Helper function to verify the node sent the get request for a data with
    // the given name. Returns the message id and the destination authority name
    // of the request.
    fn verify_get_idata_request_sent(node: &mut RoutingNode, data_name: &XorName) -> XorName {
        assert_eq!(node.sent_requests.len(), 1);
        let (_, message) = unwrap!(node.sent_requests.drain().next());
        let name = assert_match!(message.request,
                                 Request::GetIData { name, .. } => name);
        assert_eq!(name, *data_name);
        assert_match!(message.dst, Authority::ManagedNode(name) => name)
    }

    let dst = verify_get_idata_request_sent(&mut new_node, data.name());

    // One of the nodes receives the above GetIData requests and sends the
    // response. We gloss over that here, as it's not the focus of the test.

    // Simulate failure of the GetIData request. New node should retry the request with
    // another holder.
    unwrap!(new_dm.handle_get_idata_failure(&mut new_node, dst));
    let dst = verify_get_idata_request_sent(&mut new_node, data.name());

    // Again, we gloss over the request handling and response sending here.

    // Simulate malicious node sending wrong data. New node should throw it away and
    // send another request to another holder.
    let bad_data = test_utils::gen_immutable_data(10, &mut rng);
    let bad_data_name = *bad_data.name();
    unwrap!(new_dm.handle_get_idata_success(&mut new_node, dst, bad_data));
    assert!(new_dm.get_from_chunk_store(&ImmutableDataId(bad_data_name)).is_none());
    let dst = verify_get_idata_request_sent(&mut new_node, data.name());

    // ...

    // New node now receives successful response. It should put the data into the chunk store.
    unwrap!(new_dm.handle_get_idata_success(&mut new_node, dst, data.clone()));
    assert!(new_dm.get_from_chunk_store(&data.id()).is_some());

    // New node should not send any more requests to the other holders, because it already
    // has everything it needs.
    assert!(new_node.sent_requests.is_empty());
}

// Test how mutable data with some entries is replicated from nodes that hold it
// to a newly joined node during churn.
//
// 1. New node X joins the group that holds the data.
// 2. Nodes from the group send refresh message to X. The message contains ID
//    of the mutable data.
// 3. X receives the refresh and sends requests for the data to all the nodes it
//    received the refresh from.
// 4. X receives success response to the requests. It accumulates the shell and
//    entries individually.
#[test]
fn mdata_with_churn() {
    let mut rng = SeededRng::new();

    let (_, client_key) = test_utils::gen_client_authority();
    let data = test_utils::gen_mutable_data(TEST_TAG, 2, client_key, &mut rng);

    let (mut new_node, mut new_dm, other_node_names) = setup_mdata_refresh(&data, &mut rng);

    // New node sends request for the mutable data to each member of the group.
    let (msg_id, data_id) = take_get_mdata_request(&mut new_node);
    assert_eq!(data_id, data.id());

    // New node receives responses for the above requests. It should accumulate the
    // data and put it into the chunk store.
    for node_name in &other_node_names {
        unwrap!(new_dm.handle_get_mdata_success(&mut new_node, *node_name, data.clone(), msg_id));
    }

    let stored_data = unwrap!(new_dm.get_from_chunk_store(&data.id()));
    assert_eq!(stored_data, data);

    // New node does not send any more requests, because it already has everything
    // it needs.
    assert!(new_node.sent_requests.is_empty());
}

// Same as `mdata_with_churn` except only a subset of the data entries accumulate.
#[test]
fn mdata_with_churn_with_partial_accumulation() {
    let mut rng = SeededRng::new();

    let (_, client_key) = test_utils::gen_client_authority();
    let data = test_utils::gen_mutable_data(TEST_TAG, 3, client_key, &mut rng);

    let (mut new_node, mut new_dm, other_node_names) = setup_mdata_refresh(&data, &mut rng);

    // New node should send request for the mutable data.
    let (msg_id, _) = take_get_mdata_request(&mut new_node);

    // The nodes form two groups - the data they respond with differs in some of the entries.
    // None of the groups reaches quorum for their data, but the nodes together do reach
    // quorum for the shell and some of the entries. Only the entries that reached
    // quorum are written to the chunk store.
    let mut entries = data.entries()
        .into_iter()
        .map(|(key, value)| (key.clone(), value.clone()));
    let (key0, value0) = unwrap!(entries.next());
    let (key1, value1) = unwrap!(entries.next());
    let (key2, value2) = unwrap!(entries.next());

    let mut partial_data0 = data.shell();
    assert!(partial_data0.mutate_entry_without_validation(key0, value0));
    assert!(partial_data0.mutate_entry_without_validation(key1.clone(), value1.clone()));

    let mut partial_data1 = data.shell();
    assert!(partial_data1.mutate_entry_without_validation(key1.clone(), value1.clone()));
    assert!(partial_data1.mutate_entry_without_validation(key2, value2));

    for node_name in other_node_names.iter().take(QUORUM - 1) {
        unwrap!(new_dm.handle_get_mdata_success(&mut new_node,
                                                *node_name,
                                                partial_data0.clone(),
                                                msg_id));
    }

    for node_name in other_node_names
            .iter()
            .skip(QUORUM - 1)
            .take(QUORUM - 1) {
        unwrap!(new_dm.handle_get_mdata_success(&mut new_node,
                                                *node_name,
                                                partial_data1.clone(),
                                                msg_id));
    }

    let stored_data = unwrap!(new_dm.get_from_chunk_store(&data.id()));
    assert_eq!(stored_data.shell(), data.shell());
    assert_eq!(stored_data.entries().len(), 1);
    assert_eq!(value1, *unwrap!(stored_data.get(&key1)));
}

// Same as `mdata_with_churn`, except entries now accumulate before shell.
#[test]
fn mdata_with_churn_with_entries_accumulating_before_shell() {
    let mut rng = SeededRng::new();

    let (_, client_key) = test_utils::gen_client_authority();
    let data = test_utils::gen_mutable_data(TEST_TAG, 1, client_key, &mut rng);

    let (mut new_node, mut new_dm, other_node_names) = setup_mdata_refresh(&data, &mut rng);

    // New node should send request for the mutable data.
    let (msg_id, _) = take_get_mdata_request(&mut new_node);

    // First QUORUM - 1 nodes respond with the correct data.
    for node_name in other_node_names.iter().take(QUORUM - 1) {
        unwrap!(new_dm.handle_get_mdata_success(&mut new_node, *node_name, data.clone(), msg_id));
    }

    // The next node responds with a data with the same entries but different shell.
    // The entries accumulate at this point, but not the shell.
    let mut data_with_bad_shell = data.clone();
    let (other_key, _) = sign::gen_keypair();
    assert!(data_with_bad_shell.change_owner_without_validation(other_key, 1));

    let node_name = unwrap!(other_node_names.get(QUORUM - 1));
    unwrap!(new_dm.handle_get_mdata_success(&mut new_node,
                                            *node_name,
                                            data_with_bad_shell,
                                            msg_id));

    // The remaining nodes send data with the correct shell but no entries.
    // The shell accumulates now and the entries are aleady accumulated.
    for node_name in other_node_names.iter().skip(QUORUM) {
        unwrap!(new_dm.handle_get_mdata_success(&mut new_node, *node_name, data.shell(), msg_id));
    }

    let stored_data = unwrap!(new_dm.get_from_chunk_store(&data.id()));
    assert_eq!(stored_data, data);
}

#[test]
fn mdata_non_conflicting_parallel_mutations() {
    let mut rng = SeededRng::new();

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    let (_, client_key_0) = test_utils::gen_client_authority();
    let client_manager_0 = test_utils::gen_client_manager_authority(client_key_0);

    let (_, client_key_1) = test_utils::gen_client_authority();
    let client_manager_1 = test_utils::gen_client_manager_authority(client_key_1);

    let mut data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key_0, &mut rng);
    unwrap!(data.set_user_permissions(User::Anyone,
                                      PermissionSet::new()
                                          .allow(Action::Insert)
                                          .allow(Action::Update)
                                          .allow(Action::Delete),
                                      1,
                                      client_key_0));

    dm.put_into_chunk_store(data.clone());
    let nae_manager = Authority::NaeManager(*data.name());

    // Issue two mutations in parallel, each touching different key. Both should be
    // accepted.
    let actions = EntryActions::new()
        .ins(b"key0".to_vec(), b"value 0".to_vec(), 0)
        .into();
    let msg_id_0 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_0.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions,
                                           msg_id_0,
                                           client_key_0));

    let actions = EntryActions::new()
        .ins(b"key1".to_vec(), b"value 1".to_vec(), 0)
        .into();
    let msg_id_1 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_1.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions,
                                           msg_id_1,
                                           client_key_1));

    let message = unwrap!(node.sent_requests.remove(&msg_id_0));
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &payload));

    let message = unwrap!(node.sent_requests.remove(&msg_id_1));
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &payload));

    let message = unwrap!(node.sent_responses.remove(&msg_id_0));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    let message = unwrap!(node.sent_responses.remove(&msg_id_1));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    let stored_data = unwrap!(dm.get_from_chunk_store(&data.id()));
    let value0 = unwrap!(stored_data.get(b"key0"));
    assert_eq!(&value0.content, b"value 0");
    assert_eq!(value0.entry_version, 0);

    let value1 = unwrap!(stored_data.get(b"key1"));
    assert_eq!(&value1.content, b"value 1");
    assert_eq!(value1.entry_version, 0);
}

#[test]
fn mdata_conflicting_parallel_mutations() {
    let mut rng = SeededRng::new();

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    let (_, client_key_0) = test_utils::gen_client_authority();
    let client_manager_0 = test_utils::gen_client_manager_authority(client_key_0);

    let (_, client_key_1) = test_utils::gen_client_authority();
    let client_manager_1 = test_utils::gen_client_manager_authority(client_key_1);

    let mut data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key_0, &mut rng);
    unwrap!(data.set_user_permissions(User::Anyone,
                                      PermissionSet::new()
                                          .allow(Action::Insert)
                                          .allow(Action::Update)
                                          .allow(Action::Delete),
                                      1,
                                      client_key_0));


    dm.put_into_chunk_store(data.clone());
    let nae_manager = Authority::NaeManager(*data.name());

    // Issue two mutations in parallel, both touching the same key. Only the first
    // one should result in group refresh being sent. The second one should be
    // rejected.
    let actions = EntryActions::new()
        .ins(b"key".to_vec(), b"value 0".to_vec(), 0)
        .into();
    let msg_id_0 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_0.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions,
                                           msg_id_0,
                                           client_key_0));

    let actions = EntryActions::new()
        .ins(b"key".to_vec(), b"value 1".to_vec(), 0)
        .into();
    let msg_id_1 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_1.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions,
                                           msg_id_1,
                                           client_key_1));

    let message = unwrap!(node.sent_requests.remove(&msg_id_0));
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);

    assert!(!node.sent_requests.contains_key(&msg_id_1));

    // After receiving the group refresh, the first mutation succeeds and the second
    // one is rejected.
    unwrap!(dm.handle_group_refresh(&mut node, &payload));

    let message = unwrap!(node.sent_responses.remove(&msg_id_0));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    let message = unwrap!(node.sent_responses.remove(&msg_id_1));
    assert_match!(message.response, Response::MutateMDataEntries { res: Err(_), .. });
}

#[test]
fn mdata_parallel_mutations_limits() {
    let mut rng = SeededRng::new();

    let mut node = RoutingNode::new();
    let mut dm = create_data_manager();

    let (_, client_key_0) = test_utils::gen_client_authority();
    let client_manager_0 = test_utils::gen_client_manager_authority(client_key_0);

    let (_, client_key_1) = test_utils::gen_client_authority();
    let client_manager_1 = test_utils::gen_client_manager_authority(client_key_1);

    let mut data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key_0, &mut rng);
    unwrap!(data.set_user_permissions(User::Anyone,
                                      PermissionSet::new()
                                          .allow(Action::Insert)
                                          .allow(Action::Update)
                                          .allow(Action::Delete),
                                      1,
                                      client_key_0));


    dm.put_into_chunk_store(data.clone());
    let nae_manager = Authority::NaeManager(*data.name());

    // Send two parallel, non-conflicting mutations, each inserting 25 entries.
    // As the data is initially empty, both should succeed.
    let mut actions = EntryActions::new();
    for i in 0..25 {
        actions = actions.ins(vec![0, i as u8], vec![], 0);
    }
    let msg_id_0 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_0.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions.into(),
                                           msg_id_0,
                                           client_key_0));

    let mut actions = EntryActions::new();
    for i in 0..25 {
        actions = actions.ins(vec![1, i as u8], vec![], 0);
    }
    let msg_id_1 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_1.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions.into(),
                                           msg_id_1,
                                           client_key_1));

    // Refresh both mutations.
    let message = unwrap!(node.sent_requests.remove(&msg_id_0));
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &payload));

    let message = unwrap!(node.sent_requests.remove(&msg_id_1));
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &payload));

    // Both requests should succeed.
    let message = unwrap!(node.sent_responses.remove(&msg_id_0));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    let message = unwrap!(node.sent_responses.remove(&msg_id_1));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    // Now send two more non-conflicting mutations. This time each inserting 15
    // entries. Because 2 * 15 = 30 is more than half the allowed remaining entries
    // (50 / 2 = 25), the second request should be rejected.
    let mut actions = EntryActions::new();
    for i in 0..15 {
        actions = actions.ins(vec![2, i as u8], vec![], 0);
    }
    let msg_id_0 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_0.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions.into(),
                                           msg_id_0,
                                           client_key_0));

    let mut actions = EntryActions::new();
    for i in 0..15 {
        actions = actions.ins(vec![3, i as u8], vec![], 0);
    }
    let msg_id_1 = MessageId::new();
    unwrap!(dm.handle_mutate_mdata_entries(&mut node,
                                           client_manager_1.into(),
                                           nae_manager,
                                           *data.name(),
                                           data.tag(),
                                           actions.into(),
                                           msg_id_1,
                                           client_key_1));

    // Only the first mutation should result in refresh being sent.
    let message = unwrap!(node.sent_requests.remove(&msg_id_0));
    let payload = assert_match!(message.request, Request::Refresh(payload, _) => payload);
    unwrap!(dm.handle_group_refresh(&mut node, &payload));

    assert!(!node.sent_requests.contains_key(&msg_id_1));

    let message = unwrap!(node.sent_responses.remove(&msg_id_0));
    assert_match!(message.response, Response::MutateMDataEntries { res: Ok(()), .. });

    let message = unwrap!(node.sent_responses.remove(&msg_id_1));
    assert_match!(message.response, Response::MutateMDataEntries { res: Err(_), .. });
}

fn create_data_manager() -> DataManager {
    let suffix: u64 = rand::random();
    let dir = format!("{}_{}", CHUNK_STORE_DIR, suffix);

    unwrap!(DataManager::new(env::temp_dir().join(dir), CHUNK_STORE_CAPACITY))
}

// Create and setup all the objects necessary for churn-related tests.
// Returns:
//   - new node (RoutingNode + DataManager),
//   - names of the rest of the nodes in the group.
fn setup_churn<R: Rng>(rng: &mut R) -> (RoutingNode, DataManager, Vec<XorName>) {
    let mut new_node = RoutingNode::new();
    let new_dm = create_data_manager();

    let other_node_names: Vec<_> = rng.gen_iter().take(GROUP_SIZE - 1).collect();

    for name in &other_node_names {
        new_node.add_to_routing_table(*name);
    }

    (new_node, new_dm, other_node_names)
}

// Create and setup all the objects necessary to test mutable data handling during
// churn:
//   - Create new node
//   - Simulate it receiving refresh messages and accumulate them.
//   - Returns the new RoutingNode and DataManager and the names of the rest of
//     the group.
fn setup_mdata_refresh<R: Rng>(data: &MutableData,
                               rng: &mut R)
                               -> (RoutingNode, DataManager, Vec<XorName>) {
    let (mut new_node, mut new_dm, other_node_names) = setup_churn(rng);

    let refresh = vec![Refresh::Chunk(data.id())];
    let refresh = unwrap!(serialise(&refresh));

    for name in &other_node_names {
        unwrap!(new_dm.handle_serialised_refresh(&mut new_node, *name, &refresh));
    }

    (new_node, new_dm, other_node_names)
}

// Removes and returns sent `GetMData` request.
fn take_get_mdata_request(node: &mut RoutingNode) -> (MessageId, MutableDataId) {
    let (msg_id, message) = take_request(node, |message| match message.request {
        Request::GetMData { .. } => true,
        _ => false,
    });

    let (name, tag) =
        assert_match!(message.request, Request::GetMData { name, tag, .. } => (name, tag));
    (msg_id, MutableDataId(name, tag))
}

// Removes and returns the sent request matching the given predicate.
fn take_request<F>(node: &mut RoutingNode, mut f: F) -> (MessageId, RequestWrapper)
    where F: FnMut(&RequestWrapper) -> bool
{
    let msg_id = node.sent_requests
        .iter()
        .filter_map(|(msg_id, message)| if f(message) { Some(*msg_id) } else { None })
        .next();
    let msg_id = unwrap!(msg_id);
    (msg_id, unwrap!(node.sent_requests.remove(&msg_id)))
}
