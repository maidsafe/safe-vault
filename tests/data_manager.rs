// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md

use fake_clock::FakeClock;
use rand::Rng;
use routing::{Action, Authority, BootstrapConfig, ClientError, EntryAction, EntryActions, Event,
              ImmutableData, MAX_MUTABLE_DATA_ENTRIES, MessageId, MutableData, PermissionSet,
              Response, User};
use routing::mock_crust::Network;
use rust_sodium::crypto::sign;
use safe_vault::{GROUP_SIZE, PENDING_WRITE_TIMEOUT_SECS, test_utils};
use safe_vault::mock_crust_detail::{self, Data, poll};
use safe_vault::mock_crust_detail::test_client::TestClient;
use safe_vault::mock_crust_detail::test_node::{self, TestNode};
use std::cmp;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const TEST_NET_SIZE: usize = 20;

#[test]
fn immutable_data_normal_flow() {
    let seed = None;
    let node_count = TEST_NET_SIZE;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = BootstrapConfig::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let data = test_utils::gen_immutable_data(10, &mut rng);
    unwrap!(client.put_idata_response(data.clone(), &mut nodes));

    let received_data = unwrap!(client.get_idata_response(*data.name(), &mut nodes));
    assert_eq!(received_data, data);

    // Putting the same data again is OK.
    unwrap!(client.put_idata_response(data, &mut nodes));
}

#[test]
fn immutable_data_error_flow() {
    let seed = None;
    let node_count = TEST_NET_SIZE;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = BootstrapConfig::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    // GetIData with non-existing data fails.
    let non_existing_name = rng.gen();
    assert_match!(client.get_idata_response(non_existing_name, &mut nodes),
                  Err(ClientError::NoSuchData));
}

#[test]
fn immutable_data_operations_with_churn_with_cache() {
    immutable_data_operations_with_churn(true);
}

#[test]
fn immutable_data_operations_with_churn_without_cache() {
    immutable_data_operations_with_churn(false);
}

fn immutable_data_operations_with_churn(use_cache: bool) {
    let seed = None;
    let iterations = test_utils::iterations();
    const DATA_COUNT: usize = 50;
    const DATA_PER_ITER: usize = 5;
    let node_count = TEST_NET_SIZE;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, use_cache);
    let config = BootstrapConfig::with_contacts(&[nodes[1].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut all_data = vec![];
    let mut event_count = 0;

    for i in 0..iterations {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());
        for _ in 0..(cmp::min(DATA_PER_ITER, DATA_COUNT - all_data.len())) {
            let data = test_utils::gen_immutable_data(10, &mut rng);
            trace!("Putting data {:?}.", data.name());
            let _ = client.put_idata(data.clone());
            all_data.push(Data::Immutable(data));
        }

        if nodes.len() <= GROUP_SIZE + 2 || !rng.gen_weighted_bool(4) {
            let index = rng.gen_range(2, nodes.len());
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index, use_cache);
        } else {
            let number = rng.gen_range(3, 4);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_index = rng.gen_range(2, nodes.len());
                trace!("Removing node {:?}", nodes[node_index].name());
                test_node::drop_node(&mut nodes, node_index);
            }
        }

        event_count += poll::nodes_and_client_with_resend(&mut nodes, &mut client);
        trace!("Processed {} events.", event_count);

        mock_crust_detail::check_data(all_data.clone(), &nodes);
        mock_crust_detail::verify_network_invariant_for_all_nodes(&nodes);
    }

    for data in &all_data {
        match *data {
            Data::Immutable(ref sent_data) => {
                let recovered_data = unwrap!(client.get_idata_response(*sent_data.name(),
                                                                       &mut nodes));
                assert_eq!(recovered_data, *sent_data);
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn mutable_data_normal_flow() {
    let seed = None;
    let node_count = TEST_NET_SIZE;
    let num_entries = 10;
    let num_entry_actions = 10;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = BootstrapConfig::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config.clone()));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    // Put mutable data
    let mut data =
        test_utils::gen_mutable_data(10000, num_entries, *client.signing_public_key(), &mut rng);
    unwrap!(client.put_mdata_response(data.clone(), &mut nodes));

    // Get the shell and entries and verify they are what we put it.
    let received_shell =
        unwrap!(client.get_mdata_shell_response(*data.name(), data.tag(), &mut nodes));
    let received_entries =
        unwrap!(client.list_mdata_entries_response(*data.name(), data.tag(), &mut nodes));
    assert_eq!(received_shell, data.shell());
    assert_eq!(received_entries, *data.entries());

    // Get the entries individually and verify they match.
    for (key, value) in data.entries() {
        let received_value = unwrap!(client.get_mdata_value_response(*data.name(),
                                                                     data.tag(),
                                                                     key.clone(),
                                                                     &mut nodes));
        assert_eq!(received_value, *value);
    }

    // Mutate and verify the data.
    let actions = test_utils::gen_mutable_data_entry_actions(&data, num_entry_actions, &mut rng);
    unwrap!(data.mutate_entries(actions.clone(), *client.signing_public_key()));
    unwrap!(client.mutate_mdata_entries_response(*data.name(), data.tag(), actions, &mut nodes));
    let received_entries =
        unwrap!(client.list_mdata_entries_response(*data.name(), data.tag(), &mut nodes));
    assert_eq!(received_entries, *data.entries());

    // Permissions are initially empty.
    let received_permissions =
        unwrap!(client.list_mdata_permissions_response(*data.name(), data.tag(), &mut nodes));
    assert!(received_permissions.is_empty());

    // Set some permissions and get them back to verify they are the same.
    let (app_key, _) = sign::gen_keypair();
    let app_user = User::Key(app_key);

    let any_permission_set = PermissionSet::new().allow(Action::Insert);
    let app_permission_set = PermissionSet::new()
        .allow(Action::Insert)
        .allow(Action::Update)
        .allow(Action::Delete);

    unwrap!(data.set_user_permissions(User::Anyone,
                                      any_permission_set,
                                      1,
                                      *client.signing_public_key()));
    unwrap!(client.set_mdata_user_permissions_response(*data.name(),
                                                       data.tag(),
                                                       User::Anyone,
                                                       any_permission_set,
                                                       1,
                                                       &mut nodes));

    unwrap!(data.set_user_permissions(app_user,
                                      app_permission_set,
                                      2,
                                      *client.signing_public_key()));
    unwrap!(client.set_mdata_user_permissions_response(*data.name(),
                                                       data.tag(),
                                                       app_user,
                                                       app_permission_set,
                                                       2,
                                                       &mut nodes));

    let received_permissions =
        unwrap!(client.list_mdata_permissions_response(*data.name(), data.tag(), &mut nodes));
    assert_eq!(received_permissions, *data.permissions());

    let received_permission_set =
        unwrap!(client.list_mdata_user_permissions_response(*data.name(),
                                                            data.tag(),
                                                            User::Anyone,
                                                            &mut nodes));
    assert_eq!(received_permission_set, any_permission_set);

    let received_permission_set =
        unwrap!(client.list_mdata_user_permissions_response(*data.name(),
                                                            data.tag(),
                                                            User::Key(app_key),
                                                            &mut nodes));
    assert_eq!(received_permission_set, app_permission_set);

    // Modify the permissions and get them back to verify.
    let app_permission_set = PermissionSet::new()
        .allow(Action::Insert)
        .allow(Action::Update);

    unwrap!(data.set_user_permissions(app_user,
                                      app_permission_set,
                                      3,
                                      *client.signing_public_key()));
    unwrap!(client.set_mdata_user_permissions_response(*data.name(),
                                                       data.tag(),
                                                       app_user,
                                                       app_permission_set,
                                                       3,
                                                       &mut nodes));

    unwrap!(data.del_user_permissions(&User::Anyone, 4, *client.signing_public_key()));
    unwrap!(client.del_mdata_user_permissions_response(*data.name(),
                                                       data.tag(),
                                                       User::Anyone,
                                                       4,
                                                       &mut nodes));

    let received_permissions =
        unwrap!(client.list_mdata_permissions_response(*data.name(), data.tag(), &mut nodes));
    assert_eq!(received_permissions, *data.permissions());

    // Create an app.
    let mut app = TestClient::new(&network, Some(config));
    app.set_client_manager(*client.name());
    app.ensure_connected(&mut nodes);

    // Authorise the app and grant it some permissions.
    let (_, version) = unwrap!(client.list_auth_keys_and_version_response(&mut nodes));
    unwrap!(client.ins_auth_key_response(*app.signing_public_key(), version + 1, &mut nodes));

    let user = User::Key(*app.signing_public_key());
    let permission_set = PermissionSet::new()
        .allow(Action::Insert)
        .allow(Action::Update)
        .allow(Action::Delete);
    unwrap!(data.set_user_permissions(user, permission_set, 5, *client.signing_public_key()));
    unwrap!(client.set_mdata_user_permissions_response(*data.name(),
                                                       data.tag(),
                                                       user,
                                                       permission_set,
                                                       5,
                                                       &mut nodes));

    // Mutate the data by the app.
    let actions = test_utils::gen_mutable_data_entry_actions(&data, 2, &mut rng);
    unwrap!(data.mutate_entries(actions.clone(), *app.signing_public_key()));
    unwrap!(app.mutate_mdata_entries_response(*data.name(), data.tag(), actions, &mut nodes));
    let received_entries =
        unwrap!(client.list_mdata_entries_response(*data.name(), data.tag(), &mut nodes));
    assert_eq!(received_entries, *data.entries());

    // Change the owner and verify it by getting the shell.
    let new_owners = owner_keys(*app.signing_public_key());
    unwrap!(client.change_mdata_owner_response(*data.name(),
                                               data.tag(),
                                               new_owners.clone(),
                                               6,
                                               &mut nodes));

    let received_shell =
        unwrap!(client.get_mdata_shell_response(*data.name(), data.tag(), &mut nodes));
    assert_eq!(*received_shell.owners(), new_owners);
}

#[test]
fn mutable_data_error_flow() {
    let seed = None;
    let node_count = TEST_NET_SIZE;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = BootstrapConfig::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config.clone()));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut data = test_utils::gen_mutable_data(10000, 0, *client.signing_public_key(), &mut rng);
    unwrap!(client.put_mdata_response(data.clone(), &mut nodes));

    // Putting to the same data fails.
    let owners = owner_keys(*client.signing_public_key());
    let bad_data = unwrap!(MutableData::new(*data.name(),
                                            data.tag(),
                                            Default::default(),
                                            Default::default(),
                                            owners));

    assert_match!(client.put_mdata_response(bad_data, &mut nodes),
                  Err(ClientError::DataExists));

    // Requests to a non-existing data fail.
    let mut non_existing_name;
    loop {
        non_existing_name = rng.gen();
        if non_existing_name != *data.name() {
            break;
        }
    }

    assert_match!(client.get_mdata_shell_response(non_existing_name, 10000, &mut nodes),
                  Err(ClientError::NoSuchData));

    assert_match!(client.get_mdata_version_response(non_existing_name, 10000, &mut nodes),
                  Err(ClientError::NoSuchData));

    assert_match!(client.list_mdata_entries_response(non_existing_name, 10000, &mut nodes),
                  Err(ClientError::NoSuchData));

    let key = b"key".to_vec();
    assert_match!(client.get_mdata_value_response(non_existing_name, 10000, key, &mut nodes),
                  Err(ClientError::NoSuchData));

    assert_match!(client.list_mdata_permissions_response(non_existing_name, 10000, &mut nodes),
                  Err(ClientError::NoSuchData));

    let (app_key, _) = sign::gen_keypair();
    assert_match!(client.list_mdata_user_permissions_response(non_existing_name,
                                                              10000,
                                                              User::Key(app_key),
                                                              &mut nodes),
                  Err(ClientError::NoSuchData));

    let actions = test_utils::gen_mutable_data_entry_actions(&data, 1, &mut rng);
    assert_match!(client.mutate_mdata_entries_response(non_existing_name,
                                                       10000,
                                                       actions,
                                                       &mut nodes),
                  Err(ClientError::NoSuchData));

    let permission_set = PermissionSet::new().allow(Action::Insert);
    assert_match!(client.set_mdata_user_permissions_response(non_existing_name,
                                                             10000,
                                                             User::Key(app_key),
                                                             permission_set,
                                                             1,
                                                             &mut nodes),
                  Err(ClientError::NoSuchData));

    assert_match!(client.del_mdata_user_permissions_response(non_existing_name,
                                                             10000,
                                                             User::Key(app_key),
                                                             1,
                                                             &mut nodes),
                  Err(ClientError::NoSuchData));

    let new_owners = owner_keys(app_key);
    assert_match!(client.change_mdata_owner_response(non_existing_name,
                                                     10000,
                                                     new_owners,
                                                     1,
                                                     &mut nodes),
                  Err(ClientError::NoSuchData));

    // Getting non-existing entry fails.
    let non_existing_key = b"missing".to_vec();
    assert_match!(client.get_mdata_value_response(*data.name(),
                                                  data.tag(),
                                                  non_existing_key.clone(),
                                                  &mut nodes),
                  Err(ClientError::NoSuchEntry));

    // Mutating with too many entries fails.
    let actions = test_utils::gen_mutable_data_entry_actions(&data,
                                                             MAX_MUTABLE_DATA_ENTRIES as usize + 1,
                                                             &mut rng);
    assert_match!(client.mutate_mdata_entries_response(*data.name(), 10000, actions, &mut nodes),
                  Err(ClientError::TooManyEntries));

    // Updating a non-existing key fails.
    let actions = EntryActions::new()
        .update(non_existing_key.clone(), b"value".to_vec(), 1)
        .into();
    assert_match!(client.mutate_mdata_entries_response(*data.name(),
                                                       data.tag(),
                                                       actions,
                                                       &mut nodes),
                  Err(ClientError::NoSuchEntry));

    // Deleting a non-existing key fails.
    let actions = EntryActions::new()
        .del(non_existing_key.clone(), 1)
        .into();
    assert_match!(client.mutate_mdata_entries_response(*data.name(),
                                                       data.tag(),
                                                       actions,
                                                       &mut nodes),
                  Err(ClientError::NoSuchEntry));

    // Mutations are all-or-nothing. If at least one entry actions fails, none
    // gets applied.
    let actions = EntryActions::new()
        .ins(b"key".to_vec(), b"value".to_vec(), 0)
        .update(non_existing_key.clone(), b"value".to_vec(), 1)
        .into();
    assert!(client
                .mutate_mdata_entries_response(*data.name(), data.tag(), actions, &mut nodes)
                .is_err());
    let entries = unwrap!(client.list_mdata_entries_response(*data.name(), data.tag(), &mut nodes));
    assert!(entries.is_empty());

    // Insert some entries for further tests.
    let actions: BTreeMap<_, _> = EntryActions::new()
        .ins(b"key".to_vec(), b"value-0".to_vec(), 0)
        .into();
    unwrap!(data.mutate_entries(actions.clone(), *client.signing_public_key()));
    unwrap!(client.mutate_mdata_entries_response(*data.name(), data.tag(), actions, &mut nodes));

    // Inserting entry that already exists fails.
    let actions = EntryActions::new()
        .ins(b"key".to_vec(), b"value-0".to_vec(), 0)
        .into();
    assert_match!(client.mutate_mdata_entries_response(*data.name(),
                                                       data.tag(),
                                                       actions,
                                                       &mut nodes),
                  Err(ClientError::EntryExists));

    // Updating entry with wrong version fails.
    let actions = EntryActions::new()
        .update(b"key".to_vec(), b"value-1".to_vec(), 0)
        .into();
    assert_match!(client.mutate_mdata_entries_response(*data.name(),
                                                       data.tag(),
                                                       actions,
                                                       &mut nodes),
                  Err(ClientError::InvalidSuccessor));

    // Deleting entry with wrong version fails.
    let actions = EntryActions::new().del(b"key".to_vec(), 0).into();
    assert_match!(client.mutate_mdata_entries_response(*data.name(),
                                                       data.tag(),
                                                       actions,
                                                       &mut nodes),
                  Err(ClientError::InvalidSuccessor));

    // Create app.
    let mut app = TestClient::new(&network, Some(config));
    app.set_client_manager(*client.name());
    app.ensure_connected(&mut nodes);

    // Put without authorisation fails.
    let new_data = test_utils::gen_mutable_data(10000, 0, *client.signing_public_key(), &mut rng);
    assert_match!(app.put_mdata_response(new_data, &mut nodes),
                  Err(ClientError::AccessDenied));

    // Authorise the app client.
    let (_, version) = unwrap!(client.list_auth_keys_and_version_response(&mut nodes));
    unwrap!(client.ins_auth_key_response(*app.signing_public_key(), version + 1, &mut nodes));

    // Mutations by clients that don't have proper permissions fail.
    let actions = test_utils::gen_mutable_data_entry_actions(&data, 1, &mut rng);
    assert_match!(app.mutate_mdata_entries_response(*data.name(), data.tag(), actions, &mut nodes),
                  Err(ClientError::AccessDenied));

    let permission_set = PermissionSet::new()
        .allow(Action::Insert)
        .allow(Action::Update);
    let user = User::Key(*app.signing_public_key());
    assert_match!(app.set_mdata_user_permissions_response(*data.name(),
                                                          data.tag(),
                                                          user,
                                                          permission_set,
                                                          1,
                                                          &mut nodes),
                  Err(ClientError::AccessDenied));

    let permission_set = PermissionSet::new().allow(Action::Insert);
    unwrap!(client.set_mdata_user_permissions_response(*data.name(),
                                                       data.tag(),
                                                       User::Anyone,
                                                       permission_set,
                                                       1,
                                                       &mut nodes));

    assert_match!(app.del_mdata_user_permissions_response(*data.name(),
                                                          data.tag(),
                                                          User::Anyone,
                                                          2,
                                                          &mut nodes),
                  Err(ClientError::AccessDenied));

    let new_owners = owner_keys(*app.signing_public_key());
    assert_match!(app.change_mdata_owner_response(*data.name(),
                                                  data.tag(),
                                                  new_owners,
                                                  2,
                                                  &mut nodes),
                  Err(ClientError::AccessDenied));
}

// Multiple clients mutate multiple data chunks concurrently.
// This test uses parallel polling.
#[test]
fn mutable_data_parallel_mutations() {
    let seed = None;
    let node_count = TEST_NET_SIZE;
    let client_count = 3;
    let data_count = 5;
    let iterations = test_utils::iterations();

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();
    let mut event_count = 0;
    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let mut clients: Vec<_> = (0..client_count)
        .map(|_| {
                 let endpoint = unwrap!(rng.choose(&nodes), "no nodes found").endpoint();
                 let config = BootstrapConfig::with_contacts(&[endpoint]);
                 TestClient::new(&network, Some(config.clone()))
             })
        .collect();

    for client in &mut clients {
        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);
    }

    // Put some data to the network.
    let mut all_data = vec![];

    // Allow any mutations for anyone.
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(User::Anyone,
                               PermissionSet::new()
                                   .allow(Action::Insert)
                                   .allow(Action::Update)
                                   .allow(Action::Delete));

    for _ in 0..data_count {
        let name = rng.gen();
        let tag = rng.gen_range(10001, 20000);

        let mut owners = BTreeSet::new();
        let _ = owners.insert(*clients[0].signing_public_key());

        let num_entries = rng.gen_range(1, 10);
        let entries = test_utils::gen_mutable_data_entries(num_entries, &mut rng);

        let data = unwrap!(MutableData::new(name, tag, permissions.clone(), entries, owners));

        trace!("Putting mutable data with name {:?}, tag {}.",
               data.name(),
               data.tag());
        unwrap!(clients[0].put_mdata_response(data.clone(), &mut nodes));
        all_data.push(data);
    }

    // Authorize other clients.
    let (_, mut account_version) = unwrap!(clients[0]
        .list_auth_keys_and_version_response(&mut nodes));
    let client_keys: Vec<_> = clients
        .iter()
        .skip(1)
        .map(|client| *client.signing_public_key())
        .collect();

    for client_key in client_keys {
        account_version += 1;
        unwrap!(clients[0].ins_auth_key_response(client_key, account_version, &mut nodes));
    }

    for i in 0..iterations {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());

        // Mutate the data simultaneously by each client and keep the
        // corresponding entry actions.
        let j = rng.gen_range(0, all_data.len());
        let sent_actions: Vec<_> = clients
            .iter_mut()
            .map(|client| {
                let data = &all_data[j];
                let num_actions = rng.gen_range(1, 10);
                let actions =
                    test_utils::gen_mutable_data_entry_actions(data, num_actions, &mut rng);

                trace!("Client {:?} sending MutateMDataEntries for data with name {:?}, tag: {}.",
                       client.name(),
                       data.name(),
                       data.tag());
                let _ = client.mutate_mdata_entries(*data.name(), data.tag(), actions.clone());
                actions
            })
            .collect();

        event_count += poll::nodes_and_clients_parallel(&mut nodes, &mut clients);
        trace!("Processed {} events.", event_count);

        // Collect the responses from the clients. For those that succeed,
        // apply their entry actions to the local copy of the data.
        'client_loop: for (client, actions) in clients.iter_mut().zip(sent_actions) {
            let data = &mut all_data[j];
            // When there is conflicting mutations, there is chance no response to client.
            while let Ok(event) = client.try_recv() {
                if let Event::Response {
                           response: Response::MutateMDataEntries { res, .. }, ..
                       } = event {
                    match res {
                        Ok(()) => {
                            trace!("Client {:?} received success response.",
                                   client.name());
                            unwrap!(data.mutate_entries(actions, *client.signing_public_key()));
                        }
                        Err(error) => {
                            trace!("Client {:?} received failed response. Reason: {:?}",
                                   client.name(),
                                   error);
                        }
                    }
                    continue 'client_loop;
                }
            }
        }

        // Check the new version of data (on success) has been stored properly; or confirm the old
        // version of data (on failure or no response) still keeps untouched.
        mock_crust_detail::check_data(all_data.iter().cloned().map(Data::Mutable).collect(),
                                      &nodes);
        mock_crust_detail::verify_network_invariant_for_all_nodes(&nodes);
    }

    // Check that the stored data matches the local copy.
    verify_data_is_stored(&mut nodes, &mut clients[0], &all_data);
}

// Client trying to mutate a mutable_data concurrently with two different sets of actions.
// The responses to the two mutate attempts shall be:
//  1, both succeeded, when there is no conflicting mutation
//  2, only one succeeded, when there is conflicting mutation (updating the same key)
//  3, both failed, when there is conflicting mutation and 50-50 votes happens
#[test]
fn mutable_data_concurrent_mutations() {
    let seed = None;
    let node_count = TEST_NET_SIZE;
    let data_count = 5;
    let iterations = test_utils::iterations();

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();
    let mut event_count = 0;
    let mut nodes = test_node::create_nodes(&network, node_count, None, false);

    let config = BootstrapConfig::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    // Put some data to the network.
    let mut all_data = vec![];

    // Allow any mutations for anyone.
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(User::Anyone,
                               PermissionSet::new()
                                   .allow(Action::Insert)
                                   .allow(Action::Update)
                                   .allow(Action::Delete));

    for _ in 0..data_count {
        let name = rng.gen();
        let tag = rng.gen_range(10001, 20000);

        let mut owners = BTreeSet::new();
        let _ = owners.insert(*client.signing_public_key());

        let num_entries = rng.gen_range(1, 10);
        let entries = test_utils::gen_mutable_data_entries(num_entries, &mut rng);

        let data = unwrap!(MutableData::new(name, tag, permissions.clone(), entries, owners));

        trace!("Putting mutable data with name {:?}, tag {}.",
               data.name(),
               data.tag());
        unwrap!(client.put_mdata_response(data.clone(), &mut nodes));
        all_data.push(data);
    }

    let mut expected_mutation_count = data_count + 1;
    for i in 0..iterations {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());

        let mut sent_actions: HashMap<MessageId, BTreeMap<Vec<u8>, EntryAction>> = HashMap::new();
        let mut expect_successes: usize = 2;
        let index = rng.gen_range(0, all_data.len());
        {
            let data = &all_data[index];
            for _ in 0..2 {
                let num_actions = rng.gen_range(1, 10);
                let actions =
                    test_utils::gen_mutable_data_entry_actions(data, num_actions, &mut rng);
                {
                    let intersect_check = |prev_actions: &BTreeMap<Vec<u8>, EntryAction>| {
                        prev_actions
                            .iter()
                            .any(|(key, _)| actions.contains_key(key))
                    };
                    if !sent_actions.is_empty() &&
                       sent_actions
                           .iter()
                           .any(|(_, prev_actions)| intersect_check(prev_actions)) {
                        expect_successes = 1;
                    }
                }

                trace!("Updating data {:?} with actions {:?}", data.name(), actions);
                let msg_id = client.mutate_mdata_entries(*data.name(), data.tag(), actions.clone());
                let _ = sent_actions.insert(msg_id, actions);
            }
        }

        event_count += poll::nodes_and_client(&mut nodes, &mut client);
        trace!("Processed {} events.", event_count);

        let mut successes: usize = 0;

        while let Ok(event) = client.try_recv() {
            if let Event::Response {
                       response: Response::MutateMDataEntries { res, msg_id }, ..
                   } = event {
                match res {
                    Ok(()) => {
                        trace!("Client {:?} received success response.",
                               client.name());
                        let actions = unwrap!(sent_actions.remove(&msg_id));
                        unwrap!(all_data[index].mutate_entries(actions,
                                                               *client.signing_public_key()));
                        successes += 1;
                    }
                    Err(error) => {
                        trace!("Client {:?} received failed response. Reason: {:?}",
                               client.name(),
                               error);
                    }
                }
            }
        }

        if expect_successes == 1 {
            // When there is conflicting mutations, there is chance one succeed or none.
            assert!(successes <= expect_successes);
        } else {
            assert_eq!(successes, expect_successes);
        }
        mock_crust_detail::check_data(all_data.iter().cloned().map(Data::Mutable).collect(),
                                      &nodes);

        FakeClock::advance_time(PENDING_WRITE_TIMEOUT_SECS * 1000 + 1);
        event_count += poll::nodes_and_client(&mut nodes, &mut client);
        trace!(" Processed {} events.", event_count);

        let sorted_nodes = test_node::closest_to(&nodes, client.name(), GROUP_SIZE);
        let node_count_stats: Vec<_> = sorted_nodes
            .into_iter()
            .map(|node| {
                     (node.name(), unwrap!(node.get_maid_manager_mutation_count(client.name())))
                 })
            .collect();
        expected_mutation_count += successes;
        for &(_, count) in &node_count_stats {
            assert_eq!(expected_mutation_count as u64,
                       count,
                       "Expected {} mutations got: {:?}",
                       expected_mutation_count,
                       node_count_stats);
        }
    }

    mock_crust_detail::verify_network_invariant_for_all_nodes(&nodes);
    // Check that the stored data matches the local copy.
    verify_data_is_stored(&mut nodes, &mut client, &all_data);
}

// Two clients concurrently mutating same data with same actions, one with permission,
// the other not. Only the one with permission shall succeed.
#[test]
fn no_permission_mutable_data_concurrent_mutations() {
    let seed = None;
    let node_count = TEST_NET_SIZE;
    let data_count = 5;
    let iterations = test_utils::iterations();

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();
    let mut event_count = 0;
    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let mut clients: Vec<_> = (0..2)
        .map(|_| {
                 let endpoint = unwrap!(rng.choose(&nodes), "no nodes found").endpoint();
                 let config = BootstrapConfig::with_contacts(&[endpoint]);
                 TestClient::new(&network, Some(config.clone()))
             })
        .collect();

    for client in &mut clients {
        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);
    }

    // Put some data to the network.
    let mut all_data = vec![];

    // Allow mutations only for the first client.
    let mut permissions = BTreeMap::new();
    let _ = permissions.insert(User::Key(*clients[0].signing_public_key()),
                               PermissionSet::new()
                                   .allow(Action::Insert)
                                   .allow(Action::Update)
                                   .allow(Action::Delete));

    for _ in 0..data_count {
        let name = rng.gen();
        let tag = rng.gen_range(10001, 20000);

        let mut owners = BTreeSet::new();
        let _ = owners.insert(*clients[0].signing_public_key());

        let num_entries = rng.gen_range(1, 10);
        let entries = test_utils::gen_mutable_data_entries(num_entries, &mut rng);

        let data = unwrap!(MutableData::new(name, tag, permissions.clone(), entries, owners));

        trace!("Putting mutable data with name {:?}, tag {}.",
               data.name(),
               data.tag());
        unwrap!(clients[0].put_mdata_response(data.clone(), &mut nodes));
        all_data.push(data);
    }

    for i in 0..iterations {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());

        let index = rng.gen_range(0, all_data.len());
        let data_name = *all_data[index].name();
        let data_tag = all_data[index].tag();

        let num_actions = rng.gen_range(1, 10);
        let actions =
            test_utils::gen_mutable_data_entry_actions(&all_data[index], num_actions, &mut rng);

        trace!("Updating data {:?} with actions {:?}", data_name, actions);
        let _ = clients[0].mutate_mdata_entries(data_name, data_tag, actions.clone());
        let _ = clients[1].mutate_mdata_entries(data_name, data_tag, actions.clone());

        event_count += poll::nodes_and_clients_parallel(&mut nodes, &mut clients);
        trace!("Processed {} events.", event_count);

        let mut network_responded = false;
        while let Ok(event) = clients[0].try_recv() {
            if let Event::Response {
                       response: Response::MutateMDataEntries { res, .. }, ..
                   } = event {
                network_responded = true;
                match res {
                    Ok(()) => {
                        trace!("Client {:?} received success response.",
                               clients[0].name());
                        unwrap!(all_data[index].mutate_entries(actions.clone(),
                                                               *clients[0].signing_public_key()));
                    }
                    Err(error) => {
                        panic!("Client {:?} received failed response. Reason: {:?}",
                               clients[0].name(),
                               error);
                    }
                }
            }
        }
        assert!(network_responded,
                "Client {:?} shall receive a response from network",
                clients[0].name());

        network_responded = false;
        while let Ok(event) = clients[1].try_recv() {
            if let Event::Response {
                       response: Response::MutateMDataEntries { res, .. }, ..
                   } = event {
                network_responded = true;
                match res {
                    Ok(()) => {
                        panic!("Client {:?} shall not receive success response.",
                               clients[1].name());
                    }
                    Err(error) => assert_eq!(error, ClientError::AccessDenied),
                }
            }
        }
        assert!(network_responded,
                "Client {:?} shall receive a response from network",
                clients[1].name());

        mock_crust_detail::check_data(all_data.iter().cloned().map(Data::Mutable).collect(),
                                      &nodes);
    }

    mock_crust_detail::verify_network_invariant_for_all_nodes(&nodes);
    // Check that the stored data matches the local copy.
    verify_data_is_stored(&mut nodes, &mut clients[0], &all_data);
}

#[test]
fn mutable_data_operations_with_churn() {
    let seed = None;
    let node_count = TEST_NET_SIZE;
    let operation_count = 5;
    let iterations = test_utils::iterations();

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);

    let config = BootstrapConfig::with_contacts(&[nodes[1].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut all_data: Vec<MutableData> = Vec::new();
    let mut event_count = 0;

    for i in 0..iterations {
        trace!("Iteration {} of {}. Network size: {}",
               i + 1,
               iterations,
               nodes.len());
        let mut new_data = Vec::with_capacity(operation_count);
        let mut mutated_data = HashSet::new();

        for _ in 0..operation_count {
            if all_data.is_empty() || rng.gen() {
                // Put new data.
                let tag = rng.gen_range(10001, 20000);
                let entry_count = rng.gen_range(0, 10);
                let data = test_utils::gen_mutable_data(tag,
                                                        entry_count,
                                                        *client.signing_public_key(),
                                                        &mut rng);
                trace!("Putting mutable data with name {:?}, tag {}.",
                       data.name(),
                       data.tag());
                let _ = client.put_mdata(data.clone());
                new_data.push(data);
            } else {
                // Mutate existing data.
                let j = rng.gen_range(0, all_data.len());
                let data = &mut all_data[j];

                if !mutated_data.insert((*data.name(), data.tag())) {
                    trace!("Skipping data with name {:?}, tag {:?}.",
                           data.name(),
                           data.tag());
                    continue;
                }

                let action_count = rng.gen_range(1, 10);
                let actions =
                    test_utils::gen_mutable_data_entry_actions(data, action_count, &mut rng);
                unwrap!(data.mutate_entries(actions.clone(), *client.signing_public_key()));

                trace!("Sending MutateMDataEntries for data with name {:?}, tag: {}.",
                       data.name(),
                       data.tag());
                let _ = client.mutate_mdata_entries(*data.name(), data.tag(), actions);
            }
        }

        all_data.extend(new_data);

        // Churn
        if nodes.len() <= GROUP_SIZE + 2 || rng.gen_range(0, 4) < 3 {
            // Add new node.
            let bootstrap_node_index = rng.gen_range(2, nodes.len());
            let bootstrap_node_name = nodes[bootstrap_node_index].name();
            test_node::add_node(&network, &mut nodes, bootstrap_node_index, true);
            let new_node_name = nodes[nodes.len() - 1].name();

            trace!("Adding node {:?} with bootstrap node {:?}.",
                   new_node_name,
                   bootstrap_node_name);
        } else {
            // Remove some nodes.
            let count = rng.gen_range(1, 4);
            let mut removed_nodes = Vec::with_capacity(count);
            for _ in 0..count {
                let node_index = rng.gen_range(2, nodes.len());
                removed_nodes.push(nodes[node_index].name());
                test_node::drop_node(&mut nodes, node_index);
            }

            trace!("Removing {} node(s): {:?}", count, removed_nodes);
        }

        event_count += poll::nodes_and_client_with_resend(&mut nodes, &mut client);
        trace!("Processed {} events.", event_count);

        mock_crust_detail::check_data(all_data.iter().cloned().map(Data::Mutable).collect(),
                                      &nodes);
        mock_crust_detail::verify_network_invariant_for_all_nodes(&nodes);
    }

    verify_data_is_stored(&mut nodes, &mut client, &all_data);
}

#[test]
fn caching_with_data_not_close_to_proxy_node() {
    let seed = None;
    let node_count = GROUP_SIZE + 2;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);

    let config = BootstrapConfig::with_contacts(&[nodes[1].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let sent_data = gen_immutable_data_not_close_to(&nodes[1], &mut rng);
    unwrap!(client.put_idata_response(sent_data.clone(), &mut nodes));

    // The first response is not yet cached, so it comes from a NAE manager authority.
    let (received_data, src) = unwrap!(client.get_idata_response_with_src(*sent_data.name(),
                                                                          &mut nodes));
    assert_eq!(received_data, sent_data);

    match src {
        Authority::NaeManager(_) => (),
        authority => {
            panic!("Response is cached (unexpected src authority {:?})",
                   authority)
        }
    }

    // The second response is cached, so it comes from a managed node authority.
    let (received_data, src) = unwrap!(client.get_idata_response_with_src(*sent_data.name(),
                                                                          &mut nodes));
    assert_eq!(received_data, sent_data);

    match src {
        Authority::ManagedNode(_) => (),
        authority => {
            panic!("Response is not cached (unexpected src authority {:?})",
                   authority)
        }
    }
}

#[test]
fn caching_with_data_close_to_proxy_node() {
    let seed = None;
    let node_count = GROUP_SIZE + 2;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);

    let config = BootstrapConfig::with_contacts(&[nodes[1].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let sent_data = gen_immutable_data_close_to(&nodes[1], &mut rng);
    unwrap!(client.put_idata_response(sent_data.clone(), &mut nodes));

    // Send two requests and verify the response is not cached in any of them
    let (received_data, src) = unwrap!(client.get_idata_response_with_src(*sent_data.name(),
                                                                          &mut nodes));
    assert_eq!(received_data, sent_data);

    match src {
        Authority::NaeManager(_) => (),
        authority => {
            panic!("Response is cached (unexpected src authority {:?})",
                   authority)
        }
    }

    let (received_data, src) = unwrap!(client.get_idata_response_with_src(*sent_data.name(),
                                                                          &mut nodes));
    assert_eq!(received_data, sent_data);

    match src {
        Authority::NaeManager(_) => (),
        authority => {
            panic!("Response is cached (unexpected src authority {:?})",
                   authority)
        }
    }
}

fn gen_immutable_data_close_to<R: Rng>(node: &TestNode, rng: &mut R) -> ImmutableData {
    loop {
        let data = test_utils::gen_immutable_data(10, rng);
        if node.routing_table().is_closest(data.name(), GROUP_SIZE) {
            return data;
        }
    }
}

fn gen_immutable_data_not_close_to<R: Rng>(node: &TestNode, rng: &mut R) -> ImmutableData {
    loop {
        let data = test_utils::gen_immutable_data(10, rng);
        if !node.routing_table().is_closest(data.name(), GROUP_SIZE) {
            return data;
        }
    }
}

// Create set of owner keys.
fn owner_keys(key: sign::PublicKey) -> BTreeSet<sign::PublicKey> {
    let mut result = BTreeSet::new();
    let _ = result.insert(key);
    result
}

// Verify that every element of `data` is actually stored on the network.
fn verify_data_is_stored(nodes: &mut [TestNode], client: &mut TestClient, data: &[MutableData]) {
    for sent_data in data {
        let recovered_shell =
            unwrap!(client.get_mdata_shell_response(*sent_data.name(), sent_data.tag(), nodes));
        let recovered_entries =
            unwrap!(client.list_mdata_entries_response(*sent_data.name(), sent_data.tag(), nodes));

        assert_eq!(sent_data.shell(), recovered_shell);
        assert_eq!(*sent_data.entries(), recovered_entries);
    }
}
