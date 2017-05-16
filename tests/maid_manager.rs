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

use rand::Rng;
use routing::{AccountInfo, ClientError, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES,
              MAX_MUTABLE_DATA_ENTRIES, MAX_MUTABLE_DATA_SIZE_IN_BYTES, MutableData,
              TYPE_TAG_SESSION_PACKET, Value};
use routing::mock_crust::{self, Network};
use safe_vault::{DEFAULT_ACCOUNT_SIZE, GROUP_SIZE, test_utils};
use safe_vault::mock_crust_detail::{self, Data, poll, test_node};
use safe_vault::mock_crust_detail::test_client::TestClient;
use std::collections::BTreeSet;

const TEST_NET_SIZE: usize = 20;
const TEST_TAG: u64 = 123456;

#[test]
fn handle_put_without_account() {
    let network = Network::new(GROUP_SIZE, None);
    let mut rng = network.new_rng();

    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);

    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);

    let data = test_utils::gen_immutable_data(1024, &mut rng);
    let _ = client.put_idata(data);
    let event_count = poll::nodes_and_client(&mut nodes, &mut client);
    trace!("Processed {} events.", event_count);

    let count = nodes
        .iter()
        .filter(|node| {
                    node.get_maid_manager_mutation_count(client.name())
                        .is_some()
                })
        .count();
    assert_eq!(count,
               0,
               "mutations count {} found with {} nodes",
               count,
               node_count);
}

#[test]
fn handle_put_with_account() {
    let network = Network::new(GROUP_SIZE, None);
    let mut rng = network.new_rng();

    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);

    let result = client.get_account_info_response(&mut nodes);
    assert_eq!(result, Err(ClientError::NoSuchAccount));

    client.create_account(&mut nodes);
    let mut expected_mutations_done = 1;
    let mut expected_mutations_available = DEFAULT_ACCOUNT_SIZE - expected_mutations_done;
    let account_info = unwrap!(client.get_account_info_response(&mut nodes));
    assert_eq!(account_info.mutations_done, expected_mutations_done);
    assert_eq!(account_info.mutations_available,
               expected_mutations_available);

    let data = test_utils::gen_immutable_data(1024, &mut rng);
    let _ = client.put_idata(data.clone());
    let event_count = poll::nodes_and_client(&mut nodes, &mut client);
    trace!("Processed {} events.", event_count);

    let count = nodes
        .iter()
        .filter(|node| {
                    node.get_maid_manager_mutation_count(client.name())
                        .is_some()
                })
        .count();
    assert_eq!(count,
               GROUP_SIZE,
               "client account count {} found on {} nodes",
               count,
               node_count);

    mock_crust_detail::check_data(vec![Data::Immutable(data)], &nodes);

    expected_mutations_done += 1;
    expected_mutations_available = DEFAULT_ACCOUNT_SIZE - expected_mutations_done;
    let account_info = unwrap!(client.get_account_info_response(&mut nodes));
    assert_eq!(account_info.mutations_done, expected_mutations_done);
    assert_eq!(account_info.mutations_available,
               expected_mutations_available);
}

#[test]
fn put_oversized_data() {
    let network = Network::new(GROUP_SIZE, None);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, TEST_NET_SIZE, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    // Too large immutable data
    let data = test_utils::gen_immutable_data(MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as usize + 1,
                                              &mut rng);
    match client.put_idata_response(data, &mut nodes) {
        Err(ClientError::DataTooLarge) => (),
        x => panic!("Unexpected response: {:?}", x),
    }

    // Mutable data with too large entries
    let mut data = test_utils::gen_mutable_data(TEST_TAG,
                                                0,
                                                *client.full_id().public_id().signing_public_key(),
                                                &mut rng);
    let key0 = b"key0".to_vec();
    let value0 = Value {
        content: test_utils::gen_vec(MAX_MUTABLE_DATA_SIZE_IN_BYTES as usize / 2, &mut rng),
        entry_version: 0,
    };

    let key1 = b"key1".to_vec();
    let value1 = Value {
        content: test_utils::gen_vec(MAX_MUTABLE_DATA_SIZE_IN_BYTES as usize / 2 + 2, &mut rng),
        entry_version: 0,
    };

    assert!(data.mutate_entry_without_validation(key0, value0));
    assert!(data.mutate_entry_without_validation(key1, value1));

    match client.put_mdata_response(data, &mut nodes) {
        Err(ClientError::DataTooLarge) => (),
        x => panic!("Unexpected response: {:?}", x),
    }

    // Mutable data with too many entries
    let mut data = test_utils::gen_mutable_data(TEST_TAG,
                                                0,
                                                *client.full_id().public_id().signing_public_key(),
                                                &mut rng);
    for i in 0..MAX_MUTABLE_DATA_ENTRIES + 1 {
        let key = format!("key{}", i).into_bytes();
        let value = Value {
            content: test_utils::gen_vec(10, &mut rng),
            entry_version: 0,
        };

        assert!(data.mutate_entry_without_validation(key, value));
    }

    match client.put_mdata_response(data, &mut nodes) {
        Err(ClientError::TooManyEntries) => (),
        x => panic!("Unexpected response: {:?}", x),
    }
}


#[test]
fn create_account_twice() {
    let network = Network::new(GROUP_SIZE, None);
    let mut rng = network.new_rng();

    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client0 = TestClient::new(&network, Some(config.clone()));
    let mut client1 = TestClient::new(&network, Some(config.clone()));

    client0.ensure_connected(&mut nodes);
    client1.ensure_connected(&mut nodes);

    assert_eq!(Err(ClientError::NoSuchAccount),
               client0.get_account_info_response(&mut nodes));
    assert_eq!(Err(ClientError::NoSuchAccount),
               client1.get_account_info_response(&mut nodes));

    let mut owners = BTreeSet::new();
    let _ = owners.insert(*client0.signing_public_key());

    let account = unwrap!(MutableData::new(rng.gen(),
                                           TYPE_TAG_SESSION_PACKET,
                                           Default::default(),
                                           Default::default(),
                                           owners.clone()));

    let expected_account_info = AccountInfo {
        mutations_done: 1,
        mutations_available: DEFAULT_ACCOUNT_SIZE - 1,
    };

    // Create the account using `client0`.
    unwrap!(client0.put_mdata_response(account.clone(), &mut nodes));

    assert_eq!(unwrap!(client0.get_account_info_response(&mut nodes)),
               expected_account_info);
    assert_eq!(client1.get_account_info_response(&mut nodes),
               Err(ClientError::NoSuchAccount));

    // Create the account again using `client0`.
    assert_eq!(client0.put_mdata_response(account.clone(), &mut nodes),
               Err(ClientError::AccountExists));
    let _ = poll::nodes_and_client(&mut nodes, &mut client0);

    // That should not have changed anything.
    assert_eq!(unwrap!(client0.get_account_info_response(&mut nodes)),
               expected_account_info);
    assert_eq!(client1.get_account_info_response(&mut nodes),
               Err(ClientError::NoSuchAccount));

    // Create the same account using `client1`.
    assert_eq!(client1.put_mdata_response(account, &mut nodes),
               Err(ClientError::InvalidOwners));
    let _ = poll::nodes_and_client(&mut nodes, &mut client1);

    // That should not succeed.
    assert_eq!(unwrap!(client0.get_account_info_response(&mut nodes)),
               expected_account_info);
    assert_eq!(client1.get_account_info_response(&mut nodes),
               Err(ClientError::NoSuchAccount));

    // Create the account again, but with different name, using `client0`.
    let account = unwrap!(MutableData::new(rng.gen(),
                                           TYPE_TAG_SESSION_PACKET,
                                           Default::default(),
                                           Default::default(),
                                           owners));
    assert_eq!(client0.put_mdata_response(account, &mut nodes),
               Err(ClientError::AccountExists));
}

#[test]
fn storing_till_client_account_full() {
    let network = Network::new(GROUP_SIZE, None);
    let mut rng = network.new_rng();

    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let client_key = *client.full_id().public_id().signing_public_key();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    for i in 0..DEFAULT_ACCOUNT_SIZE + 5 {
        let result = if i % 2 == 0 {
            let data = test_utils::gen_mutable_data(TEST_TAG, 0, client_key, &mut rng);
            client.put_mdata_response(data, &mut nodes)
        } else {
            let data = test_utils::gen_immutable_data(10, &mut rng);
            client.put_idata_response(data, &mut nodes)
        };

        if i < DEFAULT_ACCOUNT_SIZE - 1 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(ClientError::LowBalance));
        }
    }
}

#[test]
fn account_mutation_count_increase_with_churn() {
    let seed = None;
    let iterations = test_utils::iterations();
    let node_count = 15;
    let data_count = 4;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let client_key = *client.full_id().public_id().signing_public_key();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut mutation_count = 1; // Session packet.
    let mut event_count = 0;

    for i in 0..iterations {
        for _ in 0..data_count {
            let data = test_utils::gen_mutable_data(TEST_TAG, 10, client_key, &mut rng);
            let _ = client.put_mdata(data);
            mutation_count += 1;
        }

        trace!("Churning on {} nodes, iteration {}", nodes.len(), i);

        if nodes.len() <= GROUP_SIZE + 2 || rng.gen() {
            let index = rng.gen_range(1, nodes.len());
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index, false);
        } else {
            let number = rng.gen_range(1, 4);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_index = rng.gen_range(1, nodes.len());
                test_node::drop_node(&mut nodes, node_index);
            }
        }

        event_count += poll::nodes_and_client_with_resend(&mut nodes, &mut client);
        trace!("Processed {} events.", event_count);

        let sorted_nodes = test_node::closest_to(&nodes, client.name(), GROUP_SIZE);
        let node_count_stats: Vec<_> = sorted_nodes
            .into_iter()
            .map(|node| (node.name(), node.get_maid_manager_mutation_count(client.name())))
            .collect();

        for &(_, count) in &node_count_stats {
            assert_eq!(count,
                       Some(mutation_count),
                       "Expected {} mutations, got: {:?}",
                       mutation_count,
                       node_count_stats);
        }

        mock_crust_detail::verify_network_invariant_for_all_nodes(&nodes);
    }
}

#[test]
fn account_mutation_count_decrease_with_churn() {
    let seed = None;
    let node_count = 15;
    let chunks_per_iter = 4;

    let network = Network::new(GROUP_SIZE, seed);
    let mut rng = network.new_rng();

    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let client_config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(client_config));
    let client_key = *client.full_id().public_id().signing_public_key();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut event_count = 0;
    let mut data_list = Vec::new();

    for i in 0..test_utils::iterations() as u64 {
        trace!("Churning on {} nodes, iteration {}", nodes.len(), i);

        if nodes.len() <= GROUP_SIZE + 2 || rng.gen() {
            let index = rng.gen_range(1, nodes.len());
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index, false);
        } else {
            let number = rng.gen_range(1, 4);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_index = rng.gen_range(1, nodes.len());
                test_node::drop_node(&mut nodes, node_index);
            }
        }

        if i % 2 == 0 {
            data_list.clear();
            for _ in 0..chunks_per_iter {
                let data = test_utils::gen_mutable_data(TEST_TAG, 10, client_key, &mut rng);
                let _ = client.put_mdata(data.clone());
                data_list.push(data);
            }
        } else {
            for data in &data_list {
                // Expect to be failed in DM. MM acount is increased first but be decreased back
                // due to the put failure response from DM.
                let _ = client.put_mdata(data.clone());
            }
        }

        event_count += poll::nodes_and_client_with_resend(&mut nodes, &mut client);
        trace!("Processed {} events.", event_count);

        let sorted_nodes = test_node::closest_to(&nodes, client.name(), GROUP_SIZE);
        let node_count_stats: Vec<_> = sorted_nodes
            .into_iter()
            .map(|node| (node.name(), node.get_maid_manager_mutation_count(client.name())))
            .collect();

        for &(_, count) in &node_count_stats {
            assert_eq!(count, Some(chunks_per_iter * (i / 2 + 1) + 1));
        }
    }
}
