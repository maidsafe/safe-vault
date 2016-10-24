// Copyright 2016 MaidSafe.net limited.
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

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md

use itertools::Itertools;
use rand::Rng;
use rand::distributions::{IndependentSample, Range};
use routing::{Data, ImmutableData, MIN_GROUP_SIZE, StructuredData, TYPE_TAG_SESSION_PACKET,
              XorName, Xorable};
use routing::client_errors::{GetError, MutationError};
use routing::mock_crust::{self, Network};
use rust_sodium::crypto::box_;
use safe_vault::mock_crust_detail::{self, poll, test_node};
use safe_vault::mock_crust_detail::test_client::TestClient;
use safe_vault::test_utils;

const TEST_NET_SIZE: usize = 20;

#[ignore]
#[test]
fn handle_put_without_account() {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut event_count = 0;
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);

    let immutable_data = ImmutableData::new(rng.gen_iter().take(1024).collect());
    client.put(Data::Immutable(immutable_data));
    event_count += poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);
    trace!("Processed {} events.", event_count);
    let count = nodes.iter()
        .filter(|node| node.get_maid_manager_put_count(client.name()).is_some())
        .count();
    assert!(0 == count,
            "put_count {} found with {} nodes",
            count,
            node_count);
}

#[ignore]
#[test]
fn put_oversized_data() {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    match client.put_and_verify(Data::Immutable(
            test_utils::random_immutable_data(1100 * 1024, &mut rng)), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::DataTooLarge),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    let sd = Data::Structured(test_utils::random_structured_data_with_size(10000,
                                                                           client.full_id(),
                                                                           102400,
                                                                           &mut rng));
    match client.put_and_verify(sd, &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::DataTooLarge),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    let pub_ad =
        Data::PubAppendable(test_utils::random_pub_appendable_data_with_size(client.full_id(),
                                                                             102400,
                                                                             &mut rng));
    match client.put_and_verify(pub_ad, &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::DataTooLarge),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    let (pub_encrypt_key, _) = box_::gen_keypair();
    let priv_ad =
        Data::PrivAppendable(test_utils::random_priv_appendable_data_with_size(client.full_id(),
                                                                               pub_encrypt_key,
                                                                               102400,
                                                                               &mut rng));
    match client.put_and_verify(priv_ad, &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::DataTooLarge),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }
    // After serialisation, the len of SD, pub_ad and priv_ad is : 102604, 128216, 128256
}

#[ignore]
#[test]
fn handle_put_with_account() {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);

    let result = client.get_account_info_response(&mut nodes);
    assert_eq!(result, Err(Some(GetError::NoSuchAccount)));

    client.create_account(&mut nodes);
    let default_account_size = 100;
    let mut expected_data_stored = 1;
    let mut expected_space_available = default_account_size - expected_data_stored;
    assert_eq!(unwrap!(client.get_account_info_response(&mut nodes)),
               (expected_data_stored, expected_space_available));

    let immutable_data = ImmutableData::new(rng.gen_iter().take(1024).collect());
    client.put(Data::Immutable(immutable_data.clone()));
    let event_count = poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);
    trace!("Processed {} events.", event_count);
    let count = nodes.iter()
        .filter(|node| node.get_maid_manager_put_count(client.name()).is_some())
        .count();
    assert!(MIN_GROUP_SIZE == count,
            "client account {} found on {} nodes",
            count,
            node_count);
    let mut stored_immutable = Vec::new();
    stored_immutable.push(Data::Immutable(immutable_data));
    mock_crust_detail::check_data(stored_immutable, &nodes);
    expected_data_stored += 1;
    expected_space_available = default_account_size - expected_data_stored;
    assert_eq!(unwrap!(client.get_account_info_response(&mut nodes)),
               (expected_data_stored, expected_space_available));
}

#[ignore]
#[test]
fn create_account_twice() {
    let default_account_size = 100;
    let expected_data_stored = 1;
    let expected_space_available = default_account_size - expected_data_stored;
    let acct_info = (expected_data_stored, expected_space_available);
    let acct_err = Err(Some(GetError::NoSuchAccount));
    let acct_exists = Err(Some(MutationError::AccountExists));

    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client0 = TestClient::new(&network, Some(config.clone()));
    let mut client1 = TestClient::new(&network, Some(config.clone()));
    let mut rng = network.new_rng();

    client0.ensure_connected(&mut nodes);
    client1.ensure_connected(&mut nodes);

    assert_eq!(Err(Some(GetError::NoSuchAccount)),
               client0.get_account_info_response(&mut nodes));
    assert_eq!(Err(Some(GetError::NoSuchAccount)),
               client1.get_account_info_response(&mut nodes));

    let account = unwrap!(StructuredData::new(TYPE_TAG_SESSION_PACKET,
                                              rng.gen(),
                                              0,
                                              vec![],
                                              vec![],
                                              vec![],
                                              None));

    // Create an account using `client0`.
    unwrap!(client0.put_and_verify(Data::Structured(account.clone()), &mut nodes));

    assert_eq!(unwrap!(client0.get_account_info_response(&mut nodes)),
               acct_info);
    assert_eq!(client1.get_account_info_response(&mut nodes), acct_err);

    // Create the account again using `client0`.
    assert_eq!(client0.put_and_verify(Data::Structured(account.clone()), &mut nodes),
               acct_exists);
    let _ = poll::poll_and_resend_unacknowledged(&mut nodes, &mut client0);

    // That should not have changed anything.
    assert_eq!(unwrap!(client0.get_account_info_response(&mut nodes)),
               acct_info);
    assert_eq!(client1.get_account_info_response(&mut nodes), acct_err);

    // Create the same account using `client1`.
    assert_eq!(client1.put_and_verify(Data::Structured(account.clone()), &mut nodes),
               acct_exists);
    let _ = poll::poll_and_resend_unacknowledged(&mut nodes, &mut client1);

    // That should not succeed.
    assert_eq!(unwrap!(client0.get_account_info_response(&mut nodes)),
               acct_info);
    assert_eq!(client1.get_account_info_response(&mut nodes), acct_err);
}

#[ignore]
#[test]
#[should_panic] // TODO Look at using std::panic::catch_unwind (1.9)
fn invalid_put_for_previously_created_account() {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    client.create_account(&mut nodes);
}

#[ignore]
#[test]
fn storing_till_client_account_full() {
    // This needs to be kept in sync with maid_manager.rs
    // Ideally, a setter is preferred, so that this test can be completed quicker.
    const DEFAULT_ACCOUNT_SIZE: u64 = 100;
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();

    for i in 0..(DEFAULT_ACCOUNT_SIZE + 5) {
        let data = if i % 2 == 0 {
            Data::Structured(test_utils::random_structured_data(100000, &full_id, &mut rng))
        } else {
            Data::Immutable(ImmutableData::new(rng.gen_iter().take(10).collect()))
        };
        let result = client.put_and_verify(data.clone(), &mut nodes);
        if i < DEFAULT_ACCOUNT_SIZE - 1 {
            assert_eq!(result, Ok(()));
        } else {
            assert_eq!(result, Err(Some(MutationError::LowBalance)));
        }
    }
}

#[ignore]
#[test]
fn maid_manager_account_adding_with_churn() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut rng = network.new_rng();

    let mut put_count = 1; // Login packet.
    let full_id = client.full_id().clone();
    let mut event_count = 0;

    for i in 0..test_utils::iterations() {
        for data in (0..4).map(|_| {
            Data::Structured(test_utils::random_structured_data(100000, &full_id, &mut rng))
        }) {
            client.put(data.clone());
            put_count += 1;
        }
        trace!("Churning on {} nodes, iteration {}", nodes.len(), i);
        if nodes.len() <= MIN_GROUP_SIZE + 2 || rng.gen() {
            let index = Range::new(1, nodes.len()).ind_sample(&mut rng);
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index, false);
        } else {
            let number = Range::new(1, 4).ind_sample(&mut rng);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_index = Range::new(1, nodes.len()).ind_sample(&mut rng);
                test_node::drop_node(&mut nodes, node_index);
            }
        }
        event_count += poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);

        for node in &mut nodes {
            node.clear_state();
        }
        trace!("Processed {} events.", event_count);
        let mut sorted_maid_managers = nodes.iter()
            .sorted_by(|left, right| client.name().cmp_distance(&left.name(), &right.name()));
        sorted_maid_managers.truncate(MIN_GROUP_SIZE);
        let node_count_stats: Vec<(XorName, Option<u64>)> = sorted_maid_managers.into_iter()
            .map(|x| (x.name(), x.get_maid_manager_put_count(client.name())))
            .collect();
        for &(_, count) in &node_count_stats {
            assert!(count == Some(put_count), "{:?}", node_count_stats);
        }
        mock_crust_detail::verify_kademlia_invariant_for_all_nodes(&nodes);
    }
}

#[ignore]
#[test]
fn maid_manager_account_decrease_with_churn() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let client_config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(client_config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut rng = network.new_rng();

    let full_id = client.full_id().clone();
    let mut event_count = 0;
    let chunks_per_iter = 4;
    let mut data_list = Vec::new();

    for i in 0..test_utils::iterations() as u64 {
        trace!("Churning on {} nodes, iteration {}", nodes.len(), i);
        if nodes.len() <= MIN_GROUP_SIZE + 2 || rng.gen() {
            let index = Range::new(1, nodes.len()).ind_sample(&mut rng);
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index, false);
        } else {
            let number = Range::new(1, 4).ind_sample(&mut rng);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_index = Range::new(1, nodes.len()).ind_sample(&mut rng);
                test_node::drop_node(&mut nodes, node_index);
            }
        }
        if i % 2 == 0 {
            data_list.clear();
            for data in (0..chunks_per_iter).map(|_| {
                Data::Structured(test_utils::random_structured_data(100000, &full_id, &mut rng))
            }) {
                client.put(data.clone());
                data_list.push(data);
            }
        } else {
            for data in &data_list {
                // Expect to be failed in DM. MM acount is increased first but be decreased back
                // due to the put failure response from DM.
                client.put(data.clone());
            }
        }
        event_count += poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);

        for node in &mut nodes {
            node.clear_state();
        }
        trace!("Processed {} events.", event_count);
        let mut sorted_maid_managers = nodes.iter()
            .sorted_by(|left, right| client.name().cmp_distance(&left.name(), &right.name()));
        sorted_maid_managers.truncate(MIN_GROUP_SIZE);
        let node_count_stats: Vec<(XorName, Option<u64>)> = sorted_maid_managers.into_iter()
            .map(|x| (x.name(), x.get_maid_manager_put_count(client.name())))
            .collect();
        for &(_, count) in &node_count_stats {
            assert_eq!(count, Some(chunks_per_iter * (i / 2 + 1) + 1));
        }
    }
}
