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

use rand::Rng;
use rand::distributions::{IndependentSample, Range};

use routing::{AppendWrapper, AppendedData, Authority, Data, DataIdentifier, Event, FullId,
              GROUP_SIZE, ImmutableData, PrivAppendedData, Response, StructuredData};
use routing::client_errors::{GetError, MutationError};
use routing::mock_crust::{self, Network};
use rust_sodium::crypto::{box_, sign};
use safe_vault::mock_crust_detail::{self, poll, test_node};
use safe_vault::mock_crust_detail::test_client::TestClient;
use safe_vault::mock_crust_detail::test_node::TestNode;
use safe_vault::test_utils;
use std::cmp;
use std::collections::HashSet;

const TEST_NET_SIZE: usize = 20;

#[test]
fn immutable_data_operations_with_churn_with_cache() {
    immutable_data_operations_with_churn(true);
}

#[test]
fn immutable_data_operations_with_churn_without_cache() {
    immutable_data_operations_with_churn(false);
}

fn immutable_data_operations_with_churn(use_cache: bool) {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, use_cache);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    const DATA_COUNT: usize = 50;
    const DATA_PER_ITER: usize = 5;

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut all_data = vec![];
    let mut rng = network.new_rng();
    let mut event_count = 0;

    for i in 0..10 {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());
        for _ in 0..(cmp::min(DATA_PER_ITER, DATA_COUNT - all_data.len())) {
            let data = Data::Immutable(ImmutableData::new(rng.gen_iter().take(10).collect()));
            trace!("Putting data {:?}.", data.name());
            client.put(data.clone());
            all_data.push(data);
        }
        if nodes.len() <= GROUP_SIZE + 2 || Range::new(0, 4).ind_sample(&mut rng) < 3 {
            let index = Range::new(1, nodes.len()).ind_sample(&mut rng);
            trace!("Adding node with bootstrap node {}.", index);
            test_node::add_node(&network, &mut nodes, index, use_cache);
        } else {
            let number = Range::new(3, 4).ind_sample(&mut rng);
            trace!("Removing {} node(s).", number);
            for _ in 0..number {
                let node_range = Range::new(1, nodes.len());
                let node_index = node_range.ind_sample(&mut rng);
                test_node::drop_node(&mut nodes, node_index);
            }
        }
        event_count += poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);

        for node in &mut nodes {
            node.clear_state();
        }
        trace!("Processed {} events.", event_count);

        mock_crust_detail::check_data(all_data.clone(), &nodes);
        mock_crust_detail::verify_kademlia_invariant_for_all_nodes(&nodes);
    }

    for data in &all_data {
        match *data {
            Data::Immutable(ref sent_data) => {
                match client.get(sent_data.identifier(), &mut nodes) {
                    Data::Immutable(recovered_data) => {
                        assert_eq!(recovered_data, *sent_data);
                    }
                    unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                }
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn structured_data_parallel_posts() {
    let network = Network::new(None);
    let mut rng = network.new_rng();
    let mut event_count = 0;
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, false);
    let mut clients: Vec<_> = (0..3)
        .map(|_| {
            let endpoint = unwrap_option!(rng.choose(&nodes), "no nodes found").endpoint();
            let config = mock_crust::Config::with_contacts(&[endpoint]);
            TestClient::new(&network, Some(config.clone()))
        })
        .collect();

    for client in &mut clients {
        client.ensure_connected(&mut nodes);
        client.create_account(&mut nodes);
    }

    let mut all_data = vec![];
    for _ in 0..5 {
        let type_tag = Range::new(10001, 20000).ind_sample(&mut rng);
        let sd = test_utils::random_structured_data(type_tag, clients[0].full_id(), &mut rng);
        let data = Data::Structured(sd);
        trace!("Putting data {:?} with name {:?}.",
               data.identifier(),
               data.name());
        unwrap_result!(clients[0].put_and_verify(data.clone(), &mut nodes));
        all_data.push(data);
    }

    let key = clients[0].full_id().signing_private_key().clone();
    let mut successes: usize = 0;
    for i in 0..30 {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());
        let j = Range::new(0, all_data.len()).ind_sample(&mut rng);
        let new_data: Vec<Data> = clients.iter_mut()
            .map(|client| {
                let data = Data::Structured(if let Data::Structured(sd) = all_data[j].clone() {
                    unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                       *sd.name(),
                                                       sd.get_version() + 1,
                                                       rng.gen_iter().take(10).collect(),
                                                       sd.get_owner_keys().clone(),
                                                       vec![],
                                                       Some(&key)))
                } else {
                    panic!("Non-structured data found.");
                });
                trace!("Posting data {:?} with name {:?}.",
                       data.identifier(),
                       data.name());
                client.post(data.clone());
                data
            })
            .collect();

        // A custom implementation of poll_and_resend_unacknowledged that handles more than one
        // client and handles only one event per round for each node and client, to better simulate
        // simultaneous requests.
        loop {
            let mut new_count = 0;
            loop {
                let prev_count = new_count;
                for node in &mut nodes {
                    if node.poll_once() {
                        new_count += 1;
                    }
                }
                for client in &mut clients {
                    if client.poll_once() {
                        new_count += 1;
                    }
                }
                if prev_count == new_count {
                    break;
                }
            }
            event_count += new_count;
            let mut result = false;
            for node in &mut nodes {
                result = result || node.resend_unacknowledged()
            }
            for client in &mut clients {
                result = result || client.resend_unacknowledged();
            }
            if !result && new_count == 0 {
                break;
            }
        }
        for node in &mut nodes {
            node.clear_state();
        }
        trace!("Processed {} events.", event_count);

        'client_loop: for (client, data) in clients.iter_mut().zip(new_data) {
            while let Ok(event) = client.try_recv() {
                match event {
                    Event::Response { response: Response::PostSuccess(..), .. } => {
                        trace!("Client {:?} received PostSuccess.", client.name());
                        all_data[j] = data.clone();
                        successes += 1;
                        continue 'client_loop;
                    }
                    Event::Response { response: Response::PostFailure { .. }, .. } => {
                        trace!("Client {:?} received PostFailure.", client.name());
                        continue 'client_loop;
                    }
                    _ => (),
                }
            }
            panic!("No response received for {:?}.", data.identifier());
        }

        mock_crust_detail::check_data(all_data.clone(), &nodes);
        mock_crust_detail::verify_kademlia_invariant_for_all_nodes(&nodes);
    }

    for data in &all_data {
        match *data {
            Data::Structured(ref sent_structured_data) => {
                match clients[0].get(sent_structured_data.identifier(), &mut nodes) {
                    Data::Structured(recovered_structured_data) => {
                        assert_eq!(recovered_structured_data, *sent_structured_data);
                    }
                    unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                }
            }
            _ => unreachable!(),
        }
    }

    assert!(successes > 0, "No Put attempt succeeded.");
}


#[test]
fn structured_data_operations_with_churn_with_cache() {
    structured_data_operations_with_churn(true);
}

#[test]
fn structured_data_operations_with_churn_without_cache() {
    structured_data_operations_with_churn(false);
}

fn structured_data_operations_with_churn(use_cache: bool) {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, use_cache);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut all_data: Vec<Data> = vec![];
    let mut deleted_data = vec![];
    let mut rng = network.new_rng();
    let mut event_count = 0;

    for i in 0..10 {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());
        let mut new_data = vec![];
        let mut mutated_data = HashSet::new();
        for _ in 0..4 {
            if all_data.is_empty() || rng.gen() {
                let data =
                    Data::Structured(test_utils::random_structured_data(Range::new(10001, 20000)
                                                                            .ind_sample(&mut rng),
                                                                        client.full_id(),
                                                                        &mut rng));
                trace!("Putting data {:?} with name {:?}.",
                       data.identifier(),
                       data.name());
                client.put(data.clone());
                new_data.push(data);
            } else {
                let j = Range::new(0, all_data.len()).ind_sample(&mut rng);
                let data = Data::Structured(if let Data::Structured(sd) = all_data[j].clone() {
                    if !mutated_data.insert(sd.identifier()) {
                        trace!("Skipping data {:?} with name {:?}.",
                               sd.identifier(),
                               sd.name());
                        continue;
                    }
                    unwrap_result!(StructuredData::new(sd.get_type_tag(),
                                                       *sd.name(),
                                                       sd.get_version() + 1,
                                                       rng.gen_iter().take(10).collect(),
                                                       sd.get_owner_keys().clone(),
                                                       vec![],
                                                       Some(client.full_id()
                                                           .signing_private_key())))
                } else {
                    panic!("Non-structured data found.");
                });
                if false {
                    // FIXME: Delete tests are disabled right now.
                    trace!("Deleting data {:?} with name {:?}",
                           data.identifier(),
                           data.name());
                    client.delete(data);
                    deleted_data.push(all_data.remove(j));
                } else {
                    trace!("Posting data {:?} with name {:?}.",
                           data.identifier(),
                           data.name());
                    all_data[j] = data.clone();
                    client.post(data);
                }
            }
        }
        all_data.extend(new_data);
        if nodes.len() <= GROUP_SIZE + 2 || Range::new(0, 4).ind_sample(&mut rng) < 3 {
            let index = Range::new(1, nodes.len()).ind_sample(&mut rng);
            test_node::add_node(&network, &mut nodes, index, use_cache);
            trace!("Adding node {:?} with bootstrap node {}.",
                   nodes[index].name(),
                   index);
        } else {
            let number = Range::new(3, 4).ind_sample(&mut rng);
            let mut removed_nodes = Vec::new();
            for _ in 0..number {
                let node_range = Range::new(1, nodes.len());
                let node_index = node_range.ind_sample(&mut rng);
                removed_nodes.push(nodes[node_index].name());
                test_node::drop_node(&mut nodes, node_index);
            }
            trace!("Removing {} node(s). {:?}", number, removed_nodes);
        }
        event_count += poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);

        for node in &mut nodes {
            node.clear_state();
        }
        trace!("Processed {} events.", event_count);

        mock_crust_detail::check_data(all_data.clone(), &nodes);
        mock_crust_detail::check_deleted_data(&deleted_data, &nodes);
        mock_crust_detail::verify_kademlia_invariant_for_all_nodes(&nodes);
    }

    for data in &all_data {
        match *data {
            Data::Structured(ref sent_structured_data) => {
                match client.get(sent_structured_data.identifier(), &mut nodes) {
                    Data::Structured(recovered_structured_data) => {
                        assert_eq!(recovered_structured_data, *sent_structured_data);
                    }
                    unexpected_data => panic!("Got unexpected data: {:?}", unexpected_data),
                }
            }
            _ => unreachable!(),
        }
    }

    for data in &deleted_data {
        match client.get_response(data.identifier(), &mut nodes) {
            Err(Some(error)) => assert_eq!(error, GetError::NoSuchData),
            unexpected => panic!("Got unexpected response: {:?}", unexpected),
        }
    }
}

#[test]
fn handle_priv_appendable_normal_flow() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();
    let (pub_key, secret_key) = sign::gen_keypair();
    let (pub_encrypt_key, _) = box_::gen_keypair();
    let mut rng = network.new_rng();
    let mut ad = test_utils::random_priv_appendable_data(&full_id, pub_encrypt_key, &mut rng);
    let data = Data::PrivAppendable(ad.clone());
    let _ = client.put_and_verify(data.clone(), &mut nodes);
    assert_eq!(data, client.get(data.identifier(), &mut nodes));
    let pointer = DataIdentifier::Structured(rng.gen(), 12345);
    let appended_data = unwrap_result!(AppendedData::new(pointer, pub_key, &secret_key));
    let pad = unwrap_result!(PrivAppendedData::new(&appended_data, &pub_encrypt_key));
    let wrapper = unwrap_result!(AppendWrapper::new_priv(*data.name(),
                                                         pad.clone(),
                                                         (&pub_key, &secret_key),
                                                         0));
    let _ = client.append_and_verify(wrapper, &mut nodes);
    ad.append(pad, &pub_key);
    assert_eq!(Data::PrivAppendable(ad),
               client.get(data.identifier(), &mut nodes));
}

#[test]
fn handle_pub_appendable_normal_flow() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();
    let mut rng = network.new_rng();
    let mut ad = test_utils::random_pub_appendable_data(&full_id, &mut rng);
    let (pub_key, secret_key) = sign::gen_keypair();
    let data = Data::PubAppendable(ad.clone());
    let _ = client.put_and_verify(data.clone(), &mut nodes);
    assert_eq!(data, client.get(data.identifier(), &mut nodes));
    let pointer = DataIdentifier::Structured(rng.gen(), 12345);
    let appended_data = unwrap_result!(AppendedData::new(pointer, pub_key, &secret_key));
    let wrapper = AppendWrapper::new_pub(*data.name(), appended_data.clone(), 0);
    let _ = client.append_and_verify(wrapper, &mut nodes);
    ad.append(appended_data);
    assert_eq!(Data::PubAppendable(ad),
               client.get(data.identifier(), &mut nodes));
}

#[test]
fn appendable_data_operations_with_churn_with_cache() {
    appendable_data_operations_with_churn(true);
}

#[test]
fn appendable_data_operations_with_churn_without_cache() {
    appendable_data_operations_with_churn(false);
}

fn appendable_data_operations_with_churn(use_cache: bool) {
    let network = Network::new(None);
    let node_count = TEST_NET_SIZE;
    let mut nodes = test_node::create_nodes(&network, node_count, None, use_cache);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();
    let mut rng = network.new_rng();
    let mut ad = test_utils::random_pub_appendable_data(&full_id, &mut rng);
    let (pub_key, secret_key) = sign::gen_keypair();
    let data = Data::PubAppendable(ad.clone());
    let _ = client.put_and_verify(data.clone(), &mut nodes);
    assert_eq!(data, client.get(data.identifier(), &mut nodes));
    let mut event_count = 0;

    for i in 0..10 {
        trace!("Iteration {}. Network size: {}", i + 1, nodes.len());
        let pointer = DataIdentifier::Structured(rng.gen(), 12345);
        let appended_data = unwrap_result!(AppendedData::new(pointer, pub_key, &secret_key));
        let wrapper = AppendWrapper::new_pub(*data.name(), appended_data.clone(), 0);
        let _ = client.append_and_verify(wrapper, &mut nodes);
        ad.append(appended_data);
        assert_eq!(Data::PubAppendable(ad.clone()),
                   client.get(data.identifier(), &mut nodes));

        if nodes.len() <= GROUP_SIZE + 2 || Range::new(0, 4).ind_sample(&mut rng) < 3 {
            let index = Range::new(1, nodes.len()).ind_sample(&mut rng);
            test_node::add_node(&network, &mut nodes, index, use_cache);
            trace!("Adding node {:?} with bootstrap node {}.",
                   nodes[index].name(),
                   index);
        } else {
            let number = Range::new(3, 4).ind_sample(&mut rng);
            let mut removed_nodes = Vec::new();
            for _ in 0..number {
                let node_range = Range::new(1, nodes.len());
                let node_index = node_range.ind_sample(&mut rng);
                removed_nodes.push(nodes[node_index].name());
                test_node::drop_node(&mut nodes, node_index);
            }
            trace!("Removing {} node(s). {:?}", number, removed_nodes);
        }
        event_count += poll::poll_and_resend_unacknowledged(&mut nodes, &mut client);

        for node in &mut nodes {
            node.clear_state();
        }
        trace!("Processed {} events.", event_count);
    }
}

#[test]
fn handle_put_get_normal_flow() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();
    let mut all_data: Vec<Data> = vec![];
    let mut rng = network.new_rng();

    for i in 0..GROUP_SIZE {
        let data = if i % 2 == 0 {
            Data::Structured(test_utils::random_structured_data(100000, &full_id, &mut rng))
        } else {
            Data::Immutable(ImmutableData::new(rng.gen_iter().take(10).collect()))
        };
        let _ = client.put_and_verify(data.clone(), &mut nodes);
        all_data.push(data);
    }
    for i in 0..GROUP_SIZE {
        let data = client.get(all_data[i].identifier(), &mut nodes);
        assert_eq!(data, all_data[i]);
    }
}

#[test]
fn handle_put_get_error_flow() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    // Putting to existing immutable data
    let im = Data::Immutable(ImmutableData::new(rng.gen_iter().take(10).collect()));
    let _ = client.put_and_verify(im.clone(), &mut nodes);
    match client.put_and_verify(im.clone(), &mut nodes) {
        Ok(_) => {}
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Putting to existing structured data
    let full_id = client.full_id().clone();
    let sd = Data::Structured(test_utils::random_structured_data(100000, &full_id, &mut rng));
    let _ = client.put_and_verify(sd.clone(), &mut nodes);
    match client.put_and_verify(sd.clone(), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::DataExists),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Get non-existing immutable data
    let non_existing_im = ImmutableData::new(rng.gen_iter().take(10).collect());
    match client.get_response(non_existing_im.identifier(), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, GetError::NoSuchData),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Get non-existing structured data
    let non_existing_sd = test_utils::random_structured_data(100000, &full_id, &mut rng);
    match client.get_response(non_existing_sd.identifier(), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, GetError::NoSuchData),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }
}

#[test]
fn handle_post_error_flow() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();
    let sd = test_utils::random_structured_data(100000, &full_id, &mut rng);

    // Posting to non-existing structured data
    match client.post_response(Data::Structured(sd.clone()), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::NoSuchData),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Putting the structured data
    let _ = client.put_and_verify(Data::Structured(sd.clone()), &mut nodes);

    // Posting with incorrect type_tag
    let incorrect_tag_sd = StructuredData::new(200000,
                                               *sd.name(),
                                               1,
                                               sd.get_data().clone(),
                                               vec![full_id.public_id()
                                                        .signing_public_key()
                                                        .clone()],
                                               vec![],
                                               Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.post_response(Data::Structured(incorrect_tag_sd), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::NoSuchData),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Posting with incorrect version
    let incorrect_version_sd = StructuredData::new(100000,
                                                   *sd.name(),
                                                   3,
                                                   sd.get_data().clone(),
                                                   vec![full_id.public_id()
                                                            .signing_public_key()
                                                            .clone()],
                                                   vec![],
                                                   Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.post_response(Data::Structured(incorrect_version_sd), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::InvalidSuccessor),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Posting with incorrect signature
    let new_full_id = FullId::new();
    let incorrect_signed_sd = StructuredData::new(100000,
                                                  *sd.name(),
                                                  1,
                                                  sd.get_data().clone(),
                                                  vec![new_full_id.public_id()
                                                           .signing_public_key()
                                                           .clone()],
                                                  vec![],
                                                  Some(new_full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.post_response(Data::Structured(incorrect_signed_sd), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::InvalidSuccessor),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Posting correctly
    let new_sd = StructuredData::new(100000,
                                     *sd.name(),
                                     1,
                                     sd.get_data().clone(),
                                     vec![full_id.public_id().signing_public_key().clone()],
                                     vec![],
                                     Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.post_response(Data::Structured(new_sd), &mut nodes) {
        Ok(data_id) => assert_eq!(data_id, sd.identifier()),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }
}

#[test]
#[ignore] // TODO: Delete is currently disabled.
fn handle_delete_error_flow() {
    let network = Network::new(None);
    let node_count = 15;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);
    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));
    let mut rng = network.new_rng();

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let full_id = client.full_id().clone();
    let sd = test_utils::random_structured_data(100000, &full_id, &mut rng);

    // Deleting a non-existing structured data
    match client.delete_response(Data::Structured(sd.clone()), &mut nodes) {
        // TODO: MutationError::NoSuchData is preferred to be returned in this scenario
        Err(Some(error)) => assert_eq!(error, MutationError::InvalidSuccessor),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Putting the structured data
    let _ = client.put_and_verify(Data::Structured(sd.clone()), &mut nodes);

    // Deleting with incorrect type_tag
    let incorrect_tag_sd = StructuredData::new(200000,
                                               *sd.name(),
                                               1,
                                               sd.get_data().clone(),
                                               vec![full_id.public_id()
                                                        .signing_public_key()
                                                        .clone()],
                                               vec![],
                                               Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.delete_response(Data::Structured(incorrect_tag_sd), &mut nodes) {
        // TODO: MutationError::NoSuchData is preferred to be returned in this scenario
        //       As `type_tag` is part of the name
        Err(Some(error)) => assert_eq!(error, MutationError::InvalidSuccessor),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Deleting with incorrect version
    let incorrect_version_sd = StructuredData::new(100000,
                                                   *sd.name(),
                                                   3,
                                                   sd.get_data().clone(),
                                                   vec![full_id.public_id()
                                                            .signing_public_key()
                                                            .clone()],
                                                   vec![],
                                                   Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.delete_response(Data::Structured(incorrect_version_sd), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::InvalidSuccessor),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Deleting with incorrect signature
    let new_full_id = FullId::new();
    let incorrect_signed_sd = StructuredData::new(100000,
                                                  *sd.name(),
                                                  1,
                                                  sd.get_data().clone(),
                                                  vec![new_full_id.public_id()
                                                           .signing_public_key()
                                                           .clone()],
                                                  vec![],
                                                  Some(new_full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.delete_response(Data::Structured(incorrect_signed_sd), &mut nodes) {
        Err(Some(error)) => assert_eq!(error, MutationError::InvalidSuccessor),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }

    // Deleting correctly
    let new_sd = StructuredData::new(100000,
                                     *sd.name(),
                                     1,
                                     sd.get_data().clone(),
                                     vec![full_id.public_id().signing_public_key().clone()],
                                     vec![],
                                     Some(full_id.signing_private_key()))
        .expect("Cannot create structured data for test");
    match client.delete_response(Data::Structured(new_sd), &mut nodes) {
        Ok(data_id) => assert_eq!(data_id, sd.identifier()),
        unexpected => panic!("Got unexpected response: {:?}", unexpected),
    }
}

#[test]
fn caching_with_data_not_close_to_proxy_node() {
    let network = Network::new(None);
    let node_count = GROUP_SIZE + 2;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);

    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);

    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let mut rng = network.new_rng();

    let sent_data = gen_random_immutable_data_not_close_to(&nodes[0], &mut rng);
    let _ = client.put_and_verify(sent_data.clone(), &mut nodes);

    // The first response is not yet cached, so it comes from a NAE manager authority.
    let (received_data, src) = client.get_with_src(sent_data.identifier(), &mut nodes);
    assert_eq!(received_data, sent_data);

    match src {
        Authority::NaeManager(_) => (),
        authority => {
            panic!("Response is cached (unexpected src authority {:?})",
                   authority)
        }
    }

    // The second response is cached, so it comes from a managed node authority.
    let (received_data, src) = client.get_with_src(sent_data.identifier(), &mut nodes);
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
    let network = Network::new(None);
    let node_count = GROUP_SIZE + 2;
    let mut nodes = test_node::create_nodes(&network, node_count, None, true);

    let config = mock_crust::Config::with_contacts(&[nodes[0].endpoint()]);

    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);
    let mut rng = network.new_rng();

    let sent_data = gen_random_immutable_data_close_to(&nodes[0], &mut rng);
    let _ = client.put_and_verify(sent_data.clone(), &mut nodes);

    // Send two requests and verify the response is not cached in any of them
    let (received_data, src) = client.get_with_src(sent_data.identifier(), &mut nodes);
    assert_eq!(received_data, sent_data);

    match src {
        Authority::NaeManager(_) => (),
        authority => {
            panic!("Response is cached (unexpected src authority {:?})",
                   authority)
        }
    }

    let (received_data, src) = client.get_with_src(sent_data.identifier(), &mut nodes);
    assert_eq!(received_data, sent_data);

    match src {
        Authority::NaeManager(_) => (),
        authority => {
            panic!("Response is cached (unexpected src authority {:?})",
                   authority)
        }
    }
}

fn gen_random_immutable_data_close_to<R: Rng>(node: &TestNode, rng: &mut R) -> Data {
    loop {
        let data = Data::Immutable(test_utils::random_immutable_data(10, rng));
        if node.routing_table().is_close(&data.name(), GROUP_SIZE) {
            return data;
        }
    }
}

fn gen_random_immutable_data_not_close_to<R: Rng>(node: &TestNode, rng: &mut R) -> Data {
    loop {
        let data = Data::Immutable(test_utils::random_immutable_data(10, rng));
        if !node.routing_table().is_close(&data.name(), GROUP_SIZE) {
            return data;
        }
    }
}
