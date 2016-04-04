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

#![deny(unused)]

mod poll;
mod test_client;
mod test_node;

use rand::{thread_rng, Rng};
use rand::distributions::{IndependentSample, Range};
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType};
use routing::mock_crust::{Config, Network};
use xor_name::XorName;

use self::test_client::TestClient;

#[test]
fn plain_data_put_and_get() {
    let network = Network::new();
    let mut nodes = test_node::create_nodes(&network, 8);
    let config = Config::with_contacts(&[nodes[0].endpoint()]);

    let mut client = TestClient::new(&network, Some(config));
    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut content = vec![0; 1024];
    thread_rng().fill_bytes(&mut content);
    let orig_data = ImmutableData::new(ImmutableDataType::Normal, content);

    client.put(Data::Immutable(orig_data.clone()), &mut nodes);

    match client.get(DataRequest::Immutable(orig_data.name(), ImmutableDataType::Normal), &mut nodes) {
        Data::Immutable(data) => {
            assert_eq!(data.name(), orig_data.name());
            assert_eq!(data.value(), orig_data.value());
        },

        d => panic!("Got unexpected data: {:?}", d),
    }
}

#[test]
fn test1() {
    let network = Network::new();
    let mut nodes = test_node::create_nodes(&network, 2 * 8);
    let config = Config::with_contacts(&[nodes[0].endpoint()]);
    let mut client = TestClient::new(&network, Some(config));

    client.ensure_connected(&mut nodes);
    client.create_account(&mut nodes);

    let mut orig_data = Vec::new();
    let mut rng = thread_rng();
    let range = Range::new(128, 1024);
    let num_puts = 100;

    for _ in 0..num_puts {
        let size = range.ind_sample(&mut rng);
        let mut content = vec![0; size];
        rng.fill_bytes(&mut content);
        let immutable_data = ImmutableData::new(ImmutableDataType::Normal, content);
        orig_data.push(immutable_data);
    }

    for i in 0..orig_data.len() {
        client.put(Data::Immutable(orig_data[i].clone()), &mut nodes);
    }

    for i in 0..orig_data.len() {
        match client.get(DataRequest::Immutable(orig_data[i].name(), ImmutableDataType::Normal), &mut nodes) {
            Data::Immutable(immutable_data) => {
                assert!(immutable_data.name() == orig_data[i].name());
                assert!(immutable_data.value() == orig_data[i].value());
            },
            d => panic!("Got unexpected data: {:?}", d),
        }
    }

    let mut stored_names = Vec::new();

    for node in &nodes {
        stored_names.append(&mut node.get_stored_names());
    }

    stored_names.sort();
    stored_names.dedup();
    stored_names.retain(|&stored_name|
        orig_data.iter()
                 .find(|&immutable_data| immutable_data.name() == stored_name)
                 .is_some());

    let mut orig_data_names = orig_data.iter()
                                       .cloned()
                                       .map(|immutable_data| immutable_data.name().clone())
                                       .collect::<Vec<XorName>>();
    orig_data_names.sort();

    assert_eq!(stored_names.len(), orig_data_names.len());
    assert_eq!(orig_data_names.iter()
                              .zip(stored_names)
                              .filter(|&(data_name, stored_name)| *data_name == stored_name)
                              .count(), num_puts);
}
