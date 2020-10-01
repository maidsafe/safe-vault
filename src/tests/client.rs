// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Network;
use safe_core::client::{blob_apis::exported_tests as blob_apis, exported_tests as client_tests};
use std::sync::Once;

static mut NETWORK: Network = Network { nodes: Vec::new() };
static START: Once = Once::new();

#[allow(unsafe_code)]
fn start_network() {
    START.call_once(|| unsafe {
        NETWORK = futures::executor::block_on(Network::new(7));
    });
}

#[tokio::test]
async fn client_creation() {
    start_network();
    assert!(client_tests::client_creation().await.is_ok());
}

#[tokio::test]
async fn client_creation_for_existing_sk() {
    start_network();
    assert!(client_tests::client_creation_for_existing_sk()
        .await
        .is_ok());
}

#[tokio::test]
async fn pub_blob_test() {
    start_network();
    assert!(blob_apis::pub_blob_test().await.is_ok());
}
