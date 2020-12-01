// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// ------------- Client Tests -----------------
// --------------------------------------------
use super::Network;
use sn_client::client::{
    exported_tests as client_tests, map_apis::exported_tests as map_tests,
    sequence_apis::exported_tests as sequence_tests,
    transfer_actor::balance_management::exported_tests as transfer_tests,
    transfer_actor::exported_tests as transfer_actor_tests,
};
use std::sync::Once;

static mut NETWORK: Network = Network { nodes: Vec::new() };
static START: Once = Once::new();

#[allow(unsafe_code)]
fn start_network() {
    START.call_once(|| unsafe {
        NETWORK = futures::executor::block_on(Network::new(11));
    });
}

// --------------------------------------------
#[cfg(feature = "simulated-payouts")]
mod test {
    use super::*;
    #[tokio::test]
    async fn client_creation() {
        start_network();
        assert!(client_tests::client_creation().await.is_ok());
    }

    #[tokio::test]
    async fn client_creation_for_existing_sk() {
        start_network();
        assert!(client_tests::client_creation_with_existing_keypair()
            .await
            .is_ok());
    }

    // --------------------------------------------
    // --------- Transfer Actor Tests -------------
    // --------------------------------------------

    #[tokio::test]
    async fn transfer_actor_creation_hydration_for_nonexistant_balance() {
        start_network();
        assert!(
            transfer_actor_tests::transfer_actor_creation_hydration_for_nonexistant_balance()
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn transfer_actor_creation_hydration_for_existing_balance() {
        start_network();
        assert!(
            transfer_actor_tests::transfer_actor_creation_hydration_for_existing_balance()
                .await
                .is_ok()
        );
    }

    // --------------------------------------------
    // ------------ Transfer Tests ----------------
    // --------------------------------------------

    #[tokio::test]
    async fn cannot_write_with_insufficient_balance() {
        start_network();
        assert!(transfer_tests::cannot_write_with_insufficient_balance()
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn insufficient_balance_transfers() {
        start_network();
        assert!(transfer_tests::insufficient_balance_transfers()
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn transfer_actor_cannot_send_0_money_req() {
        start_network();
        assert!(transfer_tests::transfer_actor_cannot_send_0_money_req()
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn transfer_actor_can_send_several_transfers_and_thats_reflected_locally() {
        start_network();
        assert!(
            transfer_tests::transfer_actor_can_send_several_transfers_and_thats_reflected_locally()
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn transfer_actor_can_send_money_and_thats_reflected_locally() {
        start_network();
        assert!(
            transfer_tests::transfer_actor_can_send_money_and_thats_reflected_locally()
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn balance_transfers_between_clients() {
        start_network();
        assert!(transfer_tests::balance_transfers_between_clients()
            .await
            .is_ok());
    }

    // --------------------------------------------
    // ---------- Sequence Data Tests -------------
    // --------------------------------------------

    #[tokio::test]
    async fn append_to_sequence_test() {
        start_network();
        assert!(sequence_tests::append_to_sequence_test().await.is_ok());
    }

    #[tokio::test]
    async fn sequence_basics_test() {
        start_network();
        assert!(sequence_tests::sequence_basics_test().await.is_ok());
    }

    #[tokio::test]
    async fn sequence_cannot_delete_public_test() {
        start_network();
        assert!(sequence_tests::sequence_cannot_delete_public_test()
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn sequence_deletions_should_cost_put_price() {
        start_network();
        assert!(sequence_tests::sequence_deletions_should_cost_put_price()
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn sequence_private_permissions_test() {
        start_network();
        assert!(sequence_tests::sequence_private_permissions_test()
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn sequence_pub_permissions_test() {
        start_network();
        assert!(sequence_tests::sequence_pub_permissions_test()
            .await
            .is_ok());
    }

    // --------------------------------------------
    // ------------ Map Data Tests ----------------
    // --------------------------------------------

    #[tokio::test]
    async fn del_seq_map_test() {
        start_network();
        assert!(map_tests::del_seq_map_test().await.is_ok());
    }

    #[tokio::test]
    async fn map_cannot_initially_put_data_with_another_owner_than_current_client() {
        start_network();
        assert!(
            map_tests::map_cannot_initially_put_data_with_another_owner_than_current_client()
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn del_unseq_map_test() {
        start_network();
        assert!(map_tests::del_unseq_map_test().await.is_ok());
    }

    #[tokio::test]
    async fn map_deletions_should_cost_put_price() {
        start_network();
        assert!(map_tests::map_deletions_should_cost_put_price()
            .await
            .is_ok());
    }
}
