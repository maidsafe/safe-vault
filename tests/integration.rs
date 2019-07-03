// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO: make these tests work without mock too.
#![cfg(feature = "mock")]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[macro_use]
mod common;

use self::common::{Environment, TestClient, TestVault};
use rand::Rng;
use safe_nd::{AccountData, Coins, Error as NdError, IDataAddress, Request, Response, XorName};
use unwrap::unwrap;

#[test]
fn client_connects() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();
    let mut client = TestClient::new(env.rng());
    common::establish_connection(&mut env, &mut client, &mut vault);
}

#[test]
fn accounts() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();
    let conn_info = vault.connection_info();

    let mut client = TestClient::new(env.rng());
    common::establish_connection(&mut env, &mut client, &mut vault);

    let account_data = vec![0; 32];
    let account_locator: XorName = env.rng().gen();

    // Try to get an account that does not exist yet.
    let message_id = client.send_request(conn_info.clone(), Request::GetAccount(account_locator));
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::GetAccount(Err(NdError::NoSuchAccount)) => (),
        x => unexpected!(x),
    }

    // Create a new account
    let account = unwrap!(AccountData::new(
        account_locator,
        *client.public_id().public_key(),
        account_data.clone(),
        client.full_id().sign(&account_data),
    ));

    common::perform_mutation(
        &mut env,
        &mut client,
        &mut vault,
        Request::CreateAccount(account.clone()),
    );

    // Try to get the account data and signature.
    let message_id = client.send_request(conn_info.clone(), Request::GetAccount(account_locator));
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::GetAccount(Ok((data, sig))) => {
            assert_eq!(data, account_data);

            match client.public_id().public_key().verify(&sig, &data) {
                Ok(()) => (),
                x => unexpected!(x),
            }
        }
        x => unexpected!(x),
    }

    // Putting account to the same address should fail.
    let message_id = client.send_request(conn_info.clone(), Request::CreateAccount(account));
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::Mutation(Err(NdError::AccountExists)) => (),
        x => unexpected!(x),
    }

    // Getting account from non-owning client should fail.
    {
        let mut client = TestClient::new(env.rng());
        common::establish_connection(&mut env, &mut client, &mut vault);

        let message_id =
            client.send_request(conn_info.clone(), Request::GetAccount(account_locator));
        env.poll(&mut vault);

        match client.expect_response(message_id) {
            Response::GetAccount(Err(NdError::AccessDenied)) => (),
            x => unexpected!(x),
        }
    }
}

#[test]
fn update_account() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();
    let conn_info = vault.connection_info();

    let mut client = TestClient::new(env.rng());
    common::establish_connection(&mut env, &mut client, &mut vault);

    let account_data = vec![0; 32];
    let account_locator: XorName = env.rng().gen();

    // Create a new account
    let account = unwrap!(AccountData::new(
        account_locator,
        *client.public_id().public_key(),
        account_data.clone(),
        client.full_id().sign(&account_data),
    ));

    common::perform_mutation(
        &mut env,
        &mut client,
        &mut vault,
        Request::CreateAccount(account.clone()),
    );

    // Update the account data.
    let new_account_data = vec![1; 32];
    let client_public_key = *client.public_id().public_key();
    let signature = client.full_id().sign(&new_account_data);
    common::perform_mutation(
        &mut env,
        &mut client,
        &mut vault,
        Request::UpdateAccount(unwrap!(AccountData::new(
            account_locator,
            client_public_key,
            new_account_data.clone(),
            signature,
        ))),
    );

    // Try to get the account data and signature.
    let message_id = client.send_request(conn_info.clone(), Request::GetAccount(account_locator));
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::GetAccount(Ok((data, sig))) => {
            assert_eq!(data, new_account_data);
            unwrap!(client.public_id().public_key().verify(&sig, &data));
        }
        x => unexpected!(x),
    }

    // Updating account from non-owning client should fail.
    {
        let mut client = TestClient::new(env.rng());
        common::establish_connection(&mut env, &mut client, &mut vault);

        let message_id =
            client.send_request(conn_info.clone(), Request::UpdateAccount(account.clone()));
        env.poll(&mut vault);

        match client.expect_response(message_id) {
            Response::Mutation(Err(NdError::AccessDenied)) => (),
            x => unexpected!(x),
        }
    }
}

#[test]
fn coin_operations() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();

    let mut client_a = TestClient::new(env.rng());
    let mut client_b = TestClient::new(env.rng());

    common::establish_connection(&mut env, &mut client_a, &mut vault);
    common::establish_connection(&mut env, &mut client_b, &mut vault);

    let balance = common::get_balance(&mut env, &mut client_a, &mut vault);
    assert_eq!(balance, unwrap!(Coins::from_nano(0)));

    // Create A's balance
    let public_key = *client_a.public_id().public_key();
    common::perform_mutation(
        &mut env,
        &mut client_a,
        &mut vault,
        Request::CreateCoinBalance {
            new_balance_owner: public_key,
            amount: unwrap!(Coins::from_nano(10)),
            transaction_id: 0,
        },
    );

    let balance = common::get_balance(&mut env, &mut client_a, &mut vault);
    assert_eq!(balance, unwrap!(Coins::from_nano(10)));

    // Create B'a balance
    common::perform_mutation(
        &mut env,
        &mut client_a,
        &mut vault,
        Request::CreateCoinBalance {
            new_balance_owner: *client_b.public_id().public_key(),
            amount: unwrap!(Coins::from_nano(1)),
            transaction_id: 0,
        },
    );

    let balance_a = common::get_balance(&mut env, &mut client_a, &mut vault);
    let balance_b = common::get_balance(&mut env, &mut client_b, &mut vault);
    assert_eq!(balance_a, unwrap!(Coins::from_nano(9)));
    assert_eq!(balance_b, unwrap!(Coins::from_nano(1)));

    // Transfer coins from A to B
    common::perform_mutation(
        &mut env,
        &mut client_a,
        &mut vault,
        Request::TransferCoins {
            destination: *client_b.public_id().name(),
            amount: unwrap!(Coins::from_nano(2)),
            transaction_id: 1,
        },
    );

    let balance_a = common::get_balance(&mut env, &mut client_a, &mut vault);
    let balance_b = common::get_balance(&mut env, &mut client_b, &mut vault);
    assert_eq!(balance_a, unwrap!(Coins::from_nano(7)));
    assert_eq!(balance_b, unwrap!(Coins::from_nano(3)));
}

#[test]
fn get_immutable_data() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();
    let conn_info = vault.connection_info();

    let mut client = TestClient::new(env.rng());
    common::establish_connection(&mut env, &mut client, &mut vault);

    // Get idata that doesn't exist
    let address: XorName = env.rng().gen();
    let message_id = client.send_request(
        conn_info.clone(),
        Request::GetIData(IDataAddress::Pub(address)),
    );
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::GetIData(Err(NdError::NoSuchData)) => (),
        x => unexpected!(x),
    }

    // Unpublished immutable data that we're not the owner of.
    let message_id = client.send_request(
        conn_info.clone(),
        Request::GetIData(IDataAddress::Unpub(address)),
    );
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::GetIData(Err(NdError::AccessDenied)) => (),
        x => unexpected!(x),
    }

    // TODO - Get immutable data that exist once we have PutIData working
}
