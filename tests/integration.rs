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
use safe_nd::{AccountData, Coins, Error as NdError, Request, Response, XorName};
use unwrap::unwrap;

#[test]
fn client_connects() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();
    let mut client = TestClient::new(env.rng());
    let _ = client.establish_connection(&mut env, &mut vault);
}

#[test]
fn get_balance() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();

    let mut client = TestClient::new(env.rng());
    let conn_info = client.establish_connection(&mut env, &mut vault);

    let message_id = client.send_request(conn_info, Request::GetBalance);
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::GetBalance(Ok(coins)) if coins == unwrap!(Coins::from_nano(0)) => (),
        x => unexpected!(x),
    }

    // TODO: expand this test to cover non-zero balance cases too.
}

#[test]
fn accounts() {
    let mut env = Environment::new();
    let mut vault = TestVault::new();

    let mut client = TestClient::new(env.rng());
    let conn_info = client.establish_connection(&mut env, &mut vault);

    let account_data = vec![0; 32];
    let account_locator: XorName = rand::random();

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
        client.public_id().public_key().clone(),
        account_data.clone(),
        client.full_id().sign(&account_data),
    ));

    let message_id = client.send_request(conn_info.clone(), Request::CreateAccount(account));
    env.poll(&mut vault);

    match client.expect_response(message_id) {
        Response::Mutation(Ok(_)) => (),
        x => unexpected!(x),
    }

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
}
