// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![cfg(feature = "mock_base")]
// For explanation of lint checks, run `rustc -W help`.
#![forbid(unsafe_code)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

#[macro_use]
mod common;

use self::common::{Environment, TestClientTrait};
use maplit::btreemap;
use rand::{distributions::Standard, Rng};
use safe_nd::{
    AppPermissions, ClientFullId, ClientRequest, Coins, CoinsRequest, EntryError, Error as NdError,
    IData, IDataAddress, IDataRequest, LoginPacket, LoginPacketRequest, MData, MDataAction,
    MDataAddress, MDataEntries, MDataKind, MDataPermissionSet, MDataRequest, MDataSeqEntryActions,
    MDataSeqValue, MDataUnseqEntryActions, MDataValue, MDataValues, Message, MessageId,
    PubImmutableData, PublicKey, Request, Response, Result as NdResult, SData, SDataAddress,
    SDataIndex, SDataMutationOperation, SDataOwner, SDataPrivUserPermissions,
    SDataPubUserPermissions, SDataRequest, SDataUser, SDataUserPermissions, SeqMutableData,
    Transaction, UnpubImmutableData, UnseqMutableData, XorName,
};
use safe_vault::{Result, COST_OF_PUT};
use std::collections::{BTreeMap, BTreeSet};
use unwrap::unwrap;

#[test]
fn client_connects() {
    let mut env = Environment::new();
    let client = env.new_connected_client();
    let _app = env.new_connected_app(client.public_id().clone());
}

#[test]
fn invalid_signature() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let name: XorName = env.rng().gen();
    let request = Request::IData(IDataRequest::Get(IDataAddress::Unpub(name)));
    let message_id = MessageId::new();

    // Missing signature
    client.send(&Message::Request {
        request: request.clone(),
        message_id,
        signature: None,
    });
    env.poll();
    match client.expect_response(message_id, &mut env) {
        Response::GetIData(Err(NdError::InvalidSignature)) => (),
        x => unexpected!(x),
    }

    // Invalid signature
    let other_full_id = ClientFullId::new_ed25519(env.rng());
    let to_sign = (&request, &message_id);
    let to_sign = unwrap!(bincode::serialize(&to_sign));
    let signature = other_full_id.sign(&to_sign);

    client.send(&Message::Request {
        request,
        message_id,
        signature: Some(signature),
    });
    env.poll();
    match client.expect_response(message_id, &mut env) {
        Response::GetIData(Err(NdError::InvalidSignature)) => (),
        x => unexpected!(x),
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Login packets
//
////////////////////////////////////////////////////////////////////////////////

#[test]
fn login_packets() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let login_packet_data = vec![0; 32];
    let login_packet_locator: XorName = env.rng().gen();

    let balance = common::multiply_coins(COST_OF_PUT, 2);
    common::create_balance(&mut env, &mut client, None, balance);

    // Try to get a login packet that does not exist yet.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Get(login_packet_locator)),
        NdError::NoSuchLoginPacket,
    );

    // Create a new login packet.
    let login_packet = unwrap!(LoginPacket::new(
        login_packet_locator,
        *client.public_id().public_key(),
        login_packet_data.clone(),
        client.sign(&login_packet_data),
    ));

    common::perform_mutation(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Create(login_packet.clone())),
    );

    // Try to get the login packet data and signature.
    let (data, sig) = common::get_from_response(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Get(login_packet_locator)),
    );
    assert_eq!(data, login_packet_data);
    unwrap!(client.public_id().public_key().verify(&sig, &data));

    // Putting login packet to the same address should fail.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Create(login_packet)),
        NdError::LoginPacketExists,
    );

    // The balance should be unchanged
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(1),
    );

    // Getting login packet from non-owning client should fail.
    {
        let mut client = env.new_connected_client();
        common::send_request_expect_err(
            &mut env,
            &mut client,
            Request::LoginPacket(LoginPacketRequest::Get(login_packet_locator)),
            NdError::AccessDenied,
        );
    }
}

#[test]
fn create_login_packet_for_other() {
    let mut env = Environment::new();
    let mut established_client = env.new_connected_client();
    let mut new_client = env.new_connected_client();
    let mut new_client2 = env.new_connected_client();

    let login_packet_data = vec![0; 32];
    let login_packet_locator: XorName = env.rng().gen();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut established_client, None, 1_000_000_000_000);

    // `new_client` gets `established_client` to create its balance and store its new login packet.
    let login_packet = unwrap!(LoginPacket::new(
        login_packet_locator,
        *new_client.public_id().public_key(),
        login_packet_data.clone(),
        new_client.sign(&login_packet_data),
    ));

    let amount = COST_OF_PUT;
    let nano_to_transfer = 2 * COST_OF_PUT.as_nano();
    common::send_request_expect_ok(
        &mut env,
        &mut established_client,
        Request::LoginPacket(LoginPacketRequest::CreateFor {
            new_owner: *new_client.public_id().public_key(),
            amount,
            new_login_packet: login_packet.clone(),
            transaction_id: 1,
        }),
        Transaction { id: 1, amount },
    );

    // Try to get the login packet data and signature.
    let (data, sig) = common::get_from_response(
        &mut env,
        &mut new_client,
        Request::LoginPacket(LoginPacketRequest::Get(login_packet_locator)),
    );
    assert_eq!(data, login_packet_data);
    unwrap!(new_client.public_id().public_key().verify(&sig, &data));

    // Check the balances have been updated.
    common::send_request_expect_ok(
        &mut env,
        &mut established_client,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(start_nano - nano_to_transfer),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut new_client,
        Request::Coins(CoinsRequest::GetBalance),
        COST_OF_PUT,
    );

    // Putting login packet to the same address should fail.
    common::send_request_expect_err(
        &mut env,
        &mut established_client,
        Request::LoginPacket(LoginPacketRequest::CreateFor {
            new_owner: *new_client.public_id().public_key(),
            amount: Coins::from_nano(nano_to_transfer),
            new_login_packet: login_packet.clone(),
            transaction_id: 2,
        }),
        NdError::BalanceExists,
    );

    // The balance should remain unchanged
    common::send_request_expect_ok(
        &mut env,
        &mut established_client,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(start_nano - nano_to_transfer),
    );

    // Putting login packet to the same address with different balance should fail
    // with `LoginPacketExists`
    common::send_request_expect_err(
        &mut env,
        &mut established_client,
        Request::LoginPacket(LoginPacketRequest::CreateFor {
            new_owner: *new_client2.public_id().public_key(),
            amount,
            new_login_packet: login_packet,
            transaction_id: 3,
        }),
        NdError::LoginPacketExists,
    );

    // The new balance should be created
    common::send_request_expect_ok(
        &mut env,
        &mut new_client2,
        Request::Coins(CoinsRequest::GetBalance),
        amount,
    );

    // The client's balance should be updated
    common::send_request_expect_ok(
        &mut env,
        &mut established_client,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(start_nano - 2 * nano_to_transfer),
    );

    // Getting login packet from non-owning client should fail.
    common::send_request_expect_err(
        &mut env,
        &mut established_client,
        Request::LoginPacket(LoginPacketRequest::Get(login_packet_locator)),
        NdError::AccessDenied,
    );
}

#[test]
fn update_login_packet() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, COST_OF_PUT);

    let login_packet_data = vec![0; 32];
    let login_packet_locator: XorName = env.rng().gen();

    // Create a new login packet.
    let login_packet = unwrap!(LoginPacket::new(
        login_packet_locator,
        *client.public_id().public_key(),
        login_packet_data.clone(),
        client.sign(&login_packet_data),
    ));

    common::perform_mutation(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Create(login_packet.clone())),
    );

    // Update the login packet data.
    let new_login_packet_data = vec![1; 32];
    let client_public_key = *client.public_id().public_key();
    let signature = client.sign(&new_login_packet_data);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Update(unwrap!(LoginPacket::new(
            login_packet_locator,
            client_public_key,
            new_login_packet_data.clone(),
            signature,
        )))),
    );

    // Try to get the login packet data and signature.
    let (data, sig) = common::get_from_response(
        &mut env,
        &mut client,
        Request::LoginPacket(LoginPacketRequest::Get(login_packet_locator)),
    );
    assert_eq!(data, new_login_packet_data);
    unwrap!(client.public_id().public_key().verify(&sig, &data));

    // Updating login packet from non-owning client should fail.
    {
        let mut client = env.new_connected_client();
        common::send_request_expect_err(
            &mut env,
            &mut client,
            Request::LoginPacket(LoginPacketRequest::Update(login_packet)),
            NdError::AccessDenied,
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
//
// Coins
//
////////////////////////////////////////////////////////////////////////////////

#[test]
fn balances() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        NdError::NoSuchBalance,
    );

    // Create A's balance
    let amount_a = Coins::from_nano(10);
    common::create_balance(&mut env, &mut client_a, None, amount_a);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        amount_a,
    );

    let amount_b = Coins::from_nano(1);
    common::create_balance(&mut env, &mut client_a, Some(&mut client_b), amount_b);

    let amount_a = Coins::from_nano(8);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        amount_a,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::Coins(CoinsRequest::GetBalance),
        amount_b,
    );

    // Transfer coins from A to B (first attempt with zero amount doesn't work)
    let amount_zero = Coins::from_nano(0);
    let transaction_id = 2;
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::Transfer {
            destination: *client_b.public_id().name(),
            amount: amount_zero,
            transaction_id,
        }),
        NdError::InvalidOperation,
    );
    common::transfer_coins(&mut env, &mut client_a, &mut client_b, 2, 3);

    let amount_a = Coins::from_nano(6);
    let amount_b = Coins::from_nano(3);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        amount_a,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::Coins(CoinsRequest::GetBalance),
        amount_b,
    );
}

#[test]
fn create_balance_that_already_exists() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    common::create_balance(&mut env, &mut client_a, None, 10);
    common::create_balance(&mut env, &mut client_a, Some(&mut client_b), 4);

    let balance_a = Coins::from_nano(5);
    let balance_b = Coins::from_nano(4);

    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::Coins(CoinsRequest::GetBalance),
        balance_b,
    );

    // Attempt to create the balance for B again. The request fails and A receives an error back.
    let transaction_id = 2;
    let amount = Coins::from_nano(2);
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::CreateBalance {
            new_balance_owner: *client_b.public_id().public_key(),
            amount,
            transaction_id,
        }),
        NdError::BalanceExists,
    );

    // A's balance is refunded.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // B does not receive anything.
    client_b.expect_no_new_message();

    // Attempt to create the balance for A again. This should however work for phase 1
    common::create_balance(&mut env, &mut client_a, None, 2);
    let balance_a = Coins::from_nano(2);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );
}

#[test]
fn transfer_coins_to_balance_that_doesnt_exist() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let client_b = env.new_connected_client();

    let balance_a = Coins::from_nano(10);
    common::create_balance(&mut env, &mut client_a, None, balance_a);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Attempt transfer coins to B's balance which doesn't exist. The request fails and A receives
    // an error back.
    let transaction_id = 4;
    let amount = Coins::from_nano(4);
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::Transfer {
            destination: *client_b.public_id().name(),
            amount,
            transaction_id,
        }),
        NdError::NoSuchBalance,
    );

    // A's balance is refunded.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // B does not receive anything.
    client_b.expect_no_new_message();
}

#[test]
fn balances_by_app() {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();

    // Create initial balance.
    common::create_balance(&mut env, &mut client_a, None, 10);

    // Create an app with all permissions.
    // The `perform_mutations` permission is required to send a `CreateBalance` request.
    let mut app = env.new_disconnected_app(client_a.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::Client(ClientRequest::InsAuthKey {
            key: *app.public_id().public_key(),
            version: 1,
            permissions: AppPermissions {
                transfer_coins: true,
                get_balance: true,
                perform_mutations: true,
            },
        }),
    );
    env.establish_connection(&mut app);

    // Check the balance by the app.
    common::send_request_expect_ok(
        &mut env,
        &mut app,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(10),
    );

    // Create the destination client with balance.
    let mut client_b = env.new_connected_client();
    common::create_balance(&mut env, &mut client_b, None, 0);

    // App transfers some coins.
    let transaction_id = 1;
    common::transfer_coins(&mut env, &mut app, &mut client_b, 1, transaction_id);

    // Check the coins did actually transfer.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(9),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(1),
    );
}

#[test]
fn balances_by_app_with_insufficient_permissions() {
    let mut env = Environment::new();
    let mut owner = env.new_connected_client();

    // Create initial balance.
    let balance = Coins::from_nano(10);
    common::create_balance(&mut env, &mut owner, None, balance);

    // Create an app which does *not* have permission to transfer coins.
    let mut app = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::Client(ClientRequest::InsAuthKey {
            key: *app.public_id().public_key(),
            version: 1,
            permissions: AppPermissions {
                get_balance: false,
                transfer_coins: false,
                perform_mutations: false,
            },
        }),
    );
    env.establish_connection(&mut app);

    // The attempt to get balance by the app fails.
    common::send_request_expect_err(
        &mut env,
        &mut app,
        Request::Coins(CoinsRequest::GetBalance),
        NdError::AccessDenied,
    );

    // The attempt to transfer some coins by the app fails.
    let destination: XorName = env.rng().gen();
    let transaction_id = 1;
    common::send_request_expect_err(
        &mut env,
        &mut app,
        Request::Coins(CoinsRequest::Transfer {
            destination,
            amount: Coins::from_nano(1),
            transaction_id,
        }),
        NdError::AccessDenied,
    );

    // The owners balance is unchanged.
    common::send_request_expect_ok(
        &mut env,
        &mut owner,
        Request::Coins(CoinsRequest::GetBalance),
        balance,
    );
}

////////////////////////////////////////////////////////////////////////////////
//
// Immutable data
//
////////////////////////////////////////////////////////////////////////////////

#[test]
#[ignore]
fn put_immutable_data() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let mut raw_data = vec![0u8; 1024];
    env.rng().fill(raw_data.as_mut_slice());
    let pub_idata = IData::Pub(PubImmutableData::new(raw_data.clone()));
    let unpub_idata = IData::Unpub(UnpubImmutableData::new(
        raw_data,
        *client_b.public_id().public_key(),
    ));

    // Put should fail when the client has no associated balance.
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(pub_idata.clone())),
        NdError::NoSuchBalance,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::IData(IDataRequest::Put(unpub_idata.clone())),
        NdError::NoSuchBalance,
    );

    // Create balances.  Client A starts with 2000 safecoins and spends 1000 to initialise
    // Client B's balance.
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano * 2);
    common::create_balance(&mut env, &mut client_a, Some(&mut client_b), start_nano);

    // Check client A can't Put an UnpubIData where B is the owner.
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(unpub_idata.clone())),
        NdError::InvalidOwners,
    );

    let mut expected_a = Coins::from_nano(start_nano - 1);
    let mut expected_b = Coins::from_nano(start_nano);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        expected_a,
    );

    // Check they can both Put valid data.
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(pub_idata.clone())),
    );
    common::perform_mutation(
        &mut env,
        &mut client_b,
        Request::IData(IDataRequest::Put(unpub_idata.clone())),
    );

    expected_a = unwrap!(expected_a.checked_sub(COST_OF_PUT));
    expected_b = unwrap!(expected_b.checked_sub(COST_OF_PUT));
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        expected_a,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::Coins(CoinsRequest::GetBalance),
        expected_b,
    );

    // Check the data is retrievable.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Get(*pub_idata.address())),
        pub_idata.clone(),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::IData(IDataRequest::Get(*unpub_idata.address())),
        unpub_idata.clone(),
    );

    // Published data can be put again, but unpublished not
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(pub_idata)),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::IData(IDataRequest::Put(unpub_idata)),
        NdError::DataExists,
    );

    expected_a = unwrap!(expected_a.checked_sub(COST_OF_PUT));
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        expected_a,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::Coins(CoinsRequest::GetBalance),
        expected_b,
    );
}

#[test]
fn get_immutable_data_that_doesnt_exist() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    // Try to get non-existing published immutable data
    let address: XorName = env.rng().gen();
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Pub(address))),
        NdError::NoSuchData,
    );

    // Try to get non-existing unpublished immutable data while having no balance
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Unpub(address))),
        NdError::NoSuchData,
    );

    // Try to get non-existing unpublished immutable data while having balance
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Unpub(address))),
        NdError::NoSuchData,
    );
}

#[test]
fn get_immutable_data_from_other_owner() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);
    common::create_balance(&mut env, &mut client_b, None, start_nano);

    // Client A uploads published data that Client B can fetch
    let pub_idata = IData::Pub(PubImmutableData::new(vec![1, 2, 3]));
    let mut request = Request::IData(IDataRequest::Get(*pub_idata.address()));
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(pub_idata.clone())),
    );
    common::send_request_expect_ok(&mut env, &mut client_a, request.clone(), pub_idata.clone());
    common::send_request_expect_ok(&mut env, &mut client_b, request, pub_idata);

    // Client A uploads unpublished data that Client B can't fetch
    let owner = client_a.public_id().public_key();
    let unpub_idata = IData::Unpub(UnpubImmutableData::new(vec![42], *owner));
    request = Request::IData(IDataRequest::Get(*unpub_idata.address()));
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(unpub_idata.clone())),
    );
    common::send_request_expect_ok(&mut env, &mut client_a, request.clone(), unpub_idata);
    common::send_request_expect_err(&mut env, &mut client_b, request, NdError::AccessDenied);
}

#[test]
fn put_pub_and_get_unpub_immutable_data_at_same_xor_name() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    // Create balance.
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    // Put and verify some published immutable data
    let pub_idata = IData::Pub(PubImmutableData::new(vec![1, 2, 3]));
    let pub_idata_address: XorName = *pub_idata.address().name();
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Put(pub_idata.clone())),
    );
    assert_eq!(
        pub_idata,
        common::get_from_response(
            &mut env,
            &mut client,
            Request::IData(IDataRequest::Get(IDataAddress::Pub(pub_idata_address)))
        ),
    );

    // Get some unpublished immutable data from the same address
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Unpub(pub_idata_address))),
        NdError::NoSuchData,
    );
}

#[test]
fn put_unpub_and_get_pub_immutable_data_at_same_xor_name() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    // Create balances.
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    // Put and verify some unpub immutable data
    let owner = client.public_id().public_key();
    let unpub_idata = IData::Unpub(UnpubImmutableData::new(vec![1, 2, 3], *owner));
    let unpub_idata_address: XorName = *unpub_idata.address().name();
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Put(unpub_idata.clone())),
    );
    assert_eq!(
        unpub_idata,
        common::get_from_response(
            &mut env,
            &mut client,
            Request::IData(IDataRequest::Get(IDataAddress::Unpub(unpub_idata_address)))
        ),
    );

    // Get some published immutable data from the same address
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Pub(unpub_idata_address))),
        NdError::NoSuchData,
    );
}

#[test]
fn delete_immutable_data_that_doesnt_exist() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    // Try to delete non-existing published idata while not having a balance
    let address: XorName = env.rng().gen();
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Pub(address))),
        NdError::InvalidOperation,
    );

    // Try to delete non-existing unpublished data while not having a balance
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Unpub(address))),
        NdError::NoSuchData,
    );

    // Try to delete non-existing unpublished data
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::IData(IDataRequest::Get(IDataAddress::Unpub(address))),
        NdError::NoSuchData,
    );
}

#[test]
fn delete_immutable_data() {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);

    let raw_data = vec![1, 2, 3];
    let pub_idata = IData::Pub(PubImmutableData::new(raw_data));
    let pub_idata_address: XorName = *pub_idata.address().name();
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(pub_idata)),
    );

    // Try to delete published data by constructing inconsistent Request
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Pub(
            pub_idata_address,
        ))),
        NdError::InvalidOperation,
    );

    // Try to delete published data by raw XorName
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Unpub(
            pub_idata_address,
        ))),
        NdError::NoSuchData,
    );

    let raw_data = vec![42];
    let owner = client_a.public_id().public_key();
    let unpub_idata = IData::Unpub(UnpubImmutableData::new(raw_data, *owner));
    let unpub_idata_address: XorName = *unpub_idata.address().name();
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::Put(unpub_idata)),
    );

    // Delete unpublished data without being the owner
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Unpub(
            unpub_idata_address,
        ))),
        NdError::AccessDenied,
    );

    // Delete unpublished data without having the balance
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Unpub(
            unpub_idata_address,
        ))),
    );

    // Delete unpublished data again
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::IData(IDataRequest::DeleteUnpub(IDataAddress::Unpub(
            unpub_idata_address,
        ))),
        NdError::NoSuchData,
    )
}

////////////////////////////////////////////////////////////////////////////////
//
// Auth keys
//
////////////////////////////////////////////////////////////////////////////////

#[test]
fn auth_keys() {
    type KeysResult = NdResult<(BTreeMap<PublicKey, AppPermissions>, u64)>;
    fn list_keys<T: TestClientTrait>(env: &mut Environment, client: &mut T, expected: KeysResult) {
        let request = Request::Client(ClientRequest::ListAuthKeysAndVersion);
        match expected {
            Ok(expected) => common::send_request_expect_ok(env, client, request, expected),
            Err(expected) => common::send_request_expect_err(env, client, request, expected),
        }
    }

    let mut env = Environment::new();
    let mut owner = env.new_connected_client();
    let mut app = env.new_connected_app(owner.public_id().clone());

    // Create an app with some permissions to mutate and view the balance.
    let permissions = AppPermissions {
        transfer_coins: false,
        perform_mutations: true,
        get_balance: true,
    };
    let app_public_key = *app.public_id().public_key();
    let make_ins_request = |version| {
        Request::Client(ClientRequest::InsAuthKey {
            key: app_public_key,
            version,
            permissions,
        })
    };

    // TODO - enable this once we're passed phase 1.
    if false {
        // Try to insert and then list authorised keys usin)g a client with no balance. Each should
        // return `NoSuchBalance`.
        common::send_request_expect_err(
            &mut env,
            &mut owner,
            make_ins_request(1),
            NdError::NoSuchBalance,
        );
        list_keys(&mut env, &mut owner, Err(NdError::NoSuchBalance));
    }

    // Create a balance for the owner.
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut owner, None, start_nano);

    // The app receives the transaction notification too.
    let _ = app.expect_notification(&mut env);

    // Check that listing authorised keys returns an empty collection.
    let mut expected_map = BTreeMap::new();
    list_keys(&mut env, &mut owner, Ok((expected_map.clone(), 0)));

    // Insert then list the app.
    let _ = expected_map.insert(*app.public_id().public_key(), permissions);
    common::perform_mutation(&mut env, &mut owner, make_ins_request(1));
    list_keys(&mut env, &mut owner, Ok((expected_map.clone(), 1)));

    // Check the app isn't allowed to get a listing of authorised keys, nor insert, nor delete any.
    common::send_request_expect_err(
        &mut env,
        &mut app,
        Request::Client(ClientRequest::ListAuthKeysAndVersion),
        NdError::AccessDenied,
    );
    common::send_request_expect_err(
        &mut env,
        &mut app,
        make_ins_request(2),
        NdError::AccessDenied,
    );
    let del_auth_key_request = Request::Client(ClientRequest::DelAuthKey {
        key: *app.public_id().public_key(),
        version: 2,
    });
    common::send_request_expect_err(
        &mut env,
        &mut app,
        del_auth_key_request.clone(),
        NdError::AccessDenied,
    );

    // Remove the app, then list the keys.
    common::perform_mutation(&mut env, &mut owner, del_auth_key_request);
    list_keys(&mut env, &mut owner, Ok((BTreeMap::new(), 2)));

    // Try to insert using an invalid version number.
    common::send_request_expect_err(
        &mut env,
        &mut owner,
        make_ins_request(100),
        NdError::InvalidSuccessor(2),
    );
    list_keys(&mut env, &mut owner, Ok((BTreeMap::new(), 2)));

    // Insert again and list again.
    common::perform_mutation(&mut env, &mut owner, make_ins_request(3));
    list_keys(&mut env, &mut owner, Ok((expected_map, 3)));
}

#[test]
fn app_permissions() -> Result<()> {
    let mut env = Environment::new();
    let mut owner = env.new_connected_client();
    let balance = Coins::from_nano(1000);
    common::create_balance(&mut env, &mut owner, None, balance);

    // App 0 is authorized with permission to perform mutations.
    let mut app_0 = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::Client(ClientRequest::InsAuthKey {
            key: *app_0.public_id().public_key(),
            version: 1,
            permissions: AppPermissions {
                perform_mutations: true,
                get_balance: false,
                transfer_coins: false,
            },
        }),
    );
    env.establish_connection(&mut app_0);

    // App 1 is authorized, and can only read balance.
    let mut app_1 = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::Client(ClientRequest::InsAuthKey {
            key: *app_1.public_id().public_key(),
            version: 2,
            permissions: AppPermissions {
                transfer_coins: false,
                get_balance: true,
                perform_mutations: false,
            },
        }),
    );
    env.establish_connection(&mut app_1);

    // App 2 is not authorized.
    let mut app_2 = env.new_connected_app(owner.public_id().clone());

    // App 3 is authorized with permission to transfer coins only.
    let mut app_3 = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::Client(ClientRequest::InsAuthKey {
            key: *app_3.public_id().public_key(),
            version: 3,
            permissions: AppPermissions {
                perform_mutations: false,
                get_balance: false,
                transfer_coins: true,
            },
        }),
    );
    env.establish_connection(&mut app_3);

    let sdata_owner = *owner.public_id().public_key();

    let mut pub_data = SData::new_pub(sdata_owner, env.rng().gen(), 100);
    let _op = pub_data.set_owner(sdata_owner);
    let _op = pub_data.set_pub_permissions(
        btreemap![SDataUser::Anyone => SDataPubUserPermissions::new(true, true)],
    )?;

    let pub_data_address = *pub_data.address();
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::SData(SDataRequest::Store(pub_data.clone())),
    );

    let mut priv_data = SData::new_priv(sdata_owner, env.rng().gen(), 101);
    let _op = priv_data.set_owner(sdata_owner);
    let _op = priv_data.set_priv_permissions(btreemap![
        *app_0.public_id().public_key() => SDataPrivUserPermissions::new(true, true, true),
        *app_1.public_id().public_key() => SDataPrivUserPermissions::new(true, true, true),
        *app_2.public_id().public_key() => SDataPrivUserPermissions::new(true, true, true),
    ])?;

    let priv_data_address = *priv_data.address();
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::SData(SDataRequest::Store(priv_data.clone())),
    );

    // All three apps can perform get request against published data
    let _: SData = common::get_from_response(
        &mut env,
        &mut app_0,
        Request::SData(SDataRequest::Get(pub_data_address)),
    );
    let _: SData = common::get_from_response(
        &mut env,
        &mut app_1,
        Request::SData(SDataRequest::Get(pub_data_address)),
    );
    let _: SData = common::get_from_response(
        &mut env,
        &mut app_2,
        Request::SData(SDataRequest::Get(pub_data_address)),
    );

    // Only the authorized apps can perform get request against unpublished data
    let _: SData = common::get_from_response(
        &mut env,
        &mut app_0,
        Request::SData(SDataRequest::Get(priv_data_address)),
    );
    let _: SData = common::get_from_response(
        &mut env,
        &mut app_1,
        Request::SData(SDataRequest::Get(priv_data_address)),
    );
    common::send_request_expect_err(
        &mut env,
        &mut app_2,
        Request::SData(SDataRequest::Get(priv_data_address)),
        NdError::AccessDenied,
    );

    // Only the app with the transfer coins permission can perform mutable request.
    for (mut data, address) in [(pub_data, pub_data_address), (priv_data, priv_data_address)]
        .iter()
        .cloned()
    {
        let entries_op = data.append(b"value".to_vec());

        common::send_request_expect_ok(
            &mut env,
            &mut app_0,
            Request::SData(SDataRequest::Mutate(SDataMutationOperation {
                address,
                crdt_op: entries_op.crdt_op.clone(),
            })),
            (),
        );

        common::send_request_expect_err(
            &mut env,
            &mut app_1,
            Request::SData(SDataRequest::Mutate(SDataMutationOperation {
                address,
                crdt_op: entries_op.crdt_op.clone(),
            })),
            NdError::AccessDenied,
        );
        common::send_request_expect_err(
            &mut env,
            &mut app_2,
            Request::SData(SDataRequest::Mutate(SDataMutationOperation {
                address,
                crdt_op: entries_op.crdt_op,
            })),
            NdError::AccessDenied,
        );
    }

    // A new client to credit coins to.
    let mut creditor = env.new_connected_client();
    common::create_balance(&mut env, &mut creditor, None, Coins::from_nano(0));

    // App 1 cannot transfer coins.
    common::send_request_expect_err(
        &mut env,
        &mut app_1,
        Request::Coins(CoinsRequest::Transfer {
            destination: *creditor.public_id().name(),
            amount: Coins::from_nano(50),
            transaction_id: 0,
        }),
        NdError::AccessDenied,
    );

    // App1 can read balance
    common::send_request_expect_ok(
        &mut env,
        &mut app_1,
        Request::Coins(CoinsRequest::GetBalance),
        Response::GetBalance(Ok(Coins::from_nano(996))),
    );

    let amount = Coins::from_nano(900);
    let expected = Response::Transaction(Ok(Transaction { id: 1, amount }));
    let name: XorName = env.rng().gen();
    let tag = 100;
    let data = SeqMutableData::new(name, tag, *owner.public_id().public_key());

    // App 3 can transfer coins on behalf of the user
    common::send_request_expect_ok(
        &mut env,
        &mut app_3,
        Request::Coins(CoinsRequest::Transfer {
            destination: *creditor.public_id().name(),
            amount,
            transaction_id: 1,
        }),
        expected,
    );

    // App 3 cannot mutate on behalf of the user
    common::send_request_expect_err(
        &mut env,
        &mut app_3,
        Request::MData(MDataRequest::Put(MData::from(data))),
        NdError::AccessDenied,
    );

    // App 3 cannot read balance of the user
    common::send_request_expect_err(
        &mut env,
        &mut app_3,
        Request::Coins(CoinsRequest::GetBalance),
        NdError::AccessDenied,
    );

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
//
// Mutable data
//
////////////////////////////////////////////////////////////////////////////////

#[test]
fn put_seq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, COST_OF_PUT);

    // Try to put sequenced Mutable Data
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = SeqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Put(MData::Seq(mdata.clone()))),
    );

    // Get Mutable Data and verify it's been stored correctly.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Get(MDataAddress::Seq { name, tag })),
        MData::Seq(mdata),
    );
}

#[test]
fn put_unseq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, COST_OF_PUT);

    // Try to put unsequenced Mutable Data
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = UnseqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Put(MData::Unseq(mdata.clone()))),
    );

    // Get Mutable Data and verify it's been stored correctly.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Get(MDataAddress::Unseq { name, tag })),
        MData::Unseq(mdata),
    );
}

#[test]
fn read_seq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, COST_OF_PUT);

    // Try to put sequenced Mutable Data with several entries.
    let entries: BTreeMap<_, _> = (1..4)
        .map(|_| {
            let key = env.rng().sample_iter(&Standard).take(8).collect();
            let data = env.rng().sample_iter(&Standard).take(8).collect();
            (key, MDataSeqValue { data, version: 0 })
        })
        .collect();

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = SeqMutableData::new_with_data(
        name,
        tag,
        entries.clone(),
        Default::default(),
        *client.public_id().public_key(),
    );
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Put(MData::Seq(mdata))),
    );

    // Get version.
    let address = MDataAddress::Seq { name, tag };
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetVersion(address)),
        0,
    );

    // Get keys.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::ListKeys(address)),
        entries.keys().cloned().collect::<BTreeSet<_>>(),
    );

    // Get values.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::ListValues(address)),
        MDataValues::from(entries.values().cloned().collect::<Vec<_>>()),
    );

    // Get entries.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::ListEntries(address)),
        MDataEntries::from(entries.clone()),
    );

    // Get a value by key.
    let key = unwrap!(entries.keys().cloned().next());
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: key.clone(),
        }),
        MDataValue::from(entries[&key].clone()),
    );
}

#[test]
fn mutate_seq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let balance = common::multiply_coins(COST_OF_PUT, 4);
    common::create_balance(&mut env, &mut client, None, balance);

    // Try to put sequenced Mutable Data.
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = SeqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Put(MData::Seq(mdata))),
    );

    // Get a non-existant value by key.
    let address = MDataAddress::Seq { name, tag };
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![0],
        }),
        NdError::NoSuchEntry,
    );

    // Insert new values.
    let actions = MDataSeqEntryActions::new()
        .ins(vec![0], vec![1], 0)
        .ins(vec![1], vec![1], 0);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![0],
        }),
        MDataValue::from(MDataSeqValue {
            data: vec![1],
            version: 0,
        }),
    );

    // Update and delete entries.
    let actions = MDataSeqEntryActions::new()
        .update(vec![0], vec![2], 1)
        .del(vec![1], 1);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![0],
        }),
        MDataValue::from(MDataSeqValue {
            data: vec![2],
            version: 1,
        }),
    );

    // Deleted key should not exist now.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![1],
        }),
        NdError::NoSuchEntry,
    );

    // Try an invalid update request.
    let expected_invalid_actions = btreemap![vec![0] => EntryError::InvalidSuccessor(1)];
    let actions = MDataSeqEntryActions::new().update(vec![0], vec![3], 0);
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::MutateEntries {
            address: MDataAddress::Seq { name, tag },
            actions: actions.into(),
        }),
        NdError::InvalidEntryActions(expected_invalid_actions),
    );
}

#[test]
fn mutate_unseq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let balance = common::multiply_coins(COST_OF_PUT, 3);
    common::create_balance(&mut env, &mut client, None, balance);

    // Try to put unsequenced Mutable Data.
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = UnseqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::Put(MData::Unseq(mdata))),
    );

    // Get a non-existant value by key.
    let address = MDataAddress::Unseq { name, tag };
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![0],
        }),
        NdError::NoSuchEntry,
    );

    // Insert new values.
    let actions = MDataUnseqEntryActions::new()
        .ins(vec![0], vec![1])
        .ins(vec![1], vec![1]);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![0],
        }),
        MDataValue::from(vec![1]),
    );

    // Update and delete entries.
    let actions = MDataUnseqEntryActions::new()
        .update(vec![0], vec![2])
        .del(vec![1]);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![0],
        }),
        MDataValue::from(vec![2]),
    );

    // Deleted key should not exist now.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::MData(MDataRequest::GetValue {
            address,
            key: vec![1],
        }),
        NdError::NoSuchEntry,
    );
}

#[test]
fn mutable_data_permissions() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let balance_a = common::multiply_coins(COST_OF_PUT, 3);
    let balance_b = common::multiply_coins(COST_OF_PUT, 3);
    common::create_balance(&mut env, &mut client_a, None, balance_a);
    common::create_balance(&mut env, &mut client_b, None, balance_b);

    // Try to put new unsequenced Mutable Data.
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = UnseqMutableData::new(name, tag, *client_a.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::Put(MData::Unseq(mdata))),
    );

    // Make sure client B can't insert anything.
    let actions = MDataUnseqEntryActions::new().ins(vec![0], vec![1]);
    let address = MDataAddress::Unseq { name, tag };
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
        NdError::AccessDenied,
    );

    // Insert permissions for client B.
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::SetUserPermissions {
            address,
            user: *client_b.public_id().public_key(),
            permissions: MDataPermissionSet::new().allow(MDataAction::Insert),
            version: 1,
        }),
    );

    // Client B now can insert new values.
    let actions = MDataUnseqEntryActions::new().ins(vec![0], vec![1]);
    common::perform_mutation(
        &mut env,
        &mut client_b,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
    );

    // Delete client B permissions.
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::DelUserPermissions {
            address,
            user: *client_b.public_id().public_key(),
            version: 2,
        }),
    );

    // Client B can't insert anything again.
    let actions = MDataUnseqEntryActions::new().ins(vec![0], vec![1]);
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::MData(MDataRequest::MutateEntries {
            address,
            actions: actions.into(),
        }),
        NdError::AccessDenied,
    );
}

#[test]
fn delete_mutable_data() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let balance_a = common::multiply_coins(COST_OF_PUT, 3);
    common::create_balance(&mut env, &mut client_a, None, balance_a);
    common::create_balance(&mut env, &mut client_b, None, COST_OF_PUT);

    let mdata = UnseqMutableData::new(env.rng().gen(), 100, *client_a.public_id().public_key());
    let address = *mdata.address();
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::Put(MData::Unseq(mdata))),
    );
    let balance_a = unwrap!(balance_a.checked_sub(COST_OF_PUT));
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Attempt to delete non-existent data.
    let invalid_address = MDataAddress::from_kind(MDataKind::Unseq, env.rng().gen(), 101);
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::Delete(invalid_address)),
        NdError::NoSuchData,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Attempt to delete the data by non-owner.
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::MData(MDataRequest::Delete(address)),
        NdError::AccessDenied,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Successfully delete.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::Delete(address)),
        (),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Verify the data doesn't exist any more.
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::MData(MDataRequest::Get(address)),
        NdError::NoSuchData,
    );
}

/// Sequence tests ///
#[test]
fn sequence_store_get_and_delete() {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let owner_a = *client_a.public_id().public_key();

    // Public Sequence
    let pub_sdata_name: XorName = env.rng().gen();
    let mut pub_sdata = SData::new_pub(owner_a, pub_sdata_name, 100);
    let _op = pub_sdata.set_owner(owner_a);
    let _op = pub_sdata.append(b"pub sequence first".to_vec());
    let _op = pub_sdata.append(b"pub sequence second".to_vec());

    // Private Sequence
    let priv_sdata_name: XorName = env.rng().gen();
    let mut priv_sdata = SData::new_priv(owner_a, priv_sdata_name, 100);
    let _op = priv_sdata.set_owner(owner_a);
    let _op = priv_sdata.append(b"priv sequence first".to_vec());
    let _op = priv_sdata.append(b"priv sequence second".to_vec());

    // First try to store some data without any associated balance.
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
        NdError::NoSuchBalance,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(priv_sdata.clone())),
        NdError::NoSuchBalance,
    );

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);

    // Check that client B cannot store A's data
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
        NdError::InvalidOwners,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::Store(priv_sdata.clone())),
        NdError::InvalidOwners,
    );

    // Store, this time with a balance and the correct owner
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(priv_sdata.clone())),
    );

    let balance_a = Coins::from_nano(start_nano - 2);
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Get the data to verify
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::GetLastEntry(*pub_sdata.address())),
        (/* index ==*/ 1, b"pub sequence second".to_vec()),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::GetLastEntry(*priv_sdata.address())),
        (/* index ==*/ 1, b"priv sequence second".to_vec()),
    );

    // Verify that B cannot delete A's data
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::Delete(*pub_sdata.address())),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::Delete(*priv_sdata.address())),
        NdError::AccessDenied,
    );

    // Delete the data
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Delete(*pub_sdata.address())),
        NdError::InvalidOperation,
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Delete(*priv_sdata.address())),
    );

    // Deletions are free so A's balance should remain the same.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );

    // Delete again to test if it's gone
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Delete(*priv_sdata.address())),
        NdError::NoSuchData,
    );

    // The balance should remain the same when deletion fails
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::Coins(CoinsRequest::GetBalance),
        balance_a,
    );
}

#[test]
fn sequence_delete_inexistent() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let actor = *client.public_id().public_key();
    let name: XorName = env.rng().gen();
    let tag = 100;

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Delete(
            *SData::new_pub(actor, name, tag).address(),
        )),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Delete(
            *SData::new_priv(actor, name, tag).address(),
        )),
        NdError::NoSuchData,
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::Coins(CoinsRequest::GetBalance),
        Coins::from_nano(start_nano),
    );
}

#[test]
fn sequence_get_public_inexistent() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    // Failure - non-existing data
    let invalid_name: XorName = env.rng().gen();
    let invalid_address = SDataAddress::Public {
        name: invalid_name,
        tag: 100,
    };

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Get(invalid_address)),
        NdError::NoSuchData,
    );
}

#[test]
fn sequence_get_private_invalid_owner() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, COST_OF_PUT);

    let owner = *client.public_id().public_key();
    let mut priv_sdata = SData::new_priv(owner, env.rng().gen(), 100);

    let _op = priv_sdata.set_owner(owner);

    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Store(priv_sdata.clone())),
    );

    let address = *priv_sdata.address();
    // Failure - get by non-owner not allowed
    let mut other_client = env.new_connected_client();
    common::send_request_expect_err(
        &mut env,
        &mut other_client,
        Request::SData(SDataRequest::Get(address)),
        NdError::AccessDenied,
    );

    // Failure - non-existing priv_sdata
    let invalid_name: XorName = env.rng().gen();
    let invalid_address = SDataAddress::Private {
        name: invalid_name,
        tag: 100,
    };

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Get(invalid_address)),
        NdError::NoSuchData,
    );
}

#[test]
fn sequence_get_entries() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, COST_OF_PUT);

    let owner = *client.public_id().public_key();
    let mut data = SData::new_pub(owner, env.rng().gen(), 100);

    let _op = data.set_owner(owner);
    let entry_one = b"one".to_vec();
    let entry_two = b"two".to_vec();
    let _op = data.append(entry_one.clone());
    let _op = data.append(entry_two.clone());

    let address = *data.address();
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::Coins(CoinsRequest::GetBalance),
        COST_OF_PUT,
    );
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Store(data.clone())),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Store(data)),
        NdError::InsufficientBalance,
    );

    // GetSDataRange
    let mut range_scenario = |start, end, expected_result| {
        common::send_request_expect_ok(
            &mut env,
            &mut client,
            Request::SData(SDataRequest::GetRange {
                address,
                range: (start, end),
            }),
            expected_result,
        )
    };

    //    range_scenario(SDataIndex::FromStart(0), SDataIndex::FromStart(0), vec![]);
    range_scenario(
        SDataIndex::FromStart(0),
        SDataIndex::FromStart(1),
        vec![entry_one.clone()],
    );
    range_scenario(
        SDataIndex::FromStart(1),
        SDataIndex::FromStart(2),
        vec![entry_two.clone()],
    );
    range_scenario(
        SDataIndex::FromEnd(1),
        SDataIndex::FromEnd(0),
        vec![entry_two.clone()],
    );
    range_scenario(
        SDataIndex::FromStart(0),
        SDataIndex::FromEnd(0),
        vec![entry_one, entry_two.clone()],
    );

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetRange {
            address,
            range: (SDataIndex::FromStart(0), SDataIndex::FromStart(3)),
        }),
        NdError::NoSuchEntry,
    );

    // GetSDataLastEntry
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetLastEntry(address)),
        (/*index == */ 1, entry_two),
    );
}

#[test]
fn sequence_set_owner() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    common::create_balance(&mut env, &mut client, None, 1_000);

    let owner = *client.public_id().public_key();
    let owner_2 = common::gen_public_key(env.rng());

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut pub_sdata = SData::new_pub(owner, name, tag);

    let entry = b"entry".to_vec();

    let _op = pub_sdata.set_owner(owner);
    let _op = pub_sdata.append(entry.clone());

    let address = *pub_sdata.address();
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
    );

    // keep in mind that for all scenarios the data has no permissions set,
    // so it's all about the owners being set
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetRange {
            address,
            range: (SDataIndex::FromStart(0), SDataIndex::FromStart(1)),
        }),
        vec![entry.clone()],
    );

    let owner_op = pub_sdata.set_owner(owner_2);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::MutateOwner(SDataMutationOperation {
            address,
            crdt_op: owner_op.crdt_op,
        })),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetRange {
            address,
            range: (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)),
        }),
        vec![entry],
    );
}

#[test]
fn sequence_set_pub_permissions() -> Result<()> {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    common::create_balance(&mut env, &mut client, None, 1_000);
    let owner = *client.public_id().public_key();

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut pub_sdata = SData::new_pub(owner, name, tag);
    let public_key = common::gen_public_key(env.rng());

    let _op = pub_sdata.set_owner(owner);

    let perms_0 = btreemap![SDataUser::Anyone => SDataPubUserPermissions::new(true, false)];
    let _op = pub_sdata.set_pub_permissions(perms_0);

    let address = *pub_sdata.address();
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Anyone,
        }),
        SDataUserPermissions::Pub(SDataPubUserPermissions::new(true, false)),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Key(public_key),
        }),
        NdError::NoSuchEntry,
    );

    let perms_1 = btreemap![
        SDataUser::Anyone => SDataPubUserPermissions::new(false, false),
        SDataUser::Key(public_key) => SDataPubUserPermissions::new(true, false)
    ];
    let perms_op = pub_sdata.set_pub_permissions(perms_1)?;
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::MutatePubPermissions(SDataMutationOperation {
            address,
            crdt_op: perms_op.crdt_op,
        })),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Anyone,
        }),
        SDataUserPermissions::Pub(SDataPubUserPermissions::new(false, false)),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Key(public_key),
        }),
        SDataUserPermissions::Pub(SDataPubUserPermissions::new(true, false)),
    );

    Ok(())
}

#[test]
fn sequence_set_priv_permissions() -> Result<()> {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let start_nano = 1_000;
    common::create_balance(&mut env, &mut client, None, start_nano);
    let owner = *client.public_id().public_key();

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut priv_sdata = SData::new_priv(owner, name, tag);

    let _op = priv_sdata.set_owner(owner);

    let public_key_0 = common::gen_public_key(env.rng());
    let public_key_1 = common::gen_public_key(env.rng());

    let perms_0 = btreemap![
        public_key_0 => SDataPrivUserPermissions::new(true, true, false)
    ];
    let _op = priv_sdata.set_priv_permissions(perms_0)?;

    let address = *priv_sdata.address();
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::Store(priv_sdata.clone())),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Key(public_key_0),
        }),
        SDataUserPermissions::Priv(SDataPrivUserPermissions::new(true, true, false)),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Key(public_key_1),
        }),
        NdError::NoSuchEntry,
    );

    let perms_1 = btreemap![
        public_key_0 => SDataPrivUserPermissions::new(true, false, false),
        public_key_1 => SDataPrivUserPermissions::new(true, true, true)
    ];
    let perms_op = priv_sdata.set_priv_permissions(perms_1)?;
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::MutatePrivPermissions(
            SDataMutationOperation {
                address,
                crdt_op: perms_op.crdt_op,
            },
        )),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Key(public_key_0),
        }),
        SDataUserPermissions::Priv(SDataPrivUserPermissions::new(true, false, false)),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::SData(SDataRequest::GetUserPermissions {
            address,
            user: SDataUser::Key(public_key_1),
        }),
        SDataUserPermissions::Priv(SDataPrivUserPermissions::new(true, true, true)),
    );

    Ok(())
}

#[test]
fn sequence_set_owners() -> Result<()> {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let public_key_a = *client_a.public_id().public_key();
    let public_key_b = *client_b.public_id().public_key();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);
    common::create_balance(&mut env, &mut client_b, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut pub_sdata = SData::new_pub(public_key_a, name, tag);

    let perms_0 =
        btreemap![SDataUser::Key(public_key_a) => SDataPubUserPermissions::new(true, true)];

    let _op = pub_sdata.set_pub_permissions(perms_0)?;
    let _op = pub_sdata.append(b"one".to_vec());
    let _op = pub_sdata.append(b"two".to_vec());
    let owner_a = public_key_a;
    let _op = pub_sdata.set_owner(owner_a);

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
    );

    let address = *pub_sdata.address();
    // Both A or B can get the owner
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::GetOwner(address)),
        SDataOwner {
            public_key: owner_a,
            entries_index: 2,
            permissions_index: 1,
        },
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetOwner(address)),
        SDataOwner {
            public_key: owner_a,
            entries_index: 2,
            permissions_index: 1,
        },
    );

    // Set the new owner, change from A -> B
    let owner_b = public_key_b;

    // B can't set the new owner, but A can
    let owner_op = pub_sdata.set_owner(owner_b);
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::MutateOwner(SDataMutationOperation {
            address,
            crdt_op: owner_op.crdt_op.clone(),
        })),
        NdError::AccessDenied,
    );

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::MutateOwner(SDataMutationOperation {
            address,
            crdt_op: owner_op.crdt_op,
        })),
    );

    // Both A or B can get the new owner
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::GetOwner(address)),
        SDataOwner {
            public_key: owner_b,
            entries_index: 2,
            permissions_index: 1,
        },
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetOwner(address)),
        SDataOwner {
            public_key: owner_b,
            entries_index: 2,
            permissions_index: 1,
        },
    );
    Ok(())
}

#[test]
fn sequence_append_to_public() -> Result<()> {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();
    let owner_a = *client_a.public_id().public_key();
    let owner_b = *client_b.public_id().public_key();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut pub_sdata = SData::new_pub(owner_a, name, tag);

    let _op = pub_sdata.set_owner(owner_a);

    let perms_0 = btreemap![SDataUser::Key(owner_b) => SDataPubUserPermissions::new(true, true)];

    let _op = pub_sdata.set_pub_permissions(perms_0)?;
    let _op = pub_sdata.append(b"one".to_vec());
    let _op = pub_sdata.append(b"two".to_vec());

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetLastEntry(*pub_sdata.address())),
        (/* index ==*/ 1, b"two".to_vec()),
    );

    let entries_op = pub_sdata.append(b"three".to_vec());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Mutate(SDataMutationOperation {
            address: *pub_sdata.address(),
            crdt_op: entries_op.crdt_op,
        })),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetLastEntry(*pub_sdata.address())),
        (/* index ==*/ 2, b"three".to_vec()),
    );

    Ok(())
}

#[test]
fn sequence_append_to_private() -> Result<()> {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();
    let owner_a = *client_a.public_id().public_key();
    let owner_b = *client_b.public_id().public_key();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut priv_sdata = SData::new_priv(owner_a, name, tag);

    let _op = priv_sdata.set_owner(owner_a);

    let perms_0 = btreemap![owner_b => SDataPrivUserPermissions::new(true, true, true)];

    let _op = priv_sdata.set_priv_permissions(perms_0)?;
    let _op = priv_sdata.append(b"one".to_vec());
    let _op = priv_sdata.append(b"two".to_vec());

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(priv_sdata.clone())),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetLastEntry(*priv_sdata.address())),
        (/* index ==*/ 1, b"two".to_vec()),
    );

    let entries_op = priv_sdata.append(b"three".to_vec());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Mutate(SDataMutationOperation {
            address: *priv_sdata.address(),
            crdt_op: entries_op.crdt_op,
        })),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetLastEntry(*priv_sdata.address())),
        (/* index ==*/ 2, b"three".to_vec()),
    );

    Ok(())
}

#[test]
fn sequence_append_concurrently_from_diff_clients() -> Result<()> {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();
    let mut client_c = env.new_connected_client();
    let owner_a = *client_a.public_id().public_key();
    let owner_b = *client_b.public_id().public_key();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);
    common::create_balance(&mut env, &mut client_b, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut pub_sdata = SData::new_pub(owner_a, name, tag);

    let _op = pub_sdata.set_owner(owner_a);

    // client_b can also append
    let perms_0 = btreemap![SDataUser::Key(owner_b) => SDataPubUserPermissions::new(true, true)];

    let _op = pub_sdata.set_pub_permissions(perms_0)?;
    let _op = pub_sdata.append(b"one".to_vec());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Store(pub_sdata.clone())),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::GetLastEntry(*pub_sdata.address())),
        (/* index ==*/ 0, b"one".to_vec()),
    );

    // now both clent_a and client_b append items to it
    let entries_op = pub_sdata.append(b"two-from-b".to_vec());
    common::perform_mutation(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::Mutate(SDataMutationOperation {
            address: *pub_sdata.address(),
            crdt_op: entries_op.crdt_op,
        })),
    );

    let entries_op = pub_sdata.append(b"two-from-a".to_vec());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SData(SDataRequest::Mutate(SDataMutationOperation {
            address: *pub_sdata.address(),
            crdt_op: entries_op.crdt_op,
        })),
    );

    let entries_op = pub_sdata.append(b"three-from-b".to_vec());
    common::perform_mutation(
        &mut env,
        &mut client_b,
        Request::SData(SDataRequest::Mutate(SDataMutationOperation {
            address: *pub_sdata.address(),
            crdt_op: entries_op.crdt_op,
        })),
    );

    // now client_c reads and see the three items
    common::send_request_expect_ok(
        &mut env,
        &mut client_c,
        Request::SData(SDataRequest::GetRange {
            address: *pub_sdata.address(),
            range: (SDataIndex::FromStart(0), SDataIndex::FromEnd(0)),
        }),
        vec![
            b"one".to_vec(),
            b"two-from-b".to_vec(),
            b"two-from-a".to_vec(),
            b"three-from-b".to_vec(),
        ],
    );

    Ok(())
}
