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

use self::common::{Environment, TestClientTrait, DEFAULT_NUM_CONNECTED_VAULTS};
use maplit::btreemap;
use rand::{distributions::Standard, Rng};
use safe_nd::{
    AData, ADataAddress, ADataAppendOperation, ADataEntry, ADataIndex, ADataOwner,
    ADataPermissions, ADataPubPermissionSet, ADataPubPermissions, ADataUnpubPermissionSet,
    ADataUnpubPermissions, ADataUser, AppPermissions, AppendOnlyData, ClientFullId, Coins,
    EntryError, Error as NdError, IData, IDataAddress, LoginPacket, MData, MDataAction,
    MDataAddress, MDataEntries, MDataKind, MDataPermissionSet, MDataSeqEntryActions, MDataSeqValue,
    MDataUnseqEntryActions, MDataValue, MDataValues, Message, MessageId, PubImmutableData,
    PubSeqAppendOnlyData, PubUnseqAppendOnlyData, PublicKey, Request, Response, Result as NdResult,
    SeqAppendOnly, SeqMutableData, Transaction, UnpubImmutableData, UnpubSeqAppendOnlyData,
    UnpubUnseqAppendOnlyData, UnseqAppendOnly, UnseqMutableData, XorName,
};
use safe_vault::COST_OF_PUT;
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
    let request = Request::GetIData(IDataAddress::Unpub(name));
    let message_id = MessageId::new();

    // Missing signature
    for info in client.connected_vaults() {
        client.send(
            &Message::Request {
                request: request.clone(),
                message_id,
                signature: None,
            },
            info,
        );
    }
    env.poll();
    match client.expect_response(message_id) {
        Response::GetIData(Err(NdError::InvalidSignature)) => (),
        x => unexpected!(x),
    }

    // Invalid signature
    let other_full_id = ClientFullId::new_ed25519(env.rng());
    let to_sign = (&request, &message_id);
    let to_sign = unwrap!(bincode::serialize(&to_sign));
    let signature = other_full_id.sign(&to_sign);

    for info in client.connected_vaults() {
        client.send(
            &Message::Request {
                request: request.clone(),
                message_id,
                signature: Some(signature.clone()),
            },
            info,
        );
    }
    env.poll();
    match client.expect_response(message_id) {
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

    let balance = common::multiply_coins(*COST_OF_PUT, 2);
    common::create_balance(&mut env, &mut client, None, balance);

    // Try to get a login packet that does not exist yet.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetLoginPacket(login_packet_locator),
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
        Request::CreateLoginPacket(login_packet.clone()),
    );

    // Try to get the login packet data and signature.
    let (data, sig) = common::get_from_response(
        &mut env,
        &mut client,
        Request::GetLoginPacket(login_packet_locator),
    );
    assert_eq!(data, login_packet_data);
    unwrap!(client.public_id().public_key().verify(&sig, &data));

    // Putting login packet to the same address should fail.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::CreateLoginPacket(login_packet),
        NdError::LoginPacketExists,
    );

    // Getting login packet from non-owning client should fail.
    {
        let mut client = env.new_connected_client();
        common::send_request_expect_err(
            &mut env,
            &mut client,
            Request::GetLoginPacket(login_packet_locator),
            NdError::AccessDenied,
        );
    }
}

#[test]
fn create_login_packet_for_other() {
    let mut env = Environment::new();
    let mut established_client = env.new_connected_client();
    let mut new_client = env.new_connected_client();

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

    let amount = *COST_OF_PUT;
    let nano_to_transfer = 2 * COST_OF_PUT.as_nano();
    common::send_request_expect_ok(
        &mut env,
        &mut established_client,
        Request::CreateLoginPacketFor {
            new_owner: *new_client.public_id().public_key(),
            amount,
            transaction_id: 1,
            new_login_packet: login_packet.clone(),
        },
        Transaction { id: 1, amount },
    );

    // Try to get the login packet data and signature.
    let (data, sig) = common::get_from_response(
        &mut env,
        &mut new_client,
        Request::GetLoginPacket(login_packet_locator),
    );
    assert_eq!(data, login_packet_data);
    unwrap!(new_client.public_id().public_key().verify(&sig, &data));

    // Check the balances have been updated.
    common::send_request_expect_ok(
        &mut env,
        &mut established_client,
        Request::GetBalance,
        unwrap!(Coins::from_nano(start_nano - nano_to_transfer)),
    );
    common::send_request_expect_ok(&mut env, &mut new_client, Request::GetBalance, *COST_OF_PUT);

    // Putting login packet to the same address should fail.
    common::send_request_expect_err(
        &mut env,
        &mut established_client,
        Request::CreateLoginPacketFor {
            new_owner: *new_client.public_id().public_key(),
            amount: unwrap!(Coins::from_nano(nano_to_transfer)),
            transaction_id: 2,
            new_login_packet: login_packet.clone(),
        },
        NdError::BalanceExists,
    );

    // Getting login packet from non-owning client should fail.
    common::send_request_expect_err(
        &mut env,
        &mut established_client,
        Request::GetLoginPacket(login_packet_locator),
        NdError::AccessDenied,
    );
}

#[test]
fn update_login_packet() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

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
        Request::CreateLoginPacket(login_packet.clone()),
    );

    // Update the login packet data.
    let new_login_packet_data = vec![1; 32];
    let client_public_key = *client.public_id().public_key();
    let signature = client.sign(&new_login_packet_data);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::UpdateLoginPacket(unwrap!(LoginPacket::new(
            login_packet_locator,
            client_public_key,
            new_login_packet_data.clone(),
            signature,
        ))),
    );

    // Try to get the login packet data and signature.
    let (data, sig) = common::get_from_response(
        &mut env,
        &mut client,
        Request::GetLoginPacket(login_packet_locator),
    );
    assert_eq!(data, new_login_packet_data);
    unwrap!(client.public_id().public_key().verify(&sig, &data));

    // Updating login packet from non-owning client should fail.
    {
        let mut client = env.new_connected_client();
        common::send_request_expect_err(
            &mut env,
            &mut client,
            Request::UpdateLoginPacket(login_packet),
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
fn coin_operations() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::GetBalance,
        NdError::NoSuchBalance,
    );

    // Create A's balance
    let amount_a = unwrap!(Coins::from_nano(10));
    common::create_balance(&mut env, &mut client_a, None, amount_a);
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, amount_a);

    let amount_b = unwrap!(Coins::from_nano(1));
    common::create_balance(&mut env, &mut client_a, Some(&mut client_b), amount_b);

    let amount_a = unwrap!(Coins::from_nano(8));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, amount_a);
    common::send_request_expect_ok(&mut env, &mut client_b, Request::GetBalance, amount_b);

    // Transfer coins from A to B (first attempt with zero amount doesn't work)
    let amount_zero = unwrap!(Coins::from_nano(0));
    let transaction_id = 2;
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::TransferCoins {
            destination: *client_b.public_id().name(),
            amount: amount_zero,
            transaction_id,
        },
        NdError::InvalidOperation,
    );
    common::transfer_coins(&mut env, &mut client_a, &mut client_b, 2, 3);

    let amount_a = unwrap!(Coins::from_nano(6));
    let amount_b = unwrap!(Coins::from_nano(3));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, amount_a);
    common::send_request_expect_ok(&mut env, &mut client_b, Request::GetBalance, amount_b);
}

#[test]
fn create_balance_that_already_exists() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    common::create_balance(&mut env, &mut client_a, None, 10);
    common::create_balance(&mut env, &mut client_a, Some(&mut client_b), 4);

    let balance_a = unwrap!(Coins::from_nano(5));
    let balance_b = unwrap!(Coins::from_nano(4));

    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);
    common::send_request_expect_ok(&mut env, &mut client_b, Request::GetBalance, balance_b);

    // Attempt to create the balance for B again. The request fails and A receives an error back.
    let transaction_id = 2;
    let amount = unwrap!(Coins::from_nano(2));
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::CreateBalance {
            new_balance_owner: *client_b.public_id().public_key(),
            amount,
            transaction_id,
        },
        NdError::BalanceExists,
    );

    // A's balance is refunded.
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // B does not receive anything.
    client_b.expect_no_new_message();

    // Attempt to create the balance for A again. This should however work for phase 1
    common::create_balance(&mut env, &mut client_a, None, 2);
    let balance_a = unwrap!(Coins::from_nano(2));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);
}

#[test]
fn transfer_coins_to_balance_that_doesnt_exist() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let client_b = env.new_connected_client();

    let balance_a = unwrap!(Coins::from_nano(10));
    common::create_balance(&mut env, &mut client_a, None, balance_a);
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // Attempt transfer coins to B's balance which doesn't exist. The request fails and A receives
    // an error back.
    let transaction_id = 4;
    let amount = unwrap!(Coins::from_nano(4));
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::TransferCoins {
            destination: *client_b.public_id().name(),
            amount,
            transaction_id,
        },
        NdError::NoSuchBalance,
    );

    // A's balance is refunded.
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // B does not receive anything.
    client_b.expect_no_new_message();
}

#[test]
fn coin_operations_by_app() {
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
        Request::InsAuthKey {
            key: *app.public_id().public_key(),
            version: 1,
            permissions: AppPermissions {
                transfer_coins: true,
                get_balance: true,
                perform_mutations: true,
            },
        },
    );
    env.establish_connection(&mut app);

    // Check the balance by the app.
    common::send_request_expect_ok(
        &mut env,
        &mut app,
        Request::GetBalance,
        unwrap!(Coins::from_nano(10)),
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
        Request::GetBalance,
        unwrap!(Coins::from_nano(9)),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::GetBalance,
        unwrap!(Coins::from_nano(1)),
    );
}

#[test]
fn coin_operations_by_app_with_insufficient_permissions() {
    let mut env = Environment::new();
    let mut owner = env.new_connected_client();

    // Create initial balance.
    let balance = unwrap!(Coins::from_nano(10));
    common::create_balance(&mut env, &mut owner, None, balance);

    // Create an app which does *not* have permission to transfer coins.
    let mut app = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::InsAuthKey {
            key: *app.public_id().public_key(),
            version: 1,
            permissions: AppPermissions {
                get_balance: false,
                transfer_coins: false,
                perform_mutations: false,
            },
        },
    );
    env.establish_connection(&mut app);

    // The attempt to get balance by the app fails.
    common::send_request_expect_err(
        &mut env,
        &mut app,
        Request::GetBalance,
        NdError::AccessDenied,
    );

    // The attempt to transfer some coins by the app fails.
    let destination: XorName = env.rng().gen();
    let transaction_id = 1;
    common::send_request_expect_err(
        &mut env,
        &mut app,
        Request::TransferCoins {
            destination,
            amount: unwrap!(Coins::from_nano(1)),
            transaction_id,
        },
        NdError::AccessDenied,
    );

    // The owners balance is unchanged.
    common::send_request_expect_ok(&mut env, &mut owner, Request::GetBalance, balance);
}

////////////////////////////////////////////////////////////////////////////////
//
// Append-only data
//
////////////////////////////////////////////////////////////////////////////////

#[test]
fn put_append_only_data() {
    let mut env = Environment::new();
    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let owner_a = ADataOwner {
        public_key: *client_a.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    // Published sequential data
    let pub_seq_adata_name: XorName = env.rng().gen();
    let mut pub_seq_adata = PubSeqAppendOnlyData::new(pub_seq_adata_name, 100);
    unwrap!(pub_seq_adata.append_owner(owner_a, 0));
    unwrap!(pub_seq_adata.append(
        vec![ADataEntry {
            key: b"one".to_vec(),
            value: b"pub sec".to_vec()
        }],
        0
    ));
    unwrap!(pub_seq_adata.append(
        vec![ADataEntry {
            key: b"two".to_vec(),
            value: b"pub sec".to_vec()
        }],
        1
    ));
    let pub_seq_adata = AData::PubSeq(pub_seq_adata);

    // Published unsequential data
    let pub_unseq_adata_name: XorName = env.rng().gen();
    let mut pub_unseq_adata = PubUnseqAppendOnlyData::new(pub_unseq_adata_name, 100);
    unwrap!(pub_unseq_adata.append_owner(owner_a, 0));
    unwrap!(pub_unseq_adata.append(vec![ADataEntry {
        key: b"one".to_vec(),
        value: b"pub unsec".to_vec()
    }]));
    unwrap!(pub_unseq_adata.append(vec![ADataEntry {
        key: b"two".to_vec(),
        value: b"pub unsec".to_vec()
    }]));
    let pub_unseq_adata = AData::PubUnseq(pub_unseq_adata);

    // Unpublished sequential
    let unpub_seq_adata_name: XorName = env.rng().gen();
    let mut unpub_seq_adata = UnpubSeqAppendOnlyData::new(unpub_seq_adata_name, 100);
    unwrap!(unpub_seq_adata.append_owner(owner_a, 0));
    unwrap!(unpub_seq_adata.append(
        vec![ADataEntry {
            key: b"one".to_vec(),
            value: b"unpub sec".to_vec()
        }],
        0
    ));
    unwrap!(unpub_seq_adata.append(
        vec![ADataEntry {
            key: b"two".to_vec(),
            value: b"unpub sec".to_vec()
        }],
        1
    ));
    let unpub_seq_adata = AData::UnpubSeq(unpub_seq_adata);

    // Unpublished unsequential data
    let unpub_unseq_adata_name: XorName = env.rng().gen();
    let mut unpub_unseq_adata = UnpubUnseqAppendOnlyData::new(unpub_unseq_adata_name, 100);
    unwrap!(unpub_unseq_adata.append_owner(owner_a, 0));
    unwrap!(unpub_unseq_adata.append(vec![ADataEntry {
        key: b"one".to_vec(),
        value: b"unpub unsec".to_vec()
    }]));
    unwrap!(unpub_unseq_adata.append(vec![ADataEntry {
        key: b"two".to_vec(),
        value: b"unpub unsec".to_vec()
    }]));
    let unpub_unseq_adata = AData::UnpubUnseq(unpub_unseq_adata);

    // First try to put some data without any associated balance.
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::PutAData(pub_seq_adata.clone()),
        NdError::NoSuchBalance,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::PutAData(pub_unseq_adata.clone()),
        NdError::NoSuchBalance,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::PutAData(unpub_seq_adata.clone()),
        NdError::NoSuchBalance,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::PutAData(unpub_unseq_adata.clone()),
        NdError::NoSuchBalance,
    );

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client_a, None, start_nano);

    // Check that client B cannot put A's data
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::PutAData(pub_seq_adata.clone()),
        NdError::InvalidOwners,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::PutAData(pub_unseq_adata.clone()),
        NdError::InvalidOwners,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::PutAData(unpub_seq_adata.clone()),
        NdError::InvalidOwners,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::PutAData(unpub_unseq_adata.clone()),
        NdError::InvalidOwners,
    );

    // Put, this time with a balance and the correct owner
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(pub_seq_adata.clone()),
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(pub_unseq_adata.clone()),
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(unpub_seq_adata.clone()),
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(unpub_unseq_adata.clone()),
    );

    // Get the data to verify
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetAData(*pub_seq_adata.address()),
        pub_seq_adata.clone(),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetAData(*pub_unseq_adata.address()),
        pub_unseq_adata.clone(),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetAData(*unpub_seq_adata.address()),
        unpub_seq_adata.clone(),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetAData(*unpub_unseq_adata.address()),
        unpub_unseq_adata.clone(),
    );

    // Verify that B cannot delete A's data
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::DeleteAData(*pub_seq_adata.address()),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::DeleteAData(*pub_unseq_adata.address()),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::DeleteAData(*unpub_seq_adata.address()),
        NdError::AccessDenied,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::DeleteAData(*unpub_unseq_adata.address()),
        NdError::AccessDenied,
    );

    // Delete the data
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteAData(*pub_seq_adata.address()),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteAData(*pub_unseq_adata.address()),
        NdError::InvalidOperation,
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::DeleteAData(*unpub_seq_adata.address()),
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::DeleteAData(*unpub_unseq_adata.address()),
    );

    // Delete again to test if it's gone
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteAData(*unpub_seq_adata.address()),
        NdError::NoSuchData,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteAData(*unpub_unseq_adata.address()),
        NdError::NoSuchData,
    );
}

#[test]
fn delete_append_only_data_that_doesnt_exist() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let name: XorName = env.rng().gen();
    let tag = 100;

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::DeleteAData(*AData::PubSeq(PubSeqAppendOnlyData::new(name, tag)).address()),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::DeleteAData(*AData::PubUnseq(PubUnseqAppendOnlyData::new(name, tag)).address()),
        NdError::InvalidOperation,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::DeleteAData(*AData::UnpubSeq(UnpubSeqAppendOnlyData::new(name, tag)).address()),
        NdError::NoSuchData,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::DeleteAData(
            *AData::UnpubUnseq(UnpubUnseqAppendOnlyData::new(name, tag)).address(),
        ),
        NdError::NoSuchData,
    );
}

#[test]
fn get_pub_append_only_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    let mut data = PubSeqAppendOnlyData::new(env.rng().gen(), 100);

    let owner = ADataOwner {
        public_key: *client.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };
    unwrap!(data.append_owner(owner, 0));

    let data = AData::PubSeq(data);
    let address = *data.address();
    common::perform_mutation(&mut env, &mut client, Request::PutAData(data.clone()));

    // Success
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetAData(address),
        data.clone(),
    );

    // Failure - non-existing data
    let invalid_name: XorName = env.rng().gen();
    let invalid_address = ADataAddress::PubSeq {
        name: invalid_name,
        tag: 100,
    };

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetAData(invalid_address),
        NdError::NoSuchData,
    );

    // Published data is gettable by non-owners too
    let mut other_client = env.new_connected_client();
    common::send_request_expect_ok(
        &mut env,
        &mut other_client,
        Request::GetAData(address),
        data,
    );
}

#[test]
fn get_unpub_append_only_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    let mut data = UnpubSeqAppendOnlyData::new(env.rng().gen(), 100);

    let owner = ADataOwner {
        public_key: *client.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };
    unwrap!(data.append_owner(owner, 0));

    let data = AData::UnpubSeq(data);
    let address = *data.address();
    common::perform_mutation(&mut env, &mut client, Request::PutAData(data.clone()));

    // Success
    common::send_request_expect_ok(&mut env, &mut client, Request::GetAData(address), data);

    // Failure - non-existing data
    let invalid_name: XorName = env.rng().gen();
    let invalid_address = ADataAddress::UnpubSeq {
        name: invalid_name,
        tag: 100,
    };

    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetAData(invalid_address),
        NdError::NoSuchData,
    );

    // Failure - get by non-owner not allowed
    let mut other_client = env.new_connected_client();
    common::create_balance(&mut env, &mut other_client, None, 0);

    common::send_request_expect_err(
        &mut env,
        &mut other_client,
        Request::GetAData(address),
        NdError::AccessDenied,
    );
}

#[test]
fn append_only_data_get_entries() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    let mut data = PubSeqAppendOnlyData::new(env.rng().gen(), 100);

    let owner = ADataOwner {
        public_key: *client.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    unwrap!(data.append_owner(owner, 0));
    unwrap!(data.append(
        vec![
            ADataEntry::new(b"one".to_vec(), b"foo".to_vec()),
            ADataEntry::new(b"two".to_vec(), b"bar".to_vec()),
        ],
        0,
    ));

    let data = AData::PubSeq(data);
    let address = *data.address();
    common::send_request_expect_ok(&mut env, &mut client, Request::GetBalance, *COST_OF_PUT);
    common::perform_mutation(&mut env, &mut client, Request::PutAData(data.clone()));
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::PutAData(data.clone()),
        NdError::InsufficientBalance,
    );

    // GetADataRange
    let mut range_scenario = |start, end, expected_result| {
        common::send_request_expect_ok(
            &mut env,
            &mut client,
            Request::GetADataRange {
                address,
                range: (start, end),
            },
            expected_result,
        )
    };

    range_scenario(ADataIndex::FromStart(0), ADataIndex::FromStart(0), vec![]);
    range_scenario(
        ADataIndex::FromStart(0),
        ADataIndex::FromStart(1),
        vec![ADataEntry::new(b"one".to_vec(), b"foo".to_vec())],
    );
    range_scenario(
        ADataIndex::FromStart(1),
        ADataIndex::FromStart(2),
        vec![ADataEntry::new(b"two".to_vec(), b"bar".to_vec())],
    );
    range_scenario(
        ADataIndex::FromEnd(1),
        ADataIndex::FromEnd(0),
        vec![ADataEntry::new(b"two".to_vec(), b"bar".to_vec())],
    );
    range_scenario(
        ADataIndex::FromStart(0),
        ADataIndex::FromEnd(0),
        vec![
            ADataEntry::new(b"one".to_vec(), b"foo".to_vec()),
            ADataEntry::new(b"two".to_vec(), b"bar".to_vec()),
        ],
    );
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetADataRange {
            address,
            range: (ADataIndex::FromStart(0), ADataIndex::FromStart(3)),
        },
        NdError::NoSuchEntry,
    );

    // GetADataLastEntry
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetADataLastEntry(address),
        ADataEntry::new(b"two".to_vec(), b"bar".to_vec()),
    );

    // GetADataValue
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetADataValue {
            address,
            key: b"one".to_vec(),
        },
        b"foo".to_vec(),
    );
}

#[test]
fn append_only_data_get_owners() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut data = PubSeqAppendOnlyData::new(name, tag);

    let owner_0 = ADataOwner {
        public_key: common::gen_public_key(env.rng()),
        entries_index: 0,
        permissions_index: 0,
    };
    let owner_1 = ADataOwner {
        public_key: common::gen_public_key(env.rng()),
        entries_index: 0,
        permissions_index: 0,
    };
    let owner_2 = ADataOwner {
        public_key: *client.public_id().public_key(),
        entries_index: 1,
        permissions_index: 0,
    };

    unwrap!(data.append_owner(owner_0, 0));
    unwrap!(data.append_owner(owner_1, 1));

    unwrap!(data.append(vec![ADataEntry::new(b"one".to_vec(), b"foo".to_vec())], 0));
    unwrap!(data.append_owner(owner_2, 2));

    let address = *data.address();
    common::perform_mutation(&mut env, &mut client, Request::PutAData(data.into()));

    let mut scenario = |owners_index, expected_response| {
        let req = Request::GetADataOwners {
            address,
            owners_index,
        };
        match expected_response {
            Ok(expected) => common::send_request_expect_ok(&mut env, &mut client, req, expected),
            Err(expected) => common::send_request_expect_err(&mut env, &mut client, req, expected),
        }
    };

    scenario(ADataIndex::FromStart(0), Ok(owner_0));
    scenario(ADataIndex::FromStart(1), Ok(owner_1));
    scenario(ADataIndex::FromStart(2), Ok(owner_2));
    scenario(ADataIndex::FromStart(3), Err(NdError::InvalidOwners));

    scenario(ADataIndex::FromEnd(0), Err(NdError::InvalidOwners));
    scenario(ADataIndex::FromEnd(1), Ok(owner_2));
    scenario(ADataIndex::FromEnd(2), Ok(owner_1));
    scenario(ADataIndex::FromEnd(3), Ok(owner_0));
    scenario(ADataIndex::FromEnd(4), Err(NdError::InvalidOwners));
}

#[test]
fn pub_append_only_data_get_permissions() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut data = PubSeqAppendOnlyData::new(name, tag);

    let owner = ADataOwner {
        public_key: *client.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    unwrap!(data.append_owner(owner, 0));

    let perms_0 = ADataPubPermissions {
        permissions: btreemap![ADataUser::Anyone => ADataPubPermissionSet::new(true, false)],
        entries_index: 0,
        owners_index: 1,
    };
    unwrap!(data.append_permissions(perms_0.clone(), 0));

    let public_key = common::gen_public_key(env.rng());
    let perms_1 = ADataPubPermissions {
        permissions: btreemap![
            ADataUser::Anyone => ADataPubPermissionSet::new(false, false),
            ADataUser::Key(public_key) => ADataPubPermissionSet::new(true, false)
        ],
        entries_index: 0,
        owners_index: 1,
    };
    unwrap!(data.append_permissions(perms_1.clone(), 1));

    let address = *data.address();
    common::perform_mutation(&mut env, &mut client, Request::PutAData(data.into()));

    // GetPubADataUserPermissions
    let mut scenario = |permissions_index, user, expected_response| {
        let req = Request::GetPubADataUserPermissions {
            address,
            permissions_index,
            user,
        };
        match expected_response {
            Ok(expected) => common::send_request_expect_ok(&mut env, &mut client, req, expected),
            Err(expected) => common::send_request_expect_err(&mut env, &mut client, req, expected),
        }
    };

    scenario(
        ADataIndex::FromStart(0),
        ADataUser::Anyone,
        Ok(ADataPubPermissionSet::new(true, false)),
    );
    scenario(
        ADataIndex::FromStart(0),
        ADataUser::Key(public_key),
        Err(NdError::NoSuchEntry),
    );
    scenario(
        ADataIndex::FromStart(1),
        ADataUser::Anyone,
        Ok(ADataPubPermissionSet::new(false, false)),
    );
    scenario(
        ADataIndex::FromStart(1),
        ADataUser::Key(public_key),
        Ok(ADataPubPermissionSet::new(true, false)),
    );
    scenario(
        ADataIndex::FromStart(2),
        ADataUser::Anyone,
        Err(NdError::NoSuchEntry),
    );

    scenario(
        ADataIndex::FromEnd(1),
        ADataUser::Anyone,
        Ok(ADataPubPermissionSet::new(false, false)),
    );
    scenario(
        ADataIndex::FromEnd(2),
        ADataUser::Anyone,
        Ok(ADataPubPermissionSet::new(true, false)),
    );
    scenario(
        ADataIndex::FromEnd(3),
        ADataUser::Anyone,
        Err(NdError::NoSuchEntry),
    );

    // GetUnpubADataUserPermissions (failure - incorrect data kind)
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetUnpubADataUserPermissions {
            address,
            permissions_index: ADataIndex::FromStart(1),
            public_key,
        },
        NdError::NoSuchData,
    );

    // GetADataPermissions
    let mut scenario = |permissions_index, expected_response| {
        let req = Request::GetADataPermissions {
            address,
            permissions_index,
        };
        match expected_response {
            Ok(expected) => common::send_request_expect_ok(
                &mut env,
                &mut client,
                req,
                ADataPermissions::from(expected),
            ),
            Err(expected) => common::send_request_expect_err(&mut env, &mut client, req, expected),
        }
    };

    scenario(ADataIndex::FromStart(0), Ok(perms_0));
    scenario(ADataIndex::FromStart(1), Ok(perms_1));
    scenario(ADataIndex::FromStart(2), Err(NdError::NoSuchEntry));
}

#[test]
fn unpub_append_only_data_get_permissions() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut data = UnpubSeqAppendOnlyData::new(name, tag);

    let owner = ADataOwner {
        public_key: *client.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    unwrap!(data.append_owner(owner, 0));

    let public_key_0 = common::gen_public_key(env.rng());
    let public_key_1 = common::gen_public_key(env.rng());

    let perms_0 = ADataUnpubPermissions {
        permissions: btreemap![
            public_key_0 => ADataUnpubPermissionSet::new(true, true, false)
        ],
        entries_index: 0,
        owners_index: 1,
    };
    unwrap!(data.append_permissions(perms_0.clone(), 0));

    let perms_1 = ADataUnpubPermissions {
        permissions: btreemap![
            public_key_0 => ADataUnpubPermissionSet::new(true, false, false),
            public_key_1 => ADataUnpubPermissionSet::new(true, true, true)
        ],
        entries_index: 0,
        owners_index: 1,
    };
    unwrap!(data.append_permissions(perms_1.clone(), 1));

    let address = *data.address();
    common::perform_mutation(&mut env, &mut client, Request::PutAData(data.into()));

    // GetUnpubADataUserPermissions
    let mut scenario = |permissions_index, public_key, expected_response| {
        let req = Request::GetUnpubADataUserPermissions {
            address,
            permissions_index,
            public_key,
        };
        match expected_response {
            Ok(expected) => common::send_request_expect_ok(&mut env, &mut client, req, expected),
            Err(expected) => common::send_request_expect_err(&mut env, &mut client, req, expected),
        }
    };

    scenario(
        ADataIndex::FromStart(0),
        public_key_0,
        Ok(ADataUnpubPermissionSet::new(true, true, false)),
    );
    scenario(
        ADataIndex::FromStart(0),
        public_key_1,
        Err(NdError::NoSuchEntry),
    );
    scenario(
        ADataIndex::FromStart(1),
        public_key_0,
        Ok(ADataUnpubPermissionSet::new(true, false, false)),
    );
    scenario(
        ADataIndex::FromStart(1),
        public_key_1,
        Ok(ADataUnpubPermissionSet::new(true, true, true)),
    );
    scenario(
        ADataIndex::FromStart(2),
        public_key_0,
        Err(NdError::NoSuchEntry),
    );

    scenario(
        ADataIndex::FromEnd(1),
        public_key_0,
        Ok(ADataUnpubPermissionSet::new(true, false, false)),
    );
    scenario(
        ADataIndex::FromEnd(2),
        public_key_0,
        Ok(ADataUnpubPermissionSet::new(true, true, false)),
    );
    scenario(
        ADataIndex::FromEnd(3),
        public_key_0,
        Err(NdError::NoSuchEntry),
    );

    // GetPubADataUserPermissions (failure - incorrect data kind)
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetPubADataUserPermissions {
            address,
            permissions_index: ADataIndex::FromStart(1),
            user: ADataUser::Key(public_key_0),
        },
        NdError::NoSuchData,
    );

    // GetADataPermissions
    let mut scenario = |permissions_index, expected_response| {
        let req = Request::GetADataPermissions {
            address,
            permissions_index,
        };
        match expected_response {
            Ok(expected) => common::send_request_expect_ok(
                &mut env,
                &mut client,
                req,
                ADataPermissions::from(expected),
            ),
            Err(expected) => common::send_request_expect_err(&mut env, &mut client, req, expected),
        }
    };

    scenario(ADataIndex::FromStart(0), Ok(perms_0));
    scenario(ADataIndex::FromStart(1), Ok(perms_1));
    scenario(ADataIndex::FromStart(2), Err(NdError::NoSuchEntry));
}

#[test]
fn pub_append_only_data_put_permissions() {
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
    let mut data = PubSeqAppendOnlyData::new(name, tag);

    let owner = ADataOwner {
        public_key: *client_a.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    unwrap!(data.append_owner(owner, 0));

    // Client A can manage permissions, but not B
    let perms_0 = ADataPubPermissions {
        permissions: btreemap![ADataUser::Key(public_key_a) => ADataPubPermissionSet::new(true, true)],
        entries_index: 0,
        owners_index: 1,
    };
    unwrap!(data.append_permissions(perms_0.clone(), 0));

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(AData::PubSeq(data.clone())),
    );

    // Before
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetADataPermissions {
            address: *data.address(),
            permissions_index: ADataIndex::FromStart(0),
        },
        ADataPermissions::from(perms_0),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::GetADataPermissions {
            address: *data.address(),
            permissions_index: ADataIndex::FromStart(1),
        },
        NdError::NoSuchEntry,
    );

    let perms_1 = ADataPubPermissions {
        permissions: btreemap![
            ADataUser::Key(public_key_b) => ADataPubPermissionSet::new(true, true)
        ],
        entries_index: 0,
        owners_index: 1,
    };

    // Only client A has permissions to add permissions
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::AddPubADataPermissions {
            address: *data.address(),
            permissions: perms_1.clone(),
            permissions_index: 1,
        },
        NdError::AccessDenied,
    );

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::AddPubADataPermissions {
            address: *data.address(),
            permissions: perms_1.clone(),
            permissions_index: 1,
        },
    );

    // Check that the permissions have been updated
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetADataPermissions {
            address: *data.address(),
            permissions_index: ADataIndex::FromStart(1),
        },
        ADataPermissions::from(perms_1),
    );
}

#[test]
fn unpub_append_only_data_put_permissions() {
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
    let mut data = UnpubSeqAppendOnlyData::new(name, tag);

    let owner = ADataOwner {
        public_key: *client_a.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    unwrap!(data.append_owner(owner, 0));

    // Client A can manage permissions, but not B
    let perms_0 = ADataUnpubPermissions {
        permissions: btreemap![public_key_a => ADataUnpubPermissionSet::new(true, true, true)],
        entries_index: 0,
        owners_index: 1,
    };
    unwrap!(data.append_permissions(perms_0.clone(), 0));

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(AData::UnpubSeq(data.clone())),
    );

    // Before
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetADataPermissions {
            address: *data.address(),
            permissions_index: ADataIndex::FromStart(0),
        },
        ADataPermissions::from(perms_0),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::GetADataPermissions {
            address: *data.address(),
            permissions_index: ADataIndex::FromStart(1),
        },
        NdError::NoSuchEntry,
    );

    let perms_1 = ADataUnpubPermissions {
        permissions: btreemap![
            public_key_b => ADataUnpubPermissionSet::new(true, true, true)
        ],
        entries_index: 0,
        owners_index: 1,
    };

    // Only client A has permissions to add permissions
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::AddUnpubADataPermissions {
            address: *data.address(),
            permissions: perms_1.clone(),
            permissions_index: 1,
        },
        NdError::AccessDenied,
    );

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::AddUnpubADataPermissions {
            address: *data.address(),
            permissions: perms_1.clone(),
            permissions_index: 1,
        },
    );

    // Check that the permissions have been updated
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetADataPermissions {
            address: *data.address(),
            permissions_index: ADataIndex::FromStart(1),
        },
        ADataPermissions::from(perms_1),
    );
}

#[test]
fn append_only_data_put_owners() {
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
    let mut data = PubSeqAppendOnlyData::new(name, tag);

    let owner_0 = ADataOwner {
        public_key: public_key_a,
        entries_index: 0,
        permissions_index: 0,
    };
    unwrap!(data.append_owner(owner_0, 0));

    let perms_0 = ADataPubPermissions {
        permissions: btreemap![ADataUser::Key(public_key_a) => ADataPubPermissionSet::new(true, true)],
        entries_index: 0,
        owners_index: 1,
    };

    unwrap!(data.append_permissions(perms_0.clone(), 0));
    unwrap!(data.append(
        vec![ADataEntry {
            key: b"one".to_vec(),
            value: b"foo".to_vec()
        }],
        0
    ));
    unwrap!(data.append(
        vec![ADataEntry {
            key: b"two".to_vec(),
            value: b"foo".to_vec()
        }],
        1
    ));

    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutAData(data.clone().into()),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetADataOwners {
            address: *data.address(),
            owners_index: ADataIndex::FromStart(0),
        },
        owner_0,
    );
    // Neither A or B can get the owners with index 1 (it doesn't exist)
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::GetADataOwners {
            address: *data.address(),
            owners_index: ADataIndex::FromStart(1),
        },
        NdError::InvalidOwners,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::GetADataOwners {
            address: *data.address(),
            owners_index: ADataIndex::FromStart(1),
        },
        NdError::InvalidOwners,
    );

    // Set the new owner, change from A -> B
    let owner_1 = ADataOwner {
        public_key: public_key_b,
        entries_index: 2,
        permissions_index: 1,
    };

    // B can't set the new owner, but A can
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::SetADataOwner {
            address: *data.address(),
            owner: owner_1,
            owners_index: 1,
        },
        NdError::AccessDenied,
    );
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SetADataOwner {
            address: *data.address(),
            owner: owner_1,
            owners_index: 1,
        },
    );

    // Check the new owner
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetADataOwners {
            address: *data.address(),
            owners_index: ADataIndex::FromStart(1),
        },
        owner_1,
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::GetADataOwners {
            address: *data.address(),
            owners_index: ADataIndex::FromStart(1),
        },
        owner_1,
    );
}

#[test]
fn append_only_data_append_seq() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    let public_key = *client.public_id().public_key();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut data = PubSeqAppendOnlyData::new(name, tag);

    let owner_0 = ADataOwner {
        public_key,
        entries_index: 0,
        permissions_index: 0,
    };
    unwrap!(data.append_owner(owner_0, 0));

    let perms_0 = ADataPubPermissions {
        permissions: btreemap![ADataUser::Anyone => ADataPubPermissionSet::new(true, true)],
        entries_index: 0,
        owners_index: 1,
    };

    unwrap!(data.append_permissions(perms_0.clone(), 0));
    unwrap!(data.append(
        vec![ADataEntry {
            key: b"one".to_vec(),
            value: b"foo".to_vec()
        }],
        0
    ));
    unwrap!(data.append(
        vec![ADataEntry {
            key: b"two".to_vec(),
            value: b"foo".to_vec()
        }],
        1
    ));

    common::perform_mutation(
        &mut env,
        &mut client,
        Request::PutAData(data.clone().into()),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetADataLastEntry(*data.address()),
        ADataEntry::new(b"two".to_vec(), b"foo".to_vec()),
    );

    let appended_values = ADataEntry::new(b"three".to_vec(), b"bar".to_vec());
    let append = ADataAppendOperation {
        address: *data.address(),
        values: vec![appended_values.clone()],
    };
    // First try an invalid append
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::AppendUnseq(append.clone()),
        NdError::InvalidOperation,
    );
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::AppendSeq { append, index: 2 },
    );

    // Check the result
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetADataLastEntry(*data.address()),
        appended_values,
    );
}

#[test]
fn append_only_data_append_unseq() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();
    let public_key = *client.public_id().public_key();

    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);

    let name: XorName = env.rng().gen();
    let tag = 100;
    let mut data = PubUnseqAppendOnlyData::new(name, tag);

    let owner_0 = ADataOwner {
        public_key,
        entries_index: 0,
        permissions_index: 0,
    };
    unwrap!(data.append_owner(owner_0, 0));

    let perms_0 = ADataPubPermissions {
        permissions: btreemap![ADataUser::Anyone => ADataPubPermissionSet::new(true, true)],
        entries_index: 0,
        owners_index: 1,
    };

    unwrap!(data.append_permissions(perms_0.clone(), 0));
    unwrap!(data.append(vec![ADataEntry {
        key: b"one".to_vec(),
        value: b"foo".to_vec()
    }]));
    unwrap!(data.append(vec![ADataEntry {
        key: b"two".to_vec(),
        value: b"foo".to_vec()
    }]));

    common::perform_mutation(
        &mut env,
        &mut client,
        Request::PutAData(data.clone().into()),
    );

    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetADataLastEntry(*data.address()),
        ADataEntry::new(b"two".to_vec(), b"foo".to_vec()),
    );

    let appended_values = ADataEntry::new(b"three".to_vec(), b"bar".to_vec());
    let append = ADataAppendOperation {
        address: *data.address(),
        values: vec![appended_values.clone()],
    };

    // First try an invalid append
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::AppendSeq {
            append: append.clone(),
            index: 2,
        },
        NdError::InvalidOperation,
    );
    common::perform_mutation(&mut env, &mut client, Request::AppendUnseq(append));

    // Check the result
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetADataLastEntry(*data.address()),
        appended_values,
    );
}

////////////////////////////////////////////////////////////////////////////////
//
// Immutable data
//
////////////////////////////////////////////////////////////////////////////////

#[test]
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
        Request::PutIData(pub_idata.clone()),
        NdError::NoSuchBalance,
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::PutIData(unpub_idata.clone()),
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
        Request::PutIData(unpub_idata.clone()),
        NdError::InvalidOwners,
    );

    let mut expected_a = unwrap!(Coins::from_nano(start_nano - 1));
    let mut expected_b = unwrap!(Coins::from_nano(start_nano));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, expected_a);

    // Check they can both Put valid data.
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutIData(pub_idata.clone()),
    );
    common::perform_mutation(
        &mut env,
        &mut client_b,
        Request::PutIData(unpub_idata.clone()),
    );

    expected_a = unwrap!(expected_a.checked_sub(*COST_OF_PUT));
    expected_b = unwrap!(expected_b.checked_sub(*COST_OF_PUT));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, expected_a);
    common::send_request_expect_ok(&mut env, &mut client_b, Request::GetBalance, expected_b);

    // Check the data is retrievable.
    common::send_request_expect_ok(
        &mut env,
        &mut client_a,
        Request::GetIData(*pub_idata.address()),
        pub_idata.clone(),
    );
    common::send_request_expect_ok(
        &mut env,
        &mut client_b,
        Request::GetIData(*unpub_idata.address()),
        unpub_idata.clone(),
    );

    // Published data can be put again, but unpublished not
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutIData(pub_idata.clone()),
    );
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::PutIData(unpub_idata.clone()),
        NdError::DataExists,
    );

    expected_a = unwrap!(expected_a.checked_sub(*COST_OF_PUT));
    expected_b = unwrap!(expected_b.checked_sub(*COST_OF_PUT));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, expected_a);
    common::send_request_expect_ok(&mut env, &mut client_b, Request::GetBalance, expected_b);
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
        Request::GetIData(IDataAddress::Pub(address)),
        NdError::NoSuchData,
    );

    // Try to get non-existing unpublished immutable data while having no balance
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetIData(IDataAddress::Unpub(address)),
        NdError::NoSuchData,
    );

    // Try to get non-existing unpublished immutable data while having balance
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetIData(IDataAddress::Unpub(address)),
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
    let mut request = Request::GetIData(*pub_idata.address());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutIData(pub_idata.clone()),
    );
    common::send_request_expect_ok(&mut env, &mut client_a, request.clone(), pub_idata.clone());
    common::send_request_expect_ok(&mut env, &mut client_b, request, pub_idata);

    // Client A uploads unpublished data that Client B can't fetch
    let owner = client_a.public_id().public_key();
    let unpub_idata = IData::Unpub(UnpubImmutableData::new(vec![42], *owner));
    request = Request::GetIData(*unpub_idata.address());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutIData(unpub_idata.clone()),
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
    common::perform_mutation(&mut env, &mut client, Request::PutIData(pub_idata.clone()));
    assert_eq!(
        pub_idata,
        common::get_from_response(
            &mut env,
            &mut client,
            Request::GetIData(IDataAddress::Pub(pub_idata_address))
        ),
    );

    // Get some unpublished immutable data from the same address
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetIData(IDataAddress::Unpub(pub_idata_address)),
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
        Request::PutIData(unpub_idata.clone()),
    );
    assert_eq!(
        unpub_idata,
        common::get_from_response(
            &mut env,
            &mut client,
            Request::GetIData(IDataAddress::Unpub(unpub_idata_address))
        ),
    );

    // Get some published immutable data from the same address
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetIData(IDataAddress::Pub(unpub_idata_address)),
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
        Request::DeleteUnpubIData(IDataAddress::Pub(address)),
        NdError::InvalidOperation,
    );

    // Try to delete non-existing unpublished data while not having a balance
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetIData(IDataAddress::Unpub(address)),
        NdError::NoSuchData,
    );

    // Try to delete non-existing unpublished data
    let start_nano = 1_000_000_000_000;
    common::create_balance(&mut env, &mut client, None, start_nano);
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetIData(IDataAddress::Unpub(address)),
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
    let pub_idata = IData::Pub(PubImmutableData::new(raw_data.clone()));
    let pub_idata_address: XorName = *pub_idata.address().name();
    common::perform_mutation(&mut env, &mut client_a, Request::PutIData(pub_idata));

    // Try to delete published data by constructing inconsistent Request
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteUnpubIData(IDataAddress::Pub(pub_idata_address)),
        NdError::InvalidOperation,
    );

    // Try to delete published data by raw XorName
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteUnpubIData(IDataAddress::Unpub(pub_idata_address)),
        NdError::NoSuchData,
    );

    let raw_data = vec![42];
    let owner = client_a.public_id().public_key();
    let unpub_idata = IData::Unpub(UnpubImmutableData::new(raw_data.clone(), *owner));
    let unpub_idata_address: XorName = *unpub_idata.address().name();
    common::perform_mutation(&mut env, &mut client_a, Request::PutIData(unpub_idata));

    // Delete unpublished data without being the owner
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::DeleteUnpubIData(IDataAddress::Unpub(unpub_idata_address)),
        NdError::AccessDenied,
    );

    // Delete unpublished data without having the balance
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::DeleteUnpubIData(IDataAddress::Unpub(unpub_idata_address)),
    );

    // Delete unpublished data again
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteUnpubIData(IDataAddress::Unpub(unpub_idata_address)),
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
        let request = Request::ListAuthKeysAndVersion;
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
    let make_ins_request = |version| Request::InsAuthKey {
        key: app_public_key,
        version,
        permissions,
    };

    // TODO - enable this once we're passed phase 1.
    if false {
        // Try to insert and then list authorised keys using a client with no balance. Each should
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
    for _ in 0..DEFAULT_NUM_CONNECTED_VAULTS {
        let _ = app.expect_notification();
    }

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
        Request::ListAuthKeysAndVersion,
        NdError::AccessDenied,
    );
    common::send_request_expect_err(
        &mut env,
        &mut app,
        make_ins_request(2),
        NdError::AccessDenied,
    );
    let del_auth_key_request = Request::DelAuthKey {
        key: *app.public_id().public_key(),
        version: 2,
    };
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
fn app_permissions() {
    let mut env = Environment::new();

    let mut owner = env.new_connected_client();
    let balance = unwrap!(Coins::from_nano(1000));
    common::create_balance(&mut env, &mut owner, None, balance);

    // App 0 is authorized with permission to perform mutations.
    let mut app_0 = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::InsAuthKey {
            key: *app_0.public_id().public_key(),
            version: 1,
            permissions: AppPermissions {
                perform_mutations: true,
                get_balance: false,
                transfer_coins: false,
            },
        },
    );
    env.establish_connection(&mut app_0);

    // App 1 is authorized, and can only read balance.
    let mut app_1 = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::InsAuthKey {
            key: *app_1.public_id().public_key(),
            version: 2,
            permissions: AppPermissions {
                transfer_coins: false,
                get_balance: true,
                perform_mutations: false,
            },
        },
    );
    env.establish_connection(&mut app_1);

    // App 2 is not authorized.
    let mut app_2 = env.new_connected_app(owner.public_id().clone());

    // App 3 is authorized with permission to transfer coins only.
    let mut app_3 = env.new_disconnected_app(owner.public_id().clone());
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::InsAuthKey {
            key: *app_3.public_id().public_key(),
            version: 3,
            permissions: AppPermissions {
                perform_mutations: false,
                get_balance: false,
                transfer_coins: true,
            },
        },
    );
    env.establish_connection(&mut app_3);

    let adata_owner = ADataOwner {
        public_key: *owner.public_id().public_key(),
        entries_index: 0,
        permissions_index: 0,
    };

    let mut pub_data = PubUnseqAppendOnlyData::new(env.rng().gen(), 100);
    unwrap!(pub_data.append_owner(adata_owner, 0));
    unwrap!(pub_data.append_permissions(
        ADataPubPermissions {
            permissions: btreemap![ADataUser::Anyone => ADataPubPermissionSet::new(true, true)],
            entries_index: 0,
            owners_index: 1,
        },
        0
    ));

    let pub_data_address = *pub_data.address();
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::PutAData(AData::from(pub_data)),
    );

    let mut unpub_data = UnpubUnseqAppendOnlyData::new(env.rng().gen(), 101);
    unwrap!(unpub_data.append_owner(adata_owner, 0));
    unwrap!(unpub_data.append_permissions(
        ADataUnpubPermissions {
            permissions: btreemap![
                *app_0.public_id().public_key() => ADataUnpubPermissionSet::new(true, true, true),
                *app_1.public_id().public_key() => ADataUnpubPermissionSet::new(true, true, true),
                *app_2.public_id().public_key() => ADataUnpubPermissionSet::new(true, true, true),
            ],
            entries_index: 0,
            owners_index: 1,
        },
        0
    ));

    let unpub_data_address = *unpub_data.address();
    common::perform_mutation(
        &mut env,
        &mut owner,
        Request::PutAData(AData::from(unpub_data)),
    );

    // All three apps can perform get request against published data
    let _: AData =
        common::get_from_response(&mut env, &mut app_0, Request::GetAData(pub_data_address));
    let _: AData =
        common::get_from_response(&mut env, &mut app_1, Request::GetAData(pub_data_address));
    let _: AData =
        common::get_from_response(&mut env, &mut app_2, Request::GetAData(pub_data_address));

    // Only the authorized apps can perform get request against unpublished data
    let _: AData =
        common::get_from_response(&mut env, &mut app_0, Request::GetAData(unpub_data_address));
    let _: AData =
        common::get_from_response(&mut env, &mut app_1, Request::GetAData(unpub_data_address));
    common::send_request_expect_err(
        &mut env,
        &mut app_2,
        Request::GetAData(unpub_data_address),
        NdError::AccessDenied,
    );

    // Only the app with the transfer coins permission can perform mutable request.
    for address in [pub_data_address, unpub_data_address].iter().cloned() {
        let append = ADataAppendOperation {
            address,
            values: vec![ADataEntry {
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            }],
        };

        common::send_request_expect_ok(
            &mut env,
            &mut app_0,
            Request::AppendUnseq(append.clone()),
            (),
        );

        common::send_request_expect_err(
            &mut env,
            &mut app_1,
            Request::AppendUnseq(append.clone()),
            NdError::AccessDenied,
        );
        common::send_request_expect_err(
            &mut env,
            &mut app_2,
            Request::AppendUnseq(append),
            NdError::AccessDenied,
        );
    }

    // A new client to credit coins to.
    let mut creditor = env.new_connected_client();
    common::create_balance(&mut env, &mut creditor, None, unwrap!(Coins::from_nano(0)));

    // App 1 cannot transfer coins.
    common::send_request_expect_err(
        &mut env,
        &mut app_1,
        Request::TransferCoins {
            destination: *creditor.public_id().name(),
            amount: unwrap!(Coins::from_nano(50)),
            transaction_id: 0,
        },
        NdError::AccessDenied,
    );

    // App1 can read balance
    common::send_request_expect_ok(
        &mut env,
        &mut app_1,
        Request::GetBalance,
        Response::GetBalance(Ok(unwrap!(Coins::from_nano(996)))),
    );

    let amount = unwrap!(Coins::from_nano(900));
    let expected = Response::Transaction(Ok(Transaction { id: 1, amount }));
    let name: XorName = env.rng().gen();
    let tag = 100;
    let data = SeqMutableData::new(name, tag, *owner.public_id().public_key());

    // App 3 can transfer coins on behalf of the user
    common::send_request_expect_ok(
        &mut env,
        &mut app_3,
        Request::TransferCoins {
            destination: *creditor.public_id().name(),
            amount,
            transaction_id: 1,
        },
        expected,
    );

    // App 3 cannot mutate on behalf of the user
    common::send_request_expect_err(
        &mut env,
        &mut app_3,
        Request::PutMData(MData::from(data)),
        NdError::AccessDenied,
    );

    // App 3 cannot read balance of the user
    common::send_request_expect_err(
        &mut env,
        &mut app_3,
        Request::GetBalance,
        NdError::AccessDenied,
    )
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

    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    // Try to put sequenced Mutable Data
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = SeqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::PutMData(MData::Seq(mdata.clone())),
    );

    // Get Mutable Data and verify it's been stored correctly.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMData(MDataAddress::Seq { name, tag }),
        MData::Seq(mdata),
    );
}

#[test]
fn put_unseq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

    // Try to put unsequenced Mutable Data
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = UnseqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::PutMData(MData::Unseq(mdata.clone())),
    );

    // Get Mutable Data and verify it's been stored correctly.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMData(MDataAddress::Unseq { name, tag }),
        MData::Unseq(mdata),
    );
}

#[test]
fn read_seq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    common::create_balance(&mut env, &mut client, None, *COST_OF_PUT);

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
        Request::PutMData(MData::Seq(mdata.clone())),
    );

    // Get version.
    let address = MDataAddress::Seq { name, tag };
    common::send_request_expect_ok(&mut env, &mut client, Request::GetMDataVersion(address), 0);

    // Get keys.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::ListMDataKeys(address),
        entries.keys().cloned().collect::<BTreeSet<_>>(),
    );

    // Get values.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::ListMDataValues(address),
        MDataValues::from(entries.values().cloned().collect::<Vec<_>>()),
    );

    // Get entries.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::ListMDataEntries(address),
        MDataEntries::from(entries.clone()),
    );

    // Get a value by key.
    let key = unwrap!(entries.keys().cloned().nth(0));
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: key.clone(),
        },
        MDataValue::from(entries[&key].clone()),
    );
}

#[test]
fn mutate_seq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let balance = common::multiply_coins(*COST_OF_PUT, 4);
    common::create_balance(&mut env, &mut client, None, balance);

    // Try to put sequenced Mutable Data.
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = SeqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::PutMData(MData::Seq(mdata.clone())),
    );

    // Get a non-existant value by key.
    let address = MDataAddress::Seq { name, tag };
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![0],
        },
        NdError::NoSuchEntry,
    );

    // Insert new values.
    let actions = MDataSeqEntryActions::new()
        .ins(vec![0], vec![1], 0)
        .ins(vec![1], vec![1], 0);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![0],
        },
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
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![0],
        },
        MDataValue::from(MDataSeqValue {
            data: vec![2],
            version: 1,
        }),
    );

    // Deleted key should not exist now.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![1],
        },
        NdError::NoSuchEntry,
    );

    // Try an invalid update request.
    let expected_invalid_actions = btreemap![vec![0] => EntryError::InvalidSuccessor(1)];
    let actions = MDataSeqEntryActions::new().update(vec![0], vec![3], 0);
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::MutateMDataEntries {
            address: MDataAddress::Seq { name, tag },
            actions: actions.into(),
        },
        NdError::InvalidEntryActions(expected_invalid_actions),
    );
}

#[test]
fn mutate_unseq_mutable_data() {
    let mut env = Environment::new();
    let mut client = env.new_connected_client();

    let balance = common::multiply_coins(*COST_OF_PUT, 3);
    common::create_balance(&mut env, &mut client, None, balance);

    // Try to put unsequenced Mutable Data.
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = UnseqMutableData::new(name, tag, *client.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::PutMData(MData::Unseq(mdata.clone())),
    );

    // Get a non-existant value by key.
    let address = MDataAddress::Unseq { name, tag };
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![0],
        },
        NdError::NoSuchEntry,
    );

    // Insert new values.
    let actions = MDataUnseqEntryActions::new()
        .ins(vec![0], vec![1])
        .ins(vec![1], vec![1]);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![0],
        },
        MDataValue::from(vec![1]),
    );

    // Update and delete entries.
    let actions = MDataUnseqEntryActions::new()
        .update(vec![0], vec![2])
        .del(vec![1]);
    common::perform_mutation(
        &mut env,
        &mut client,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );

    // Get an existing value by key.
    common::send_request_expect_ok(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![0],
        },
        MDataValue::from(vec![2]),
    );

    // Deleted key should not exist now.
    common::send_request_expect_err(
        &mut env,
        &mut client,
        Request::GetMDataValue {
            address,
            key: vec![1],
        },
        NdError::NoSuchEntry,
    );
}

#[test]
fn mutable_data_permissions() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let balance_a = common::multiply_coins(*COST_OF_PUT, 3);
    let balance_b = common::multiply_coins(*COST_OF_PUT, 3);
    common::create_balance(&mut env, &mut client_a, None, balance_a);
    common::create_balance(&mut env, &mut client_b, None, balance_b);

    // Try to put new unsequenced Mutable Data.
    let name: XorName = env.rng().gen();
    let tag = 100;
    let mdata = UnseqMutableData::new(name, tag, *client_a.public_id().public_key());
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutMData(MData::Unseq(mdata.clone())),
    );

    // Make sure client B can't insert anything.
    let actions = MDataUnseqEntryActions::new().ins(vec![0], vec![1]);
    let address = MDataAddress::Unseq { name, tag };
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
        NdError::AccessDenied,
    );

    // Insert permissions for client B.
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::SetMDataUserPermissions {
            address,
            user: *client_b.public_id().public_key(),
            permissions: MDataPermissionSet::new().allow(MDataAction::Insert),
            version: 1,
        },
    );

    // Client B now can insert new values.
    let actions = MDataUnseqEntryActions::new().ins(vec![0], vec![1]);
    common::perform_mutation(
        &mut env,
        &mut client_b,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
    );

    // Delete client B permissions.
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::DelMDataUserPermissions {
            address,
            user: *client_b.public_id().public_key(),
            version: 2,
        },
    );

    // Client B can't insert anything again.
    let actions = MDataUnseqEntryActions::new().ins(vec![0], vec![1]);
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::MutateMDataEntries {
            address,
            actions: actions.into(),
        },
        NdError::AccessDenied,
    );
}

#[test]
fn delete_mutable_data() {
    let mut env = Environment::new();

    let mut client_a = env.new_connected_client();
    let mut client_b = env.new_connected_client();

    let balance_a = common::multiply_coins(*COST_OF_PUT, 3);
    common::create_balance(&mut env, &mut client_a, None, balance_a);
    common::create_balance(&mut env, &mut client_b, None, *COST_OF_PUT);

    let mdata = UnseqMutableData::new(env.rng().gen(), 100, *client_a.public_id().public_key());
    let address = *mdata.address();
    common::perform_mutation(
        &mut env,
        &mut client_a,
        Request::PutMData(MData::Unseq(mdata.clone())),
    );
    let balance_a = unwrap!(balance_a.checked_sub(*COST_OF_PUT));
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // Attempt to delete non-existent data.
    let invalid_address = MDataAddress::from_kind(MDataKind::Unseq, env.rng().gen(), 101);
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::DeleteMData(invalid_address),
        NdError::NoSuchData,
    );
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // Attempt to delete the data by non-owner.
    common::send_request_expect_err(
        &mut env,
        &mut client_b,
        Request::DeleteMData(address),
        NdError::AccessDenied,
    );
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // Successfully delete.
    common::send_request_expect_ok(&mut env, &mut client_a, Request::DeleteMData(address), ());
    common::send_request_expect_ok(&mut env, &mut client_a, Request::GetBalance, balance_a);

    // Verify the data doesn't exist any more.
    common::send_request_expect_err(
        &mut env,
        &mut client_a,
        Request::GetMData(address),
        NdError::NoSuchData,
    );
}
