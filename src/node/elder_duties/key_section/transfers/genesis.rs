// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use bls::SecretKeySet;
use sn_data_types::{Credit, Money, PublicKey, SignedCredit};
use std::collections::BTreeMap;

use crate::{Error, Result};

/// Produces a genesis balance for a new network.
pub fn get_genesis(balance: u64, id: PublicKey) -> Result<SignedCredit> {
    let index = 0;
    let threshold = 0;
    // Nothing comes before genesis, it is a paradox
    // that it comes from somewhere. In other words, it is
    // signed over from a "ghost", the keys generated are "ghost" keys,
    // they come from nothing and can't be verified.
    // They are unimportant and will be thrown away,
    // thus the source of random is also unimportant.
    let mut rng = rand::thread_rng();
    let bls_secret_key = SecretKeySet::random(threshold, &mut rng);
    let peer_replicas = bls_secret_key.public_keys();
    let secret_key = bls_secret_key.secret_key_share(index);

    let credit = Credit {
        id: Default::default(),
        amount: Money::from_nano(balance),
        recipient: id,
        msg: "genesis".to_string(),
    };

    let serialised_credit = bincode::serialize(&credit)?;
    let sender_sig_share = secret_key.sign(serialised_credit);
    let mut sender_sig_shares = BTreeMap::new();
    let _ = sender_sig_shares.insert(0, sender_sig_share);
    // Combine shares to produce the main signature.
    let sender_signature = sn_data_types::Signature::Bls(
        peer_replicas
            .combine_signatures(&sender_sig_shares)
            .map_err(|_| Error::CouldNotCombineSignatures)?,
    );

    Ok(SignedCredit {
        credit,
        actor_signature: sender_signature,
    })
}
