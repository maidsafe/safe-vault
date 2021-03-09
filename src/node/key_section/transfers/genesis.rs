// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::RewardsAndWallets, Error, Network, Result};
use sn_data_types::{Credit, CreditAgreementProof, SignedCredit, Token};
use std::collections::BTreeMap;

/// Produces a genesis balance for a new network.
pub async fn get_genesis(
    balance: u64,
    rewards_and_wallets: &RewardsAndWallets,
    network: Network,
) -> Result<CreditAgreementProof> {
    let recipient = network
        .section_public_key()
        .await
        .ok_or(Error::NoSectionPublicKey)?;
    let credit = Credit {
        id: Default::default(),
        amount: Token::from_nano(balance),
        recipient,
        msg: "genesis".to_string(),
    };

    // actor instances' signatures over > credit <
    let our_pk_set = network.our_public_key_set().await?;
    let mut credit_sig_shares = BTreeMap::new();
    let our_pk_share = network.our_public_key_share().await?;
    let index = network.our_index().await?;

    let credit_sig_share = network.sign_as_elder(&credit).await?;
    let _ = credit_sig_shares.insert(index, credit_sig_share);

    // Combine shares to produce the main signature.
    let actor_signature = sn_data_types::Signature::Bls(
        our_pk_set
            .combine_signatures(&credit_sig_shares)
            .map_err(|_| Error::CouldNotCombineSignatures)?,
    );

    let signed_credit = SignedCredit {
        credit,
        actor_signature,
    };

    // replicas signatures over > signed_credit <

    let mut credit_sig_shares = BTreeMap::new();
    let credit_sig_share = network.sign_as_elder(&signed_credit).await?;
    let _ = credit_sig_shares.insert(index, credit_sig_share);

    let debiting_replicas_sig = sn_data_types::Signature::Bls(
        our_pk_set
            .combine_signatures(&credit_sig_shares)
            .map_err(|_| Error::CouldNotCombineSignatures)?,
    );

    Ok(CreditAgreementProof {
        signed_credit,
        debiting_replicas_sig,
        debiting_replicas_keys: our_pk_set,
    })
}
