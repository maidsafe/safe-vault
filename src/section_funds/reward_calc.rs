// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::{NodeAge, PublicKey, Token};
use sn_routing::XorName;
use std::collections::BTreeMap;

const MIN_REWARD_AGE: u8 = 6;

///  -----  MINTING  -----
/// This is the minting of new coins happening;
/// the size being the sum of payments to parent section,
/// i.e. it at most doubles the amount paid into section,
/// or else what's left until we've reached max supply.
/// Max supply is the proportional supply for a section in
/// a network of a certain size, i.e. max _total_ supply (2^32) divided by number of sections.
pub fn get_reward_and_mint_amount(
    payments: Token,
    section_managed: Token,
    max_supply: Token,
) -> Token {
    let payments = payments.as_nano();
    let section_managed = section_managed.as_nano();
    let max_supply = max_supply.as_nano();
    let reward_nanos = if max_supply > section_managed {
        // an amount at most equal to `payments` will be minted
        let to_be_minted = u64::min(payments, max_supply - section_managed);
        // reward = payments + newly minted tokens
        payments + to_be_minted
    } else {
        // the section has exceeded its proportional supply in the network
        let excess_supply = section_managed - max_supply;
        // paid tokens are burned by
        // rewarding less than paid
        if payments > excess_supply {
            payments - excess_supply
        } else {
            0 // can't go minus rewards, but whatever was paid is now burned completely
        }
    };

    Token::from_nano(reward_nanos)
}

/// Calculates reward for each public key
/// proportional to the age of its node,
/// out of the total amount supplied.
pub fn distribute_rewards(
    amount: Token,
    nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
) -> BTreeMap<XorName, (NodeAge, PublicKey, Token)> {
    let reward_buckets = get_buckets(nodes);
    distribute(amount, reward_buckets)
}

fn get_buckets(
    nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
) -> BTreeMap<NodeAge, BTreeMap<XorName, PublicKey>> {
    let mut reward_buckets = BTreeMap::new();
    for (node_name, (age, wallet)) in nodes {
        if age >= MIN_REWARD_AGE {
            let _ = reward_buckets
                .entry(age)
                .or_insert_with(BTreeMap::new)
                .insert(node_name, wallet);
        }
    }
    println!("reward_buckets: {}", reward_buckets.len());
    reward_buckets
}

fn distribute(
    amount: Token,
    reward_buckets: BTreeMap<NodeAge, BTreeMap<XorName, PublicKey>>,
) -> BTreeMap<XorName, (NodeAge, PublicKey, Token)> {
    if reward_buckets.is_empty() {
        return BTreeMap::new();
    }
    let mut counters = BTreeMap::new();
    let mut remaining_amount = amount.as_nano();

    // shorten iterations
    let max_age = *reward_buckets.keys().max().unwrap_or(&1) as u64;
    let node_count = reward_buckets.values().map(|b| b.len() as u64).sum::<u64>();
    let share = remaining_amount / (max_age * node_count);
    let divisor = max_age * remaining_amount.to_string().len() as u64;
    let bucket_multiplier = u64::max(1, share / divisor);

    while remaining_amount > 0 {
        for (age, wallets) in &reward_buckets {
            // every tick up in age indicates about double amount of work performed
            let proportional_work = 2_u64.pow(*age as u32);
            let reward = u64::min(
                (proportional_work * wallets.len() as u64) * bucket_multiplier,
                remaining_amount,
            );
            let _ = counters
                .entry(*age)
                .and_modify(|existing| *existing += reward)
                .or_insert(reward);
            remaining_amount -= reward;
            if remaining_amount == 0 {
                break;
            }
        }
    }

    let mut to_return = BTreeMap::new();
    for (age, reward) in counters {
        let wallets = reward_buckets.get(&age).unwrap();
        let wallet_count = wallets.len() as u64;
        let reward_per_wallet = reward / wallet_count;
        let remainder = reward % wallet_count;

        let mut first_added: bool = false;
        for (node_name, wallet) in wallets {
            if !first_added {
                let _ = to_return.insert(
                    *node_name,
                    (
                        age,
                        *wallet,
                        Token::from_nano(reward_per_wallet + remainder),
                    ),
                );
                first_added = true;
            } else {
                let _ = to_return.insert(
                    *node_name,
                    (age, *wallet, Token::from_nano(reward_per_wallet)),
                );
            }
        }
    }

    println!("remaining_amount: {}", remaining_amount);

    to_return
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use sn_data_types::NodeAge;

    use super::*;

    #[test]
    fn calculates_reward_distribution() {
        // setup
        let amount = Token::from_nano(u32::MAX as u64 * 1_000_000_000);
        println!("Paid to section: {:?}", amount.as_nano());
        println!();

        let iters = 10;
        let mut nodes = BTreeMap::<XorName, (NodeAge, PublicKey)>::new();
        for i in 0..iters {
            let _ = nodes.insert(XorName::random(), (i + MIN_REWARD_AGE - 1, get_random_pk()));
            let _ = nodes.insert(XorName::random(), (i + MIN_REWARD_AGE, get_random_pk()));
            let _ = nodes.insert(XorName::random(), (i + MIN_REWARD_AGE, get_random_pk()));
        }

        println!("Added {} nodes", nodes.len());

        // start timer
        let now = std::time::Instant::now();

        // calc
        let rewards = distribute_rewards(amount, nodes);

        // stop timer
        let duration = now.elapsed();

        println!();
        println!("Elapsed: {:?} ms", duration.as_millis());
        println!();

        let mut total = 0;
        let rewards = rewards.values().sorted();
        for (_, _, amount) in rewards {
            println!("{:?}", amount.as_nano());
            total += amount.as_nano();
        }

        println!();

        println!("Total rewards: {:?}", total);
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(bls::SecretKey::random().public_key())
    }
}
