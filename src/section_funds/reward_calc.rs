// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use log::debug;
use sn_data_types::{NodeAge, PublicKey, Token};
use sn_routing::{Prefix, XorName};
use std::collections::{BTreeMap, BTreeSet};

const MIN_REWARD_AGE: u8 = 5;

/// Calculates reward for each public key
/// proportional to the age of its node,
/// out of the total payments received.
pub fn distribute_rewards(
    payments: Token,
    nodes: BTreeMap<XorName, (NodeAge, PublicKey)>,
) -> BTreeMap<XorName, (NodeAge, PublicKey, Token)> {
    let reward_buckets = get_buckets(nodes);
    distribute(payments, reward_buckets)
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
    payments: Token,
    reward_buckets: BTreeMap<NodeAge, BTreeMap<XorName, PublicKey>>,
) -> BTreeMap<XorName, (NodeAge, PublicKey, Token)> {
    if reward_buckets.is_empty() {
        return Default::default();
    }
    let mut counters = BTreeMap::new();
    let mut remaining_payments = payments.as_nano();

    // shorten iterations by
    let apprx = remaining_payments / u64::max(1, reward_buckets.len() as u64);
    let ratio = reward_buckets.keys().max().unwrap_or(&1);
    let div = u64::max(1, apprx / *ratio as u64 / 25);

    while remaining_payments > 0 {
        for (age, wallets) in &reward_buckets {
            let reward = u64::min(
                (*age as usize * wallets.len()) as u64 * div,
                remaining_payments,
            );
            let _ = counters
                .entry(*age)
                .and_modify(|existing| *existing += reward)
                .or_insert(reward);
            remaining_payments -= reward;
            if remaining_payments == 0 {
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

    println!("remaining_payments: {}", remaining_payments);

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
        let amount = Token::from_nano(1_000_000_000);
        println!("Paid to section: {:?}", amount.as_nano());
        println!();

        let iters = 7;
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
