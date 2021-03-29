// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::{BTreeMap, BTreeSet};

use sn_data_types::{PublicKey, Token};
use sn_routing::Prefix;

const MIN_REWARD_AGE: u8 = 6;

/// Calculates reward for each public key
/// proportional to the age of its node,
/// out of the total payments received.
pub fn distribute_rewards(
    payments: Token,
    nodes: BTreeMap<PublicKey, Age>,
) -> BTreeMap<PublicKey, Token> {
    let reward_buckets = get_buckets(nodes);
    let rewards = distribute(payments, reward_buckets);
    rewards
}

fn get_buckets(nodes: BTreeMap<PublicKey, Age>) -> BTreeMap<usize, BTreeSet<PublicKey>> {
    let mut reward_buckets = BTreeMap::new();
    for (wallet, age) in nodes {
        if age >= MIN_REWARD_AGE {
            let _ = reward_buckets
                .entry((age as usize))
                .or_insert(BTreeSet::new())
                .insert(wallet);
        }
    }
    println!("reward_buckets: {}", reward_buckets.len());
    reward_buckets
}

fn distribute(
    payments: Token,
    reward_buckets: BTreeMap<usize, BTreeSet<PublicKey>>,
) -> BTreeMap<PublicKey, Token> {
    let mut counters = BTreeMap::new();
    let mut remaining_payments = payments.as_nano();

    // shorten iterations by
    let apprx = remaining_payments / reward_buckets.len() as u64;
    let ratio = reward_buckets.keys().max().unwrap();
    let div = apprx / *ratio as u64 / 25;

    while remaining_payments > 0 {
        for (age, wallets) in &reward_buckets {
            let reward = u64::min((*age * wallets.len()) as u64 * div, remaining_payments);
            let _ = counters
                .entry(*age)
                .and_modify(|existing| *existing += reward)
                .or_insert(reward);
            remaining_payments -= reward;
            if remaining_payments <= 0 {
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
        for wallet in wallets {
            if !first_added {
                let _ = to_return.insert(*wallet, Token::from_nano(reward_per_wallet + remainder));
                first_added = true;
            } else {
                let _ = to_return.insert(*wallet, Token::from_nano(reward_per_wallet));
            }
        }
    }

    println!("remaining_payments: {}", remaining_payments);

    to_return
}

/// Calculation of reward for nodes.
#[derive(Clone)]
pub struct RewardCalc {
    prefix: Prefix,
}

// Node age
type Age = u8;

impl RewardCalc {
    /// Ctor
    pub fn new(prefix: Prefix) -> RewardCalc {
        Self { prefix }
    }

    /// Calculates the reward for a node
    /// when it has reached a certain age.
    pub fn reward(&self, age: Age) -> Token {
        let prefix_len = self.prefix.bit_count();
        RewardCalc::reward_from(age, prefix_len)
    }

    fn reward_from(age: Age, prefix_len: usize) -> Token {
        let time = 2_u64.pow(age as u32);
        let nanos = 1_000_000_000;
        let network_size = 2_u64.pow(prefix_len as u32);
        let steepness_reductor = prefix_len as u64 + 1;
        Token::from_nano(time * nanos / network_size * steepness_reductor)
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use super::*;

    #[test]
    fn distr() {
        // setup
        let full_amount = Token::from_nano(u32::MAX as u64 * 1_000_000_000);
        println!("Initial amount: {:?}", full_amount.as_nano());
        println!();

        let iters = 7;
        //let new_section_size = 21;
        let mut nodes = BTreeMap::<PublicKey, Age>::new();
        for i in 0..iters {
            let _ = nodes.insert(get_random_pk(), i + MIN_REWARD_AGE - 1);
            let _ = nodes.insert(get_random_pk(), i + MIN_REWARD_AGE);
            let _ = nodes.insert(get_random_pk(), i + MIN_REWARD_AGE);
        }

        println!("Added {} nodes", nodes.len());

        // start timer
        let now = std::time::Instant::now();

        // calc
        let rewards = distribute_rewards(full_amount, nodes);

        // stop timer
        let duration = now.elapsed();

        println!();
        println!("Elapsed: {:?} ms", duration.as_millis());
        println!();

        let mut total = 0;
        let rewards = rewards.values().sorted();
        for amount in rewards {
            println!("{:?}", amount.as_nano());
            total += amount.as_nano();
        }

        println!();

        println!("Total rewards: {:?}", total);
    }

    fn get_random_pk() -> PublicKey {
        PublicKey::from(bls::SecretKey::random().public_key())
    }

    #[test]
    fn first_reward_is_32bn_nanos() {
        let age = 5;
        let prefix_len = 1;
        let reward = RewardCalc::reward_from(age, prefix_len);
        assert!(reward == Token::from_nano(32_000_000_000));
    }

    #[test]
    fn min_reward_payable_up_to_at_least_2000bn_nodes() {
        let age = 5;
        let prefix_len = 34;
        let reward = RewardCalc::reward_from(age, prefix_len);
        assert!(reward >= Token::from_nano(1));
    }
}
