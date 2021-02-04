// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Age;
use sn_data_types::Token;
use sn_routing::Prefix;

/// Calculation of reward for nodes.
pub struct RewardCalc {
    prefix: Prefix,
}

#[allow(unused)]
impl RewardCalc {
    /// Ctor
    pub fn new(prefix: Prefix) -> RewardCalc {
        Self { prefix }
    }

    /// Calculates the reward for a node
    /// when it has reached a certain age.
    pub async fn reward(&self, age: Age) -> Token {
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
    use super::*;
    use crate::Result;

    #[test]
    fn first_reward_is_32bn_nanos() -> Result<()> {
        let age = 5;
        let prefix_len = 1;
        let reward = RewardCalc::reward_from(age, prefix_len);
        assert!(reward == Token::from_nano(32_000_000_000));
        Ok(())
    }

    #[test]
    fn min_reward_payable_up_to_at_least_2000bn_nodes() -> Result<()> {
        let age = 5;
        let prefix_len = 34;
        let reward = RewardCalc::reward_from(age, prefix_len);
        assert!(reward >= Token::from_nano(1));
        Ok(())
    }
}
