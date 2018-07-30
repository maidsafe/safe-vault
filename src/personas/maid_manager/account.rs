// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use routing::{AccountInfo, MessageId};
use safe_crypto::PublicSignKey;
use std::collections::BTreeSet;

/// Default available number of operations per account.
#[cfg(not(feature = "use-mock-crust"))]
pub const DEFAULT_MAX_OPS_COUNT: u64 = 1000;
/// Default available number of mutations per account.
#[cfg(feature = "use-mock-crust")]
pub const DEFAULT_MAX_OPS_COUNT: u64 = 100;

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    /// Message ids of data operations performed by this account.
    pub data_ops_msg_ids: BTreeSet<MessageId>,
    /// Number of keys operations performed by this account.
    pub keys_ops_count: u64,
    /// App authentication keys.
    pub keys: BTreeSet<PublicSignKey>,
    /// Dev option to allow clients to make unlimited mutation requests.
    disable_mutation_limit: bool,
}

impl Account {
    pub fn new(disable_mutation_limit: bool) -> Self {
        Account {
            data_ops_msg_ids: BTreeSet::new(),
            keys_ops_count: 0,
            keys: BTreeSet::new(),
            disable_mutation_limit,
        }
    }

    // TODO: Change the `AccountInfo` struct in routing.
    pub fn balance(&self) -> AccountInfo {
        let done = self.data_ops_msg_ids.len() as u64 + self.keys_ops_count;
        let available = if self.disable_mutation_limit {
            u64::max_value()
        } else {
            DEFAULT_MAX_OPS_COUNT.saturating_sub(done)
        };

        AccountInfo {
            mutations_done: done,
            mutations_available: available,
        }
    }

    pub fn has_balance(&self) -> bool {
        self.disable_mutation_limit
            || self.data_ops_msg_ids.len() as u64 + self.keys_ops_count < DEFAULT_MAX_OPS_COUNT
    }
}

#[cfg(test)]
mod tests {
    use super::{Account, DEFAULT_MAX_OPS_COUNT};
    use routing::MessageId;

    #[test]
    fn balance() {
        let mut account = Account::new(false);
        assert!(account.has_balance());

        account.keys_ops_count = DEFAULT_MAX_OPS_COUNT - 1;
        assert!(account.has_balance());

        let _ = account.data_ops_msg_ids.insert(MessageId::zero());
        assert!(!account.has_balance());

        let mut unlimited_account = Account::new(true);
        assert!(unlimited_account.has_balance());

        unlimited_account.keys_ops_count = DEFAULT_MAX_OPS_COUNT;
        assert!(unlimited_account.has_balance());
    }
}
