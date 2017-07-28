// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::ACCUMULATOR_TIMEOUT_SECS;
use super::data::{Data, MutableDataId};
use QUORUM;
use accumulator::Accumulator;
use routing::{MutableData, Value, XorName};
use std::time::Duration;
use utils::{self, HashMap, Instant, SecureHash};

/// The timeout after which cached mutable data entries expire.
const ENTRY_CACHE_TIMEOUT_SECS: u64 = 60;

pub struct MutableDataCache {
    shell_accumulator: Accumulator<ShellKey, XorName>,
    entry_accumulator: Accumulator<EntryKey, XorName>,
    entry_cache: HashMap<MutableDataId, EntryCache>,
}

impl MutableDataCache {
    pub fn new() -> Self {
        let duration = Duration::from_secs(ACCUMULATOR_TIMEOUT_SECS);

        MutableDataCache {
            shell_accumulator: Accumulator::with_duration(QUORUM, duration),
            entry_accumulator: Accumulator::with_duration(QUORUM, duration),
            entry_cache: Default::default(),
        }
    }

    /// Accumulates mutable data. Returns the shell and entries that reached the
    /// accumulation quorum (if any).
    pub fn accumulate(
        &mut self,
        mut data: MutableData,
        src: XorName,
    ) -> (Option<MutableData>, HashMap<Vec<u8>, Value>) {
        let data_id = data.id();
        let entries = data.take_entries();

        let shell_key = ShellKey {
            id: data_id,
            hash: utils::secure_hash(&data),
        };

        let result_shell = if self.shell_accumulator.add(shell_key.clone(), src).is_some() {
            self.shell_accumulator.delete(&shell_key);
            Some(data)
        } else {
            None
        };

        let mut result_entries = HashMap::default();
        for (key, value) in entries {
            let entry_key = EntryKey {
                id: data_id,
                key: key,
                hash: utils::secure_hash(&value),
            };

            if self.entry_accumulator.add(entry_key.clone(), src).is_some() {
                self.entry_accumulator.delete(&entry_key);
                let _ = result_entries.insert(entry_key.key, value);
            }
        }

        (result_shell, result_entries)
    }

    /// Inserts entry into entry cache.
    pub fn insert_entry(&mut self, id: MutableDataId, key: Vec<u8>, value: Value) {
        self.remove_expired_entries();

        let _ = self.entry_cache
            .entry(id)
            .or_insert_with(HashMap::default)
            .insert(key, (value, Instant::now()));
    }

    /// Inserts multiple entries into entry cache.
    pub fn insert_entries<I>(&mut self, id: MutableDataId, entries: I)
    where
        I: IntoIterator<Item = (Vec<u8>, Value)>,
    {
        self.remove_expired_entries();

        let mut map = self.entry_cache.entry(id).or_insert_with(HashMap::default);

        for (key, value) in entries {
            let _ = map.insert(key, (value, Instant::now()));
        }
    }

    // Returns and removes all cached entries of the given mutable data.
    pub fn take_entries(&mut self, id: &MutableDataId) -> HashMap<Vec<u8>, Value> {
        let result = self.entry_cache
            .remove(id)
            .unwrap_or_else(Default::default)
            .into_iter()
            .map(|(key, (value, _))| (key, value))
            .collect();

        self.remove_expired_entries();

        result
    }

    fn remove_expired_entries(&mut self) {
        let mut remove = Vec::new();

        for (data_id, entries) in &mut self.entry_cache {
            let expired_keys: Vec<_> = entries
                .iter()
                .filter_map(|(key, &(_, instant))| if instant.elapsed().as_secs() >
                    ENTRY_CACHE_TIMEOUT_SECS
                {
                    Some(key.clone())
                } else {
                    None
                })
                .collect();

            for key in expired_keys {
                let _ = entries.remove(&key);
            }

            if entries.is_empty() {
                remove.push(*data_id);
            }
        }

        for data_id in remove {
            let _ = self.entry_cache.remove(&data_id);
        }
    }
}

#[cfg(all(test, feature = "use-mock-routing"))]
impl MutableDataCache {
    /// Clear the cache.
    pub fn clear(&mut self) {
        self.entry_cache.clear();
    }
}

type EntryCache = HashMap<Vec<u8>, (Value, Instant)>;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ShellKey {
    id: MutableDataId,
    hash: SecureHash,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct EntryKey {
    id: MutableDataId,
    key: Vec<u8>,
    hash: SecureHash,
}
