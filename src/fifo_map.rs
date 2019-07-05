// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A fixed-capacity hash map. When the capacity is reached, insertion causes the oldest (least
//! recently inserted) element to be evicted.
//! Note this is similar to a LRU cache, but it doesn't refresh elements on access.

use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct FifoMap<K, V>
where
    K: Eq + Hash,
{
    map: LinkedHashMap<K, V>,
    capacity: usize,
}

impl<K, V> FifoMap<K, V>
where
    K: Eq + Hash,
{
    pub fn new(capacity: usize) -> Self {
        Self {
            map: LinkedHashMap::new(),
            capacity,
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let old_val = self.map.insert(key, value);

        if self.map.len() > self.capacity {
            let _ = self.map.pop_front();
        }

        old_val
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
}

impl<K, V> Debug for FifoMap<K, V>
where
    K: Debug + Eq + Hash,
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_map().entries(self.map.iter().rev()).finish()
    }
}
