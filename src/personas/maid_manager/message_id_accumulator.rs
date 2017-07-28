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

use lru_time_cache::LruCache;
use routing::XorName;
use std::collections::BTreeSet;
use std::time::Duration;

pub struct MessageIdAccumulator<K> {
    quorum: usize,
    map: LruCache<K, BTreeSet<XorName>>,
}

impl<K> MessageIdAccumulator<K>
where
    K: Clone + Ord,
{
    pub fn new(quorum: usize, duration: Duration) -> Self {
        MessageIdAccumulator {
            quorum: quorum,
            map: LruCache::with_expiry_duration(duration),
        }
    }

    pub fn add(&mut self, key: K, src_name: XorName) -> Option<K> {
        let done = {
            let src_list = self.map.entry(key.clone()).or_insert_with(Default::default);
            let _ = src_list.insert(src_name);
            src_list.len() >= self.quorum
        };

        if done {
            let _ = self.map.remove(&key);
            Some(key)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use routing::XorName;

    #[test]
    fn smoke() {
        let mut accumulator = MessageIdAccumulator::new(5, Duration::from_secs(10));
        let msg_id = 0;
        let duplicate_sender = XorName(rand::random());
        assert_eq!(accumulator.add(msg_id, XorName(rand::random())), None);
        assert_eq!(accumulator.add(msg_id, duplicate_sender), None);
        assert_eq!(accumulator.add(msg_id, XorName(rand::random())), None);
        assert_eq!(accumulator.add(msg_id, XorName(rand::random())), None);
        assert_eq!(accumulator.add(msg_id, duplicate_sender), None);
        assert_eq!(
            accumulator.add(msg_id, XorName(rand::random())),
            Some(msg_id)
        );
    }
}
