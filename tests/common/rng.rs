// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use rand::{self, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::env;
use unwrap::unwrap;

pub type TestRng = ChaChaRng;

// Create new random number generator suitable for tests. To provide repeatable results, the seed
// can be overriden using the "SEED" env variable. If this variable is not provided, a random one
// is used (to support soak testing). The current seed is printed to stdout.
pub fn new() -> TestRng {
    let seed = if let Ok(seed) = env::var("SEED") {
        unwrap!(seed.parse(), "SEED must contain a valid u64 value")
    } else {
        rand::thread_rng().gen()
    };

    println!("RNG seed: {}", seed);

    TestRng::seed_from_u64(seed)
}

pub fn from_rng(rng: &mut TestRng) -> TestRng {
    unwrap!(TestRng::from_rng(rng))
}
