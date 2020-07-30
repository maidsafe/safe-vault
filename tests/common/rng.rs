// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use rand::{CryptoRng, Error, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{env, thread};

const SEED_ENV_NAME: &str = "SEED";

pub struct TestRng(ChaChaRng);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for TestRng {}

pub fn from_rng<R: RngCore>(rng: &mut R) -> TestRng {
    TestRng(ChaChaRng::from_seed(rng.gen()))
}

pub fn from_seed(seed: u64) -> TestRng {
    TestRng(ChaChaRng::seed_from_u64(seed))
}

pub fn get_seed() -> u64 {
    if let Ok(value) = env::var(SEED_ENV_NAME) {
        value
            .parse()
            .expect("Failed to parse seed - must be valid u64 value")
    } else {
        rand::thread_rng().gen()
    }
}

/// Helper struct that prints the current seed on panic.
pub struct SeedPrinter {
    seed: u64,
}

impl SeedPrinter {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }
}

impl Drop for SeedPrinter {
    fn drop(&mut self) {
        if thread::panicking() {
            print_seed(self.seed);
        }
    }
}

fn print_seed(seed: u64) {
    let msg = format!("{}", seed);
    let border = (0..msg.len()).map(|_| "=").collect::<String>();
    println!("\n{}\n{}\n{}\n", border, msg, border);
}
