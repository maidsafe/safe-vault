// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "mock_parsec")]
use rand::Rng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use unwrap::unwrap;

pub type TestRng = ChaChaRng;

// Create new random number generator suitable for tests, from the given generator from routing.
pub fn new<R: RngCore>(rng: R) -> TestRng {
    unwrap!(TestRng::from_rng(rng))
}

#[cfg(feature = "mock_parsec")]
pub fn new_rng<R: Rng>(rng: &mut R) -> TestRng {
    TestRng::from_seed(rng.gen())
}
