// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// Mock version of Quic-P2P
#[cfg(feature = "mock")]
#[allow(unused)] // TODO: remove this [allow(unused)]
pub(crate) mod mock_quic_p2p;

#[cfg(not(feature = "mock"))]
pub struct Network;

#[cfg(not(feature = "mock"))]
impl Network {
    pub fn new<R: rand::Rng>(_: &mut R) -> Self {
        Network
    }
}

#[cfg(feature = "mock")]
pub use self::mock_quic_p2p::Network;
