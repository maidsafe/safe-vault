// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::{PublicKey, SectionElders};
use sn_routing::XorName;

///
#[derive(Clone, Debug)]
pub struct SectionWallet {
    ///
    pub members: SectionElders,
    ///
    pub replicas: SectionElders,
}

impl SectionWallet {
    fn key(&self) -> bls::PublicKey {
        self.members.key_set.public_key()
    }

    fn name(&self) -> XorName {
        PublicKey::Bls(self.key()).into()
    }

    fn owner_address(&self) -> XorName {
        self.members.prefix.name()
    }

    fn replicas_address(&self) -> XorName {
        self.replicas.prefix.name()
    }
}
