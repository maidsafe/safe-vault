// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeMap;

use dashmap::DashMap;
use sn_data_types::{CreditAgreementProof, CreditId, PublicKey, SectionElders, Token};
use sn_routing::XorName;

///
#[derive(Clone, Debug)]
pub struct SectionWallet {
    ///
    members: SectionElders,
    ///
    replicas: SectionElders,
    ///
    payments: DashMap<CreditId, CreditAgreementProof>,
}

impl SectionWallet {
    pub fn new(
        members: SectionElders,
        replicas: SectionElders,
        payments: BTreeMap<CreditId, CreditAgreementProof>,
    ) -> Self {
        Self {
            members,
            replicas,
            payments: payments.into_iter().collect(),
        }
    }

    pub fn add_payment(&self, credit: CreditAgreementProof) {
        // todo: validate
        let _ = self.payments.insert(*credit.id(), credit);
    }

    pub fn balance(&self) -> Token {
        Token::from_nano(self.payments.iter().map(|c| (*c).amount().as_nano()).sum())
    }

    pub fn key(&self) -> bls::PublicKey {
        self.members.key_set.public_key()
    }

    pub fn name(&self) -> XorName {
        PublicKey::Bls(self.key()).into()
    }

    pub fn owner_address(&self) -> XorName {
        self.members.prefix.name()
    }

    pub fn replicas_address(&self) -> XorName {
        self.replicas.prefix.name()
    }
}
