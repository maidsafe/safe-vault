// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node::node_ops::{NetworkDuties, NetworkDuty, NodeMessagingDuty, OutgoingMsg},
    Result,
};
use sn_data_types::{PublicKey, SectionElders, Token};
use sn_messaging::{
    client::{Message, NodeCmd, NodeQuery, NodeSystemCmd, NodeSystemQuery},
    Aggregation, DstLocation, MessageId,
};
use xor_name::XorName;

///
pub struct ChurningWallet {
    balance: Token,
    churn: Churn,
}

///
#[derive(Clone, Debug)]
pub enum Churn {
    /// Contains next section wallet.
    Regular(SectionWallet),
    ///
    Split {
        ///
        child_1: SectionWallet,
        ///
        child_2: SectionWallet,
    },
}

///
#[derive(Clone, Debug)]
pub struct SectionWallet {
    ///
    elders: SectionElders,
    ///
    replicas: SectionElders,
}

impl SectionWallet {
    fn key(&self) -> bls::PublicKey {
        self.elders.key_set.public_key()
    }

    fn name(&self) -> XorName {
        PublicKey::Bls(self.key()).into()
    }

    fn owner_address(&self) -> XorName {
        self.elders.prefix.name()
    }

    fn replicas_address(&self) -> XorName {
        self.replicas.prefix.name()
    }
}

impl ChurningWallet {
    pub fn new(balance: Token, churn: Churn) -> Self {
        Self { balance, churn }
    }

    /// Move Wallet
    pub async fn move_wallet(&mut self) -> Result<NetworkDuties> {
        match self.churn.clone() {
            Churn::Regular(next) => self.create_wallet(self.balance, next),
            Churn::Split {
                child_1,
                child_2,
            } => {
                // Split the tokens of current actor.
                let half_balance = self.balance.as_nano() / 2;
                let remainder = self.balance.as_nano() % 2;

                // create two transfers; one to each sibling wallet
                let t1_amount = Token::from_nano(half_balance + remainder);
                let t2_amount = Token::from_nano(half_balance);

                let mut ops = vec![];

                // Determine which transfer is first
                // (deterministic order is important for reaching consensus)
                if child_1.key() > child_2.key() {
                    ops.extend(self.create_wallet(t1_amount, child_1)?);
                    ops.extend(self.create_wallet(t2_amount, child_2)?);
                    Ok(ops)
                } else {
                    ops.extend(self.create_wallet(t1_amount, child_2)?);
                    ops.extend(self.create_wallet(t2_amount, child_1)?);
                    Ok(ops)
                }
            }
        }
    }

    /// Generates validation
    /// to transfer the tokens from
    /// previous actor to new actor.
    fn create_wallet(&mut self, amount: Token, new_wallet: SectionWallet) -> Result<NetworkDuties> {
        use NodeSystemCmd::CreateSectionWallet;
        let cmd = NodeCmd::System(CreateSectionWallet {
            amount,
            key: new_wallet.key(),
        });

        let mut ops = vec![];

        // send to new wallet replicas
        ops.push(NetworkDuty::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: cmd.clone(),
                id: MessageId::combine(vec![new_wallet.replicas_address(), new_wallet.name()]),
                target_section_pk: None,
            },
            section_source: true,
            dst: DstLocation::Section(new_wallet.replicas_address()),
            aggregation: Aggregation::AtDestination,
        })));

        // send to our section
        ops.push(NetworkDuty::from(NodeMessagingDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd,
                id: MessageId::combine(vec![new_wallet.owner_address(), new_wallet.name()]),
                target_section_pk: None,
            },
            section_source: true,
            dst: DstLocation::Section(new_wallet.owner_address()),
            aggregation: Aggregation::AtDestination,
        })));

        Ok(ops)
    }
}
