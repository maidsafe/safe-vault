// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::transfers::replica_manager::ReplicaManager;
use crate::{
    capacity::RateLimit,
    node::keys::NodeSigningKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{NodeOperation, PaymentDuty},
    utils,
};
use futures::lock::Mutex;
use sn_data_types::{
    Cmd, CmdError, ElderDuties, Error, Message, MsgEnvelope, PublicKey, Result, TransferError,
};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// An Elder in a KeySection is responsible for
/// data payment, and will receive write
/// requests from clients.
/// At Payments, a local request to Transfers module
/// will clear the payment, and thereafter the node forwards
/// the actual write request (without payment info) to a DataSection,
/// which would be a section closest to the data
/// (where it is then handled by Elders with Metadata duties).
pub struct Payments {
    replica: Arc<Mutex<ReplicaManager>>,
    rate_limit: RateLimit,
    wrapping: ElderMsgWrapping,
}

impl Payments {
    pub fn new(
        keys: NodeSigningKeys,
        rate_limit: RateLimit,
        replica: Arc<Mutex<ReplicaManager>>,
    ) -> Self {
        let wrapping = ElderMsgWrapping::new(keys, ElderDuties::Payment);
        Self {
            replica,
            rate_limit,
            wrapping,
        }
    }

    // The code in this method is a bit messy, needs to be cleaned up.
    pub async fn process_payment_duty(&mut self, duty: &PaymentDuty) -> Option<NodeOperation> {
        use PaymentDuty::*;
        match duty {
            ProcessPayment(msg) => self.process_payment(msg).await,
        }
    }

    async fn process_payment(&mut self, msg: &MsgEnvelope) -> Option<NodeOperation> {
        let (payment, num_bytes) = match &msg.message {
            Message::Cmd {
                cmd: Cmd::Data { payment, cmd },
                ..
            } => (payment, utils::serialise(cmd).len() as u64),
            _ => return None,
        };

        // Make sure we are actually at the correct replicas,
        // before executing the debit.
        // (We could also add a method that executes both
        // debit + credit atomically, but this is much simpler).
        let recipient_is_not_section = match self.section_wallet_id().await {
            Ok(section) => payment.to() != section,
            _ => true, // this would be strange, is it even possible?
        };

        use TransferError::*;
        if recipient_is_not_section {
            return self
                .wrapping
                .error(
                    CmdError::Transfer(TransferRegistration(Error::NoSuchRecipient)),
                    msg.id(),
                    &msg.origin.address(),
                )
                .await
                .map(|c| c.into());
        }
        let registration = self.replica.lock().await.register(&payment);
        let result = match registration {
            Ok(_) => match self.replica.lock().await.receive_propagated(&payment) {
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            },
            Err(error) => Err(error), // not using TransferPropagation error, since that is for NodeCmds, so wouldn't be returned to client.
        };
        let result = match result {
            Ok(_) => {
                // Paying too little will see the amount be forfeited.
                // This is because it is easy to know the cost by
                // serializing the write and counting the num bytes,
                // so you are forced to do the job properly.
                // This prevents spam of the network.
                let total_cost = self.rate_limit.from(num_bytes).await?;
                if total_cost > payment.amount() {
                    // todo, better error, like `TooLowPayment`
                    return self
                        .wrapping
                        .error(
                            CmdError::Transfer(TransferRegistration(Error::InsufficientBalance)),
                            msg.id(),
                            &msg.origin.address(),
                        )
                        .await
                        .map(|c| c.into());
                }
                // consider having the section actor be
                // informed of this transfer as well..
                self.wrapping.forward(msg).await
            }
            Err(error) => {
                self.wrapping
                    .error(
                        CmdError::Transfer(TransferRegistration(error)),
                        msg.id(),
                        &msg.origin.address(),
                    )
                    .await
            }
        };
        result.map(|c| c.into())
    }

    async fn section_wallet_id(&self) -> Result<PublicKey> {
        match self.replica.lock().await.replicas_pk_set() {
            Some(keys) => Ok(PublicKey::Bls(keys.public_key())),
            None => Err(Error::NoSuchKey),
        }
    }
}

impl Display for Payments {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Payments")
    }
}
