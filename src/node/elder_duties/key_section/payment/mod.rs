// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod calc;

use super::transfers::replica_manager::ReplicaManager;
use crate::{
    node::economy::MintingMetrics,
    node::keys::NodeKeys,
    node::msg_wrapping::ElderMsgWrapping,
    node::node_ops::{NodeOperation, PaymentDuty, RewardDuty},
    utils,
};
use calc::Economy;
use routing::Node as Routing;
use safe_nd::{
    Address, Cmd, CmdError, ElderDuties, Error, Message, MessageId, Money, MsgEnvelope,
    PaymentQuery, PublicKey, QueryResponse, Result, TransferError,
};
use std::{
    cell::{RefCell, RefMut},
    fmt::{self, Display, Formatter},
    rc::Rc,
};

pub struct Payments {
    keys: NodeKeys,
    replica: Rc<RefCell<ReplicaManager>>,
    wrapping: ElderMsgWrapping,
    calc: Economy,
    store_cost: Money,
    previous_counter: u64,
    counter: u64,
}

/// An Elder in S(R) is responsible for
/// data payment, and will receive write
/// requests from clients.
/// At Payments, a local request to Transfers module
/// will clear the payment, and thereafter the node forwards
/// the actual write request (without payment info) to data section (S(D), i.e. elders with Metadata duties).
impl Payments {
    pub fn new(
        keys: NodeKeys,
        routing: Rc<RefCell<Routing>>,
        replica: Rc<RefCell<ReplicaManager>>,
    ) -> Self {
        let wrapping = ElderMsgWrapping::new(keys.clone(), ElderDuties::Payment);
        let calc = Economy::new(keys.public_key(), routing, replica.clone());
        Self {
            keys,
            replica,
            wrapping,
            calc,
            store_cost: Money::zero(),
            previous_counter: 1,
            counter: 1,
        }
    }

    pub fn update_costs(&mut self) -> Option<NodeOperation> {
        let indicator = self.calc.update_indicator()?;
        let cost_base = indicator.period_cost_base.as_nano();
        let load = self.counter as f64 / self.previous_counter as f64;
        let store_cost = load * cost_base as f64;
        self.store_cost = Money::from_nano(store_cost as u64);
        self.previous_counter = self.counter;
        self.counter = 1;

        Some(
            RewardDuty::UpdateRewards(MintingMetrics {
                key: indicator.period_key,
                store_cost: self.store_cost,
                velocity: indicator.minting_velocity,
            })
            .into(),
        )
    }

    // The code in this method is a bit messy, needs to be cleaned up.
    pub fn process(&mut self, duty: &PaymentDuty) -> Option<NodeOperation> {
        use PaymentDuty::*;
        match duty {
            ProcessPayment(msg) => self.process_payment(msg),
            ProcessQuery {
                query,
                msg_id,
                origin,
            } => match query {
                PaymentQuery::GetStoreCost(_) => self.store_cost(msg_id, origin),
            },
        }
    }

    fn store_cost(&self, msg_id: &MessageId, origin: &Address) -> Option<NodeOperation> {
        let public_key = PublicKey::Bls(self.replica.borrow().replicas_pk_set()?.public_key());
        Some(
            self.wrapping
                .send(Message::QueryResponse {
                    response: QueryResponse::GetStoreCost(Ok((public_key, self.store_cost))),
                    id: MessageId::new(),
                    correlation_id: *msg_id,
                    query_origin: origin.clone(),
                })?
                .into(),
        )
    }

    fn process_payment(&mut self, msg: &MsgEnvelope) -> Option<NodeOperation> {
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
        let recipient_is_not_section = match self.section_account_id() {
            Ok(section) => payment.to() != section,
            _ => true, // this would be strange, is it even possible?
        };

        use TransferError::*;
        if recipient_is_not_section {
            let error = CmdError::Transfer(TransferRegistration(Error::NoSuchRecipient));
            let result = self.wrapping.error(error, msg.id(), &msg.origin.address());
            return result.map(|c| c.into());
        }
        let registration = self.replica_mut().register(&payment);
        let result = match registration {
            Ok(_) => match self.replica_mut().receive_propagated(&payment) {
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            },
            Err(error) => Err(error), // not using TransferPropagation error, since that is for NodeCmds, so wouldn't be returned to client.
        };
        let result = match result {
            Ok(_) => {
                self.counter += 1;
                // Paying too little will see the amount be forfeited.
                // This is because it is easy to know the cost by querying,
                // so you are forced to do the job properly, instead of burdoning the network.
                let store_cost = Money::from_nano(num_bytes + self.store_cost.as_nano());
                if store_cost > payment.amount() {
                    let error =
                        CmdError::Transfer(TransferRegistration(Error::InsufficientBalance)); // todo, better error, like `TooLowPayment`
                    let result = self.wrapping.error(error, msg.id(), &msg.origin.address());
                    return result.map(|c| c.into());
                }
                self.wrapping.forward(msg)
            }
            Err(error) => self.wrapping.error(
                CmdError::Transfer(TransferRegistration(error)),
                msg.id(),
                &msg.origin.address(),
            ),
        };
        result.map(|c| c.into())
    }

    fn section_account_id(&self) -> Result<PublicKey> {
        match self.replica.borrow().replicas_pk_set() {
            Some(keys) => Ok(PublicKey::Bls(keys.public_key())),
            None => Err(Error::NoSuchKey),
        }
    }

    fn replica_mut(&mut self) -> RefMut<ReplicaManager> {
        self.replica.borrow_mut()
    }
}

impl Display for Payments {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.keys.public_key())
    }
}
