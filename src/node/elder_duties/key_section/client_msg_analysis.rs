// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::node_ops::{NodeOperation, PaymentDuty, TransferDuty};
use crate::Network;
use log::info;
use sn_data_types::{Cmd, Message, MsgEnvelope, MsgSender, Query};

/// Evaluates msgs sent directly from a client,
/// i.e. not remote msgs from the network.
pub struct ClientMsgAnalysis {
    routing: Network,
}

impl ClientMsgAnalysis {
    pub fn new(routing: Network) -> Self {
        Self { routing }
    }

    pub fn evaluate(&mut self, msg: &MsgEnvelope) -> Option<NodeOperation> {
        info!("Evaluation of client msg envelope: {:?}", msg);
        if let Some(duty) = self.try_data_payment(msg) {
            Some(duty.into())
        } else if let Some(duty) = self.try_transfers(msg) {
            Some(duty.into())
        } else {
            None
        }
    }

    /// We do not accumulate these request, they are executed
    /// at once (i.e. payment carried out) and sent on to
    /// Metadata section. (They however, will accumulate those msgs.)
    /// The reason for this is that the payment request is already signed
    /// by the client and validated by its replicas,
    /// so there is no reason to accumulate it here.
    fn try_data_payment(&self, msg: &MsgEnvelope) -> Option<PaymentDuty> {
        let from_client = || matches!(msg.origin, MsgSender::Client { .. });

        let is_data_write = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };

        let shall_process =
            |msg| is_data_write() && from_client() && self.is_dst_for(msg) && self.is_elder();

        if !shall_process(msg) {
            return None;
        }

        Some(PaymentDuty::ProcessPayment(msg.clone())) // TODO: Fix these for type safety
    }

    fn try_transfers(&self, msg: &MsgEnvelope) -> Option<TransferDuty> {
        let from_client = || matches!(msg.origin, MsgSender::Client { .. });

        let shall_process = |msg| from_client() && self.is_dst_for(msg) && self.is_elder();

        let duty = match &msg.message {
            Message::Cmd {
                cmd: Cmd::Transfer(cmd),
                ..
            } => {
                if !shall_process(msg) {
                    return None;
                }
                TransferDuty::ProcessCmd {
                    cmd: cmd.clone().into(),
                    msg_id: msg.id(),
                    origin: msg.origin.address(),
                }
            }
            Message::Query {
                query: Query::Transfer(query),
                ..
            } => {
                if !shall_process(msg) {
                    return None;
                }
                TransferDuty::ProcessQuery {
                    query: query.clone().into(),
                    msg_id: msg.id(),
                    origin: msg.origin.address(),
                }
            }
            _ => return None,
        };
        Some(duty)
    }

    fn is_dst_for(&self, msg: &MsgEnvelope) -> bool {
        self.routing.matches_our_prefix(msg.destination().xorname())
    }

    fn is_elder(&self) -> bool {
        self.routing.is_elder()
    }
}
