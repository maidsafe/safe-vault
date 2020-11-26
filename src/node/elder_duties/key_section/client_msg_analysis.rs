// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::node_ops::{MetadataDuty, NodeOperation, PaymentDuty, TransferDuty};
use crate::Network;
use crate::{Error, Outcome, TernaryResult};
use log::{info, warn};
use sn_data_types::{Cmd, Message, MsgEnvelope, Query};

// NB: Just as with the msg_analysis.rs,
// this approach is not entirely good, so will need to be improved.

/// Evaluates msgs sent directly from a client,
/// i.e. not remote msgs from the network.
pub struct ClientMsgAnalysis {
    routing: Network,
}

impl ClientMsgAnalysis {
    pub fn new(routing: Network) -> Self {
        Self { routing }
    }

    pub async fn evaluate(&mut self, msg: &MsgEnvelope) -> Outcome<NodeOperation> {
        info!("Evaluation of client msg envelope: {:?}", msg);
        let op = if let Ok(Some(duty)) = self.try_data(msg).await {
            duty.into()
        } else if let Ok(Some(duty)) = self.try_data_payment(msg).await {
            duty.into()
        } else if let Ok(Some(duty)) = self.try_transfers(msg).await {
            duty.into()
        } else {
            return Outcome::error(Error::Logic);
        };
        Outcome::oki(op)
    }

    /// We do not accumulate these request, they are executed
    /// at once and sent on to Metadata section. They don't accumulate either,
    /// just send back the response, for the client to accumulate.
    async fn try_data(&self, msg: &MsgEnvelope) -> Outcome<MetadataDuty> {
        let is_data_read = || {
            matches!(msg.message, Message::Query {
                query: Query::Data { .. },
                ..
            })
        };
        let shall_process = || is_data_read() && msg.origin.is_client();

        if !shall_process() || !self.is_dst_for(msg).await || !self.is_elder().await {
            return Ok(None);
        }

        Outcome::oki(MetadataDuty::ProcessRead(msg.clone())) // TODO: Fix these for type safety
    }

    /// We do not accumulate these request, they are executed
    /// at once (i.e. payment carried out) and sent on to
    /// Metadata section. (They however, will accumulate those msgs.)
    /// The reason for this is that the payment request is already signed
    /// by the client and validated by its replicas,
    /// so there is no reason to accumulate it here.
    async fn try_data_payment(&self, msg: &MsgEnvelope) -> Outcome<PaymentDuty> {
        let is_data_write = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };

        let shall_process = || is_data_write() && msg.origin.is_client();

        if !shall_process() || !self.is_dst_for(msg).await || !self.is_elder().await {
            return Ok(None);
        }

        Outcome::oki(PaymentDuty::ProcessPayment(msg.clone())) // TODO: Fix these for type safety
    }

    async fn try_transfers(&self, msg: &MsgEnvelope) -> Outcome<TransferDuty> {
        let duty = match &msg.message {
            Message::Cmd {
                cmd: Cmd::Transfer(cmd),
                ..
            } => {
                if !msg.origin.is_client() || !self.is_dst_for(msg).await || !self.is_elder().await
                {
                    return Ok(None);
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
                if !msg.origin.is_client() || !self.is_dst_for(msg).await || !self.is_elder().await
                {
                    return Ok(None);
                }
                TransferDuty::ProcessQuery {
                    query: query.clone().into(),
                    msg_id: msg.id(),
                    origin: msg.origin.address(),
                }
            }
            _ => return Ok(None),
        };
        Outcome::oki(duty)
    }

    async fn is_dst_for(&self, msg: &MsgEnvelope) -> bool {
        if let Ok(dst) = msg.destination() {
            self.routing.matches_our_prefix(dst.xorname()).await
        } else {
            warn!("Invalid dst of msg: {:?}", msg);
            false
        }
    }

    async fn is_elder(&self) -> bool {
        self.routing.is_elder().await
    }
}
