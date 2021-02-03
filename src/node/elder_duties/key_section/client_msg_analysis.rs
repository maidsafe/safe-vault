// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::node_ops::{
    MetadataDuty, NodeMessagingDuty, NodeOperation, TransferCmd, TransferDuty,
};
use crate::ElderState;
use crate::{Error, Result};
use log::{info, warn};
use sn_messaging::client::{
    Cmd, CmdError, Error as MessageError, Message, MessageId, MsgEnvelope, Query,
};

// NB: Just as with the msg_analysis.rs,
// this approach is not entirely good, so will need to be improved.

/// Evaluates msgs sent directly from a client,
/// i.e. not remote msgs from the network.
pub struct ClientMsgAnalysis {
    elder_state: ElderState,
}

impl ClientMsgAnalysis {
    pub fn new(elder_state: ElderState) -> Self {
        Self { elder_state }
    }

    pub async fn evaluate(&self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        info!("Evaluation of client msg envelope: {:?}", msg);

        // Check if the msg is a New Data Write and verify owners
        if let Message::Cmd {
            cmd: Cmd::Data { cmd, .. },
            ..
        } = &msg.message
        {
            // If owner is `Some`, then the Cmd is going to be newly created Data.
            if let Some(owner) = cmd.owner() {
                let public_key = msg.origin.id().public_key();
                if owner != public_key {
                    return Ok(NodeMessagingDuty::SendToClient(MsgEnvelope {
                        message: Message::CmdError {
                            error: CmdError::Data(MessageError::InvalidOwners(public_key)),
                            id: MessageId::new(),
                            correlation_id: msg.id(),
                            cmd_origin: msg.origin.address(),
                        },
                        origin: msg.clone().origin,
                        proxies: vec![],
                    })
                    .into());
                }
            }
        }

        match self.try_data(msg).await? {
            NodeOperation::NoOp => (),
            op => return Ok(op),
        };
        match self.try_data_payment(msg).await? {
            NodeOperation::NoOp => (),
            op => return Ok(op),
        };
        match self.try_transfers(msg).await? {
            NodeOperation::NoOp => (),
            op => return Ok(op),
        };

        Err(Error::Logic(format!(
            "Could not evaluate Client Msg w/id {:?}",
            msg.id()
        )))
    }

    /// We do not accumulate these request, they are executed
    /// at once and sent on to Metadata section. They don't accumulate either,
    /// just send back the response, for the client to accumulate.
    async fn try_data(&self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        let is_data_read = || {
            matches!(msg.message, Message::Query {
                query: Query::Data { .. },
                ..
            })
        };
        let shall_process = || is_data_read() && msg.origin.is_client();

        if !shall_process() || !self.is_dst_for(msg).await {
            return Ok(NodeOperation::NoOp);
        }

        Ok(MetadataDuty::ProcessRead(msg.clone()).into()) // TODO: Fix these for type safety
    }

    /// We do not accumulate these request, they are executed
    /// at once (i.e. payment carried out) and sent on to
    /// Metadata section. (They however, will accumulate those msgs.)
    /// The reason for this is that the payment request is already signed
    /// by the client and validated by its replicas,
    /// so there is no reason to accumulate it here.
    async fn try_data_payment(&self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        let is_data_write = || {
            matches!(msg.message, Message::Cmd {
                cmd: Cmd::Data { .. },
                ..
            })
        };

        let shall_process = || is_data_write() && msg.origin.is_client();

        if !shall_process() || !self.is_dst_for(msg).await {
            return Ok(NodeOperation::NoOp);
        }

        Ok(TransferDuty::ProcessCmd {
            cmd: TransferCmd::ProcessPayment(msg.clone()),
            msg_id: msg.id(),
            origin: msg.origin.address(),
        }
        .into())
    }

    async fn try_transfers(&self, msg: &MsgEnvelope) -> Result<NodeOperation> {
        let duty = match &msg.message {
            Message::Cmd {
                cmd: Cmd::Transfer(cmd),
                ..
            } => {
                if !msg.origin.is_client() || !self.is_dst_for(msg).await {
                    return Ok(NodeOperation::NoOp);
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
                if !msg.origin.is_client() || !self.is_dst_for(msg).await {
                    return Ok(NodeOperation::NoOp);
                }
                TransferDuty::ProcessQuery {
                    query: query.clone().into(),
                    msg_id: msg.id(),
                    origin: msg.origin.address(),
                }
            }
            _ => return Ok(NodeOperation::NoOp),
        };
        Ok(duty.into())
    }

    async fn is_dst_for(&self, msg: &MsgEnvelope) -> bool {
        if let Ok(dst) = msg.destination() {
            self.elder_state.prefix().matches(&dst.xorname())
        } else {
            warn!("Invalid dst of msg: {:?}", msg);
            false
        }
    }
}
