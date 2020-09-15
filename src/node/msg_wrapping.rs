// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::keys::NodeSigningKeys, node::node_ops::NodeMessagingDuty, utils};
use log::info;
use sn_data_types::{
    Address, AdultDuties, CmdError, Duty, ElderDuties, Message, MessageId, MsgEnvelope, MsgSender,
    NodeDuties,
};
use xor_name::XorName;

use serde::Serialize;
use std::collections::BTreeSet;

/// Wrapping of msgs sent by Elders.
#[derive(Clone)]
pub struct ElderMsgWrapping {
    inner: MsgWrapping,
}

/// Wrapping of msgs sent by Adults.
#[derive(Clone)]
pub struct AdultMsgWrapping {
    inner: MsgWrapping,
}

/// Wrapping of msgs sent by any Node.
#[derive(Clone)]
pub struct NodeMsgWrapping {
    inner: MsgWrapping,
}

/// Msg wrapping simplifies
/// the signing and stamping of
/// a sender duty onto remote msgs
/// to be sent on the wire.
#[derive(Clone)]
struct MsgWrapping {
    keys: NodeSigningKeys,
    duty: Duty,
}

impl NodeMsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: NodeDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Node(duty));
        Self { inner }
    }

    pub async fn send(&self, message: Message) -> Option<NodeMessagingDuty> {
        self.inner.send(message)
    }
}

impl AdultMsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: AdultDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Adult(duty));
        Self { inner }
    }

    pub async fn send(&self, message: Message) -> Option<NodeMessagingDuty> {
        self.inner.send(message).await
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<NodeMessagingDuty> {
        self.inner.error(error, msg_id, origin).await
    }
}

impl ElderMsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: ElderDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Elder(duty));
        Self { inner }
    }

    pub fn forward(&self, msg: &MsgEnvelope) -> Option<NodeMessagingDuty> {
        let msg = self.inner.set_proxy(&msg).await;
        Some(NodeMessagingDuty::SendToSection(msg))
    }

    pub async fn send(&self, message: Message) -> Option<NodeMessagingDuty> {
        self.inner.send(message).await
    }

    pub async fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Option<NodeMessagingDuty> {
        self.inner.send_to_adults(targets, msg).await
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<NodeMessagingDuty> {
        self.inner.error(error, msg_id, origin).await
    }
}

impl MsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: Duty) -> Self {
        Self { keys, duty }
    }

    pub async fn send(&self, message: Message) -> Option<NodeMessagingDuty> {
        let origin = self.sign(&message).await;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Some(NodeMessagingDuty::SendToSection(msg))
    }

    pub async fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Option<NodeMessagingDuty> {
        let msg = self.set_proxy(&msg).await;
        Some(MessagingDuty::SendToAdults { targets, msg })
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<NodeMessagingDuty> {
        info!("Error {:?}", error);
        self.send(Message::CmdError {
            id: MessageId::new(),
            error,
            correlation_id: msg_id,
            cmd_origin: origin.clone(),
        })
        .await
    }

    async fn sign<T: Serialize>(&self, data: &T) -> MsgSender {
        MsgSender::Node {
            duty: self.duty,
            proof: self.keys.produce_proof(&utils::serialise(data)).await,
        }
    }

    async fn set_proxy(&self, msg: &MsgEnvelope) -> MsgEnvelope {
        // origin signs the message, while proxies sign the envelope
        let mut msg = msg.clone();
        msg.add_proxy(self.sign(&msg).await);

        msg
    }
}
