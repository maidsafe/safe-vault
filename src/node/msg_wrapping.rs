// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::keys::NodeSigningKeys, node::node_ops::NodeMessagingDuty};
use log::info;
use sn_data_types::{
    Address, AdultDuties, CmdError, Duty, ElderDuties, Message, MessageId, MsgEnvelope, MsgSender,
    NodeDuties, Signature,
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

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Option<NodeMessagingDuty> {
        self.inner.send_to_section(message, as_node).await
    }

    // pub async fn send_to_node(&self, message: Message) -> Option<NodeMessagingDuty> {
    //     self.inner.send_to_node(message).await
    // }
}

impl AdultMsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: AdultDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Adult(duty));
        Self { inner }
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Option<NodeMessagingDuty> {
        self.inner.send_to_section(message, as_node).await
    }

    pub async fn send_to_node(&self, message: Message) -> Option<NodeMessagingDuty> {
        self.inner.send_to_node(message).await
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

    pub async fn forward(&self, msg: &MsgEnvelope) -> Option<NodeMessagingDuty> {
        let msg = self.inner.set_proxy(&msg).await?;
        Some(NodeMessagingDuty::SendToSection { msg, as_node: true })
    }

    pub async fn send_to_client(&self, message: Message) -> Option<NodeMessagingDuty> {
        self.inner.send_to_client(message).await
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Option<NodeMessagingDuty> {
        self.inner.send_to_section(message, as_node).await
    }

    pub async fn send_to_node(&self, message: Message) -> Option<NodeMessagingDuty> {
        self.inner.send_to_node(message).await
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

    pub async fn send_to_client(&self, message: Message) -> Option<NodeMessagingDuty> {
        let origin = self.sign(&message).await?;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Some(NodeMessagingDuty::SendToClient(msg))
    }

    pub async fn send_to_node(&self, message: Message) -> Option<NodeMessagingDuty> {
        let origin = self.sign(&message).await?;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Some(NodeMessagingDuty::SendToNode(msg))
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Option<NodeMessagingDuty> {
        let origin = self.sign(&message).await?;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Some(NodeMessagingDuty::SendToSection { msg, as_node })
    }

    pub async fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Option<NodeMessagingDuty> {
        let msg = self.set_proxy(&msg).await?;
        Some(NodeMessagingDuty::SendToAdults { targets, msg })
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<NodeMessagingDuty> {
        info!("Error {:?}", error);
        self.send_to_section(
            Message::CmdError {
                id: MessageId::new(),
                error,
                correlation_id: msg_id,
                cmd_origin: origin.clone(),
            },
            true,
        )
        .await
    }

    async fn sign<T: Serialize>(&self, data: &T) -> Option<MsgSender> {
        let sender = match self.duty {
            Duty::Adult(duty) => {
                let (key, sig) = self.ed_key_sig(data).await?;
                MsgSender::adult(key, duty, sig).ok()?
            }
            Duty::Elder(duty) => {
                let key = self.keys.elder_key().await?;
                if let Signature::BlsShare(sig) = self.keys.sign_as_elder(data).await? {
                    MsgSender::elder(key, duty, sig.share).ok()?
                } else {
                    return None;
                }
            }
            Duty::Node(_) => {
                let (key, sig) = self.ed_key_sig(data).await?;
                MsgSender::any_node(key, self.duty, sig).ok()?
            }
        };

        Some(sender)
    }

    async fn ed_key_sig<T: Serialize>(
        &self,
        data: &T,
    ) -> Option<(ed25519_dalek::PublicKey, ed25519_dalek::Signature)> {
        let key = self.keys.node_id().await;
        let sig = match self.keys.sign_as_node(data).await {
            Signature::Ed25519(key) => key,
            _ => return None,
        };
        Some((key, sig))
    }

    async fn set_proxy(&self, msg: &MsgEnvelope) -> Option<MsgEnvelope> {
        // origin signs the message, while proxies sign the envelope
        let mut msg = msg.clone();
        msg.add_proxy(self.sign(&msg).await?);

        Some(msg)
    }
}
