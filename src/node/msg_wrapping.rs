// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::keys::NodeSigningKeys, node::node_ops::NodeMessagingDuty};
use crate::{Error, Result};
use log::info;
use sn_data_types::Signature;
use sn_messaging::{
    Address, AdultDuties, CmdError, Duty, ElderDuties, Message, MessageId, MsgEnvelope, MsgSender,
    NodeDuties, TransientElderKey, TransientSectionKey,
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
    ) -> Result<NodeMessagingDuty> {
        self.inner.send_to_section(message, as_node).await
    }

    // pub async fn send_to_node(&self, message: Message) -> Result<NodeMessagingDuty> {
    //     self.inner.send_to_node(message).await
    // }
}

impl AdultMsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: AdultDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Adult(duty));
        Self { inner }
    }

    pub async fn name(&self) -> XorName {
        self.inner.keys.name().await
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Result<NodeMessagingDuty> {
        self.inner.send_to_section(message, as_node).await
    }

    pub async fn send_to_node(&self, message: Message) -> Result<NodeMessagingDuty> {
        self.inner.send_to_node(message).await
    }

    pub async fn send_to_adults(
        &self,
        message: Message,
        targets: BTreeSet<XorName>,
        duty: AdultDuties,
    ) -> Result<NodeMessagingDuty> {
        let (key, sig) = self
            .inner
            .ed_key_sig(&message.serialize()?)
            .await
            .ok_or_else(|| Error::Logic("Could not sign with Node key".to_string()))?;
        let origin = MsgSender::adult(key, duty, sig)?;
        self.inner
            .send_to_adults(targets, message, false, origin, vec![])
            .await
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Result<NodeMessagingDuty> {
        self.inner.error(error, msg_id, origin).await
    }
}

impl ElderMsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: ElderDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Elder(duty));
        Self { inner }
    }

    pub async fn forward(&self, msg: &MsgEnvelope) -> Result<NodeMessagingDuty> {
        if let Some(msg) = self.inner.set_proxy(&msg, true).await {
            Ok(NodeMessagingDuty::SendToSection {
                msg,
                as_node: false,
            })
        } else {
            Err(Error::Logic(format!(
                "{:?}: Could not forward msg to section",
                msg.id()
            )))
        }
    }

    pub async fn send_to_client(&self, message: Message) -> Result<NodeMessagingDuty> {
        self.inner.send_to_client(message).await
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Result<NodeMessagingDuty> {
        self.inner.send_to_section(message, as_node).await
    }

    pub async fn send_to_node(&self, message: Message) -> Result<NodeMessagingDuty> {
        self.inner.send_to_node(message).await
    }

    pub async fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        message: Message,
        as_section: bool,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        self.inner
            .send_to_adults(targets, message, as_section, origin, proxies)
            .await
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Result<NodeMessagingDuty> {
        self.inner.error(error, msg_id, origin).await
    }
}

impl MsgWrapping {
    pub fn new(keys: NodeSigningKeys, duty: Duty) -> Self {
        Self { keys, duty }
    }

    pub async fn send_to_client(&self, message: Message) -> Result<NodeMessagingDuty> {
        if let Some(origin) = self.sign(&message, true).await {
            let msg = MsgEnvelope {
                message,
                origin,
                proxies: Default::default(),
            };
            Ok(NodeMessagingDuty::SendToClient(msg))
        } else {
            Err(Error::Logic(format!(
                "{:?}: Could not send msg to client",
                message.id()
            )))
        }
    }

    pub async fn send_to_node(&self, message: Message) -> Result<NodeMessagingDuty> {
        if let Some(origin) = self.sign(&message, false).await {
            let msg = MsgEnvelope {
                message,
                origin,
                proxies: Default::default(),
            };
            Ok(NodeMessagingDuty::SendToNode(msg))
        } else {
            Err(Error::Logic(format!(
                "{:?}: Could not send msg to client",
                message.id()
            )))
        }
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Result<NodeMessagingDuty> {
        if let Some(origin) = self.sign(&message, !as_node).await {
            let msg = MsgEnvelope {
                message,
                origin,
                proxies: Default::default(),
            };
            Ok(NodeMessagingDuty::SendToSection { msg, as_node })
        } else {
            Err(Error::Logic(format!(
                "{:?}: Could not send msg to section",
                message.id()
            )))
        }
    }

    pub async fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        message: Message,
        as_section: bool,
        origin: MsgSender,
        proxies: Vec<MsgSender>,
    ) -> Result<NodeMessagingDuty> {
        let msg_envelope = MsgEnvelope {
            message,
            origin,
            proxies,
        };
        if let Some(msg) = self.set_proxy(&msg_envelope, as_section).await {
            Ok(NodeMessagingDuty::SendToAdults { targets, msg })
        } else {
            Err(Error::Logic(format!(
                "{:?}: Could not send msg to adults",
                msg_envelope.id()
            )))
        }
    }

    pub async fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Result<NodeMessagingDuty> {
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

    async fn sign<T: Serialize>(&self, data: &T, as_section: bool) -> Option<MsgSender> {
        let sender = match self.duty {
            Duty::Adult(duty) => {
                let (key, sig) = self.ed_key_sig(data).await?;
                MsgSender::adult(key, duty, sig).ok()?
            }
            Duty::Elder(duty) => {
                if as_section {
                    let bls_key = self.keys.public_key_set().await?.public_key();
                    MsgSender::section(TransientSectionKey { bls_key }, duty).ok()?
                } else {
                    info!("Signing as Node!");
                    let key: TransientElderKey = self.keys.elder_key().await?;
                    if let Signature::BlsShare(sig) = self.keys.sign_as_elder(data).await? {
                        MsgSender::elder(key, duty, sig.share).ok()?
                    } else {
                        return None;
                    }
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
        let sig = match self.keys.sign_as_node(data).await.ok() {
            Some(Signature::Ed25519(key)) => key,
            _ => return None,
        };
        Some((key, sig))
    }

    async fn set_proxy(&self, msg: &MsgEnvelope, as_section: bool) -> Option<MsgEnvelope> {
        // origin signs the message, while proxies sign the envelope
        let mut msg = msg.clone();
        msg.add_proxy(self.sign(&msg.message, as_section).await?);

        Some(msg)
    }
}
