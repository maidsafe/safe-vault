// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::node_ops::NodeMessagingDuty, AdultState, ElderState, NodeState};
use crate::{Error, Result};
use log::{info, warn};
use serde::Serialize;
use sn_data_types::Signature;
use sn_messaging::client::{
    Address, AdultDuties, CmdError, Duty, ElderDuties, Message, MessageId, MsgEnvelope, MsgSender,
    NodeDuties, TransientSectionKey,
};
use std::collections::BTreeSet;
use xor_name::XorName;

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
    node_state: NodeState,
    duty: Duty,
}

impl NodeMsgWrapping {
    pub fn new(node_state: NodeState, duty: NodeDuties) -> Self {
        let inner = MsgWrapping::new(node_state, Duty::Node(duty));
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
    pub fn new(adult_state: AdultState, duty: AdultDuties) -> Self {
        let inner = MsgWrapping::new(NodeState::Adult(adult_state), Duty::Adult(duty));
        Self { inner }
    }

    pub fn name(&self) -> XorName {
        self.inner.name()
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
        let (key, sig) = self.inner.ed_key_sig(&message.serialize()?).await?;
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
    pub fn new(elder_state: ElderState, duty: ElderDuties) -> Self {
        let inner = MsgWrapping::new(NodeState::Elder(elder_state), Duty::Elder(duty));
        Self { inner }
    }

    pub async fn forward(&self, msg: &MsgEnvelope) -> Result<NodeMessagingDuty> {
        let msg = self.inner.set_proxy(&msg, true).await?;
        Ok(NodeMessagingDuty::SendToSection {
            msg,
            as_node: false,
        })
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
    pub fn new(node_state: NodeState, duty: Duty) -> Self {
        Self { node_state, duty }
    }

    pub fn name(&self) -> XorName {
        match &self.node_state {
            NodeState::Adult(state) => state.node_name(),
            NodeState::Elder(state) => state.node_name(),
        }
    }

    pub async fn send_to_client(&self, message: Message) -> Result<NodeMessagingDuty> {
        let origin = self.sign(&message, true).await?;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Ok(NodeMessagingDuty::SendToClient(msg))
    }

    pub async fn send_to_node(&self, message: Message) -> Result<NodeMessagingDuty> {
        let origin = self.sign(&message, false).await?;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Ok(NodeMessagingDuty::SendToNode(msg))
    }

    pub async fn send_to_section(
        &self,
        message: Message,
        as_node: bool,
    ) -> Result<NodeMessagingDuty> {
        let origin = self.sign(&message, !as_node).await?;
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Ok(NodeMessagingDuty::SendToSection { msg, as_node })
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
        let msg = self.set_proxy(&msg_envelope, as_section).await?;
        Ok(NodeMessagingDuty::SendToAdults { targets, msg })
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

    async fn sign<T: Serialize>(&self, data: &T, as_section: bool) -> Result<MsgSender> {
        let sender = match self.duty {
            Duty::Adult(duty) => {
                info!("Signing data as Adult.");
                let (key, sig) = self.ed_key_sig(data).await?;
                MsgSender::adult(key, duty, sig)?
            }
            Duty::Elder(duty) => {
                let elder_state = match &self.node_state {
                    NodeState::Adult(_) => return Err(Error::InvalidOperation),
                    NodeState::Elder(state) => state,
                };
                if as_section {
                    warn!("Creating section sender!");
                    info!("Signing data as Section.");
                    let bls_key = elder_state.public_key_set().public_key();
                    MsgSender::section(TransientSectionKey { bls_key }, duty)?
                } else {
                    info!("Signing data as Elder.");
                    let sig = elder_state.sign_as_elder(data).await?;
                    MsgSender::elder(elder_state.elder_key(), duty, sig.share)?
                }
            }
            Duty::Node(_) => {
                info!("Signing data as Node.");
                let (key, sig) = self.ed_key_sig(data).await?;
                MsgSender::any_node(key, self.duty, sig)?
            }
        };

        Ok(sender)
    }

    async fn ed_key_sig<T: Serialize>(
        &self,
        data: &T,
    ) -> Result<(ed25519_dalek::PublicKey, ed25519_dalek::Signature)> {
        match &self.node_state {
            NodeState::Adult(state) => {
                let key = state.node_id();
                match state.sign_as_node(data).await {
                    Ok(Signature::Ed25519(sig)) => Ok((key, sig)),
                    Err(e) => Err(e),
                    _ => Err(Error::InvalidOperation),
                }
            }
            NodeState::Elder(state) => {
                let key = state.node_id();
                match state.sign_as_node(data).await {
                    Ok(Signature::Ed25519(sig)) => Ok((key, sig)),
                    Err(e) => Err(e),
                    _ => Err(Error::InvalidOperation),
                }
            }
        }
    }

    async fn set_proxy(&self, msg: &MsgEnvelope, as_section: bool) -> Result<MsgEnvelope> {
        // origin signs the message, while proxies sign the envelope
        let mut msg = msg.clone();
        msg.add_proxy(self.sign(&msg.message, as_section).await?);
        Ok(msg)
    }
}
