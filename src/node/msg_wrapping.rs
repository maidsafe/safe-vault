// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{node::keys::NodeKeys, node::node_ops::MessagingDuty, utils};
use log::info;
use safe_nd::{
    Address, AdultDuties, CmdError, Duty, ElderDuties, Message, MessageId, MsgEnvelope, MsgSender,
    NodeCmdError, XorName,
};
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

/// Msg wrapping simplifies
/// the signing and stamping of
/// a sender duty onto remote msgs
/// to be sent on the wire.
#[derive(Clone)]
struct MsgWrapping {
    keys: NodeKeys,
    duty: Duty,
}

impl AdultMsgWrapping {
    pub fn new(keys: NodeKeys, duty: AdultDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Adult(duty));
        Self { inner }
    }

    pub fn send(&self, message: Message) -> Option<MessagingDuty> {
        self.inner.send(message)
    }

    // pub fn send_to_adults(
    //     &self,
    //     targets: BTreeSet<XorName>,
    //     msg: &MsgEnvelope,
    // ) -> Option<MessagingDuty> {
    //     self.inner.send_to_adults(targets, msg)
    // }

    pub fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        self.inner.error(error, msg_id, origin)
    }
}

impl ElderMsgWrapping {
    pub fn new(keys: NodeKeys, duty: ElderDuties) -> Self {
        let inner = MsgWrapping::new(keys, Duty::Elder(duty));
        Self { inner }
    }

    pub fn forward(&self, msg: &MsgEnvelope) -> Option<MessagingDuty> {
        let msg = self.inner.set_proxy(&msg);
        Some(MessagingDuty::SendToSection(msg))
    }

    pub fn send(&self, message: Message) -> Option<MessagingDuty> {
        self.inner.send(message)
    }

    pub fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Option<MessagingDuty> {
        self.inner.send_to_adults(targets, msg)
    }

    pub fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        self.inner.error(error, msg_id, origin)
    }

    pub fn network_error(
        &self,
        error: NodeCmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        self.inner.network_error(error, msg_id, origin)
    }
}

impl MsgWrapping {
    pub fn new(keys: NodeKeys, duty: Duty) -> Self {
        Self { keys, duty }
    }

    pub fn send(&self, message: Message) -> Option<MessagingDuty> {
        let origin = self.sign(&message);
        let msg = MsgEnvelope {
            message,
            origin,
            proxies: Default::default(),
        };
        Some(MessagingDuty::SendToSection(msg))
    }

    pub fn send_to_adults(
        &self,
        targets: BTreeSet<XorName>,
        msg: &MsgEnvelope,
    ) -> Option<MessagingDuty> {
        let msg = self.set_proxy(&msg);
        Some(MessagingDuty::SendToAdults { targets, msg })
    }

    pub fn error(
        &self,
        error: CmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        info!("Error {:?}", error);
        self.send(Message::CmdError {
            id: MessageId::new(),
            error,
            correlation_id: msg_id,
            cmd_origin: origin.clone(),
        })
    }

    pub fn network_error(
        &self,
        error: NodeCmdError,
        msg_id: MessageId,
        origin: &Address,
    ) -> Option<MessagingDuty> {
        self.send(Message::NodeCmdError {
            id: MessageId::new(),
            error,
            correlation_id: msg_id,
            cmd_origin: origin.clone(),
        })
    }

    fn sign<T: Serialize>(&self, data: &T) -> MsgSender {
        MsgSender::Node {
            duty: self.duty,
            proof: self.keys.produce_proof(&utils::serialise(data)),
        }
    }

    fn set_proxy(&self, msg: &MsgEnvelope) -> MsgEnvelope {
        // origin signs the message, while proxies sign the envelope
        msg.with_proxy(self.sign(msg))
    }
}
