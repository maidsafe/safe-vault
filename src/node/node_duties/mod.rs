// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulation;
pub mod messaging;
mod msg_analysis;
mod network_events;

use crate::node::{
    adult_duties::AdultDuties,
    elder_duties::ElderDuties,
    msg_wrapping::NodeMsgWrapping,
    node_duties::messaging::Messaging,
    node_ops::{NodeDuty, NodeOperation},
    startup::Startup,
    state_db::NodeInfo,
};
use crate::Network;
use futures::lock::Mutex;
use log::{info, trace, warn};
use msg_analysis::NetworkMsgAnalysis;
use network_events::NetworkEvents;
use rand::{CryptoRng, Rng};
use sn_data_types::{Message, MessageId, NodeCmd, NodeSystemCmd, PublicKey};
use std::sync::Arc;

#[allow(clippy::large_enum_variant)]
pub enum DutyLevel<R: CryptoRng + Rng> {
    Infant,
    Adult(AdultDuties),
    Elder(ElderDuties<R>),
}

/// Node duties are those that all nodes
/// carry out. (TBD: adjust for Infant level, which might be doing nothing now).
/// Within the duty level, there are then additional
/// duties to be carried out, depending on the level.
pub struct NodeDuties<R: CryptoRng + Rng> {
    node_info: NodeInfo,
    duty_level: DutyLevel<R>,
    network_events: NetworkEvents,
    messaging: Messaging,
    network_api: Network,
    rng: Option<R>,
}

impl<R: CryptoRng + Rng> NodeDuties<R> {
    pub fn new(node_info: NodeInfo, network_api: Network, rng: R) -> Self {
        let startup = Startup::new(node_info.reward_key, network_api.clone());
        let msg_analysis = NetworkMsgAnalysis::new(network_api.clone());
        let network_events = NetworkEvents::new(startup, msg_analysis);

        let messaging = Messaging::new(network_api.clone());
        Self {
            node_info,
            duty_level: DutyLevel::Infant,
            network_events,
            messaging,
            network_api,
            rng: Some(rng),
        }
    }

    pub fn adult_duties(&mut self) -> Option<&mut AdultDuties> {
        use DutyLevel::*;
        match &mut self.duty_level {
            Adult(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn elder_duties(&mut self) -> Option<&mut ElderDuties<R>> {
        use DutyLevel::*;

        let level = match &mut self.duty_level {
            Elder(ref mut duties) => Some(duties),
            _ => None,
        };

        info!(
            "Checking duty level: are we an Elder? {:?}",
            level.is_some()
        );

        level
    }

    pub async fn process_node_duty(&mut self, duty: NodeDuty) -> Option<NodeOperation> {
        use NodeDuty::*;
        info!("Processing Node Duty: {:?}", duty);
        match duty {
            RegisterWallet(wallet) => self.register_wallet(wallet).await,
            BecomeAdult => self.become_adult(),
            BecomeElder => self.become_elder().await,
            ProcessMessaging(duty) => self.messaging.process_messaging_duty(duty).await,
            ProcessNetworkEvent(event) => self.network_events.process_network_event(event).await,
        }
    }

    async fn register_wallet(&mut self, wallet: PublicKey) -> Option<NodeOperation> {
        let wrapping =
            NodeMsgWrapping::new(self.node_info.keys(), sn_data_types::NodeDuties::NodeConfig);
        wrapping
            .send(Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet {
                    wallet,
                    section: self.node_info.public_key().await?.into(),
                }),
                id: MessageId::new(),
            })
            .await
            .map(|c| c.into())
    }

    fn become_adult(&mut self) -> Option<NodeOperation> {
        trace!("Becoming Adult");
        use DutyLevel::*;
        let total_used_space = Arc::new(Mutex::new(0));
        if let Ok(duties) = AdultDuties::new(&self.node_info, &total_used_space) {
            self.duty_level = Adult(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());
        }
        None
    }

    async fn become_elder(&mut self) -> Option<NodeOperation> {
        trace!("Becoming Elder");

        use DutyLevel::*;
        let total_used_space = Arc::new(Mutex::new(0));
        info!("Attempting to assume Elder duties..");
        if matches!(self.duty_level, Elder(_)) {
            return None;
        }
        if let Ok(duties) = ElderDuties::new(
            &self.node_info,
            &total_used_space,
            self.network_api.clone(),
            self.rng.take()?,
        )
        .await
        {
            let mut duties = duties;
            let op = duties.initiate().await;
            self.duty_level = Elder(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())
            info!("Successfully assumed Elder duties!");
            op
        } else {
            warn!("Was not able to assume Elder duties!");
            None
        }
    }
}
