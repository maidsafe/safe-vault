// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod messaging;
mod msg_analysis;
mod network_events;

use crate::node::{
    adult_duties::AdultDuties,
    duty_cfg::DutyConfig,
    elder_duties::ElderDuties,
    msg_wrapping::NodeMsgWrapping,
    node_duties::messaging::Messaging,
    node_ops::{Blah, NodeDuty, NodeOperation},
    state_db::AgeGroup,
    state_db::NodeInfo,
};
use crate::{chunk_store::UsedSpace, Error, Network, Result};
use log::{info, trace, warn};
use msg_analysis::NetworkMsgAnalysis;
use network_events::NetworkEvents;
use sn_data_types::PublicKey;
use sn_messaging::{Message, MessageId, NodeCmd, NodeDuties as MsgNodeDuties, NodeSystemCmd};

#[allow(clippy::large_enum_variant)]
pub enum DutyLevel {
    Infant,
    Adult(AdultDuties),
    Elder(ElderDuties),
}

/// Node duties are those that all nodes
/// carry out. (TBD: adjust for Infant level, which might be doing nothing now).
/// Within the duty level, there are then additional
/// duties to be carried out, depending on the level.
pub struct NodeDuties {
    node_info: NodeInfo,
    duty_level: DutyLevel,
    network_events: NetworkEvents,
    messaging: Messaging,
    network_api: Network,
}

impl NodeDuties {
    pub async fn new(node_info: NodeInfo, network_api: Network) -> Self {
        let age_grp = if network_api.is_elder().await {
            AgeGroup::Elder
        } else if network_api.is_adult().await {
            AgeGroup::Adult
        } else {
            AgeGroup::Infant
        };

        let duty_cfg = DutyConfig::new(node_info.reward_key, network_api.clone(), age_grp);
        let msg_analysis = NetworkMsgAnalysis::new(network_api.clone());
        let network_events = NetworkEvents::new(duty_cfg, msg_analysis);

        let messaging = Messaging::new(network_api.clone());
        Self {
            node_info,
            duty_level: DutyLevel::Infant,
            network_events,
            messaging,
            network_api,
        }
    }

    pub fn adult_duties(&mut self) -> Option<&mut AdultDuties> {
        use DutyLevel::*;
        match &mut self.duty_level {
            Adult(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn elder_duties(&mut self) -> Option<&mut ElderDuties> {
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

    pub async fn process_node_duty(&mut self, duty: NodeDuty) -> Result<NodeOperation> {
        use NodeDuty::*;
        info!("Processing Node Duty: {:?}", duty);
        match duty {
            RegisterWallet(wallet) => self.register_wallet(wallet).await,
            BecomeAdult => self.become_adult().await,
            BecomeElder => self.become_elder().await,
            ProcessMessaging(duty) => self.messaging.process_messaging_duty(duty).await,
            ProcessNetworkEvent(event) => {
                self.network_events
                    .process_network_event(event, &self.network_api)
                    .await
            }
            NoOp => Ok(NodeOperation::NoOp),
            StorageFull => self.notify_section_of_our_storage().await,
        }
    }

    async fn notify_section_of_our_storage(&mut self) -> Result<NodeOperation> {
        let wrapping = NodeMsgWrapping::new(self.node_info.keys(), MsgNodeDuties::NodeConfig);
        let node_id = self.node_info.public_key().await;
        wrapping
            .send_to_section(
                Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::StorageFull {
                        section: node_id.into(),
                        node_id,
                    }),
                    id: MessageId::new(),
                },
                true,
            )
            .await
            .convert()
    }

    async fn register_wallet(&mut self, wallet: PublicKey) -> Result<NodeOperation> {
        let wrapping = NodeMsgWrapping::new(self.node_info.keys(), MsgNodeDuties::NodeConfig);
        wrapping
            .send_to_section(
                Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet {
                        wallet,
                        section: self.node_info.public_key().await.into(),
                    }),
                    id: MessageId::new(),
                },
                true,
            )
            .await
            .convert()
    }

    async fn become_adult(&mut self) -> Result<NodeOperation> {
        trace!("Becoming Adult");
        use DutyLevel::*;
        let used_space = UsedSpace::new(self.node_info.max_storage_capacity);
        if let Ok(duties) = AdultDuties::new(&self.node_info, used_space).await {
            self.duty_level = Adult(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());
        }
        Ok(NodeOperation::NoOp)
    }

    async fn become_elder(&mut self) -> Result<NodeOperation> {
        trace!("Becoming Elder");

        use DutyLevel::*;
        let used_space = UsedSpace::new(self.node_info.max_storage_capacity);
        info!("Attempting to assume Elder duties..");
        if matches!(self.duty_level, Elder(_)) {
            return Ok(NodeOperation::NoOp);
        }

        match ElderDuties::new(&self.node_info, used_space, self.network_api.clone()).await {
            Ok(duties) => {
                let mut duties = duties;
                let op = duties.initiate(self.node_info.first).await;
                self.duty_level = Elder(duties);
                // NB: This is wrong, shouldn't write to disk here,
                // let it be upper layer resp.
                // Also, "Error-to-Unit" is not a good conversion..
                //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())
                info!("Successfully assumed Elder duties!");
                op
            }
            Err(e) => {
                warn!("Was not able to assume Elder duties! {:?}", e);
                Err(Error::Logic(format!(
                    "Not able to assume Elder Duties: {:?}",
                    e
                )))
            }
        }
    }
}
