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
    node_ops::{IntoNodeOp, NodeDuty, NodeOperation, RewardCmd, RewardDuty},
    state_db::NodeInfo,
};
use crate::{chunk_store::UsedSpace, Error, Network, Result};
use log::{info, trace, warn};
use msg_analysis::NetworkMsgAnalysis;
use network_events::NetworkEvents;
use sn_data_types::{
    Address, Message, MessageId, NodeCmd, NodeQuery, NodeSystemCmd, NodeTransferQuery, PublicKey,
    WalletInfo,
};

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

/// Configuration made after connected to
/// network, or promoted to elder.
///
/// These are calls made as part of
/// a node initialising into a certain duty.
/// Being first node:
/// -> 1. Add own node id to rewards.
/// -> 2. Add own wallet to rewards.
/// Assuming Adult duties:
/// -> 1. Instantiate AdultDuties.
/// -> 2. Register wallet at Elders.
/// Assuming Elder duties:
/// -> 1. Instantiate ElderDuties.
/// -> 2. Add own node id to rewards.
/// -> 3. Add own wallet to rewards.

impl NodeDuties {
    pub async fn new(node_info: NodeInfo, network_api: Network) -> Self {
        let msg_analysis = NetworkMsgAnalysis::new(network_api.clone());
        let network_events = NetworkEvents::new(msg_analysis);

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
        info!("Processing Node duty: {:?}", duty);
        match duty {
            RegisterWallet(wallet) => self.register_wallet(wallet).await,
            AssumeAdultDuties => self.assume_adult_duties().await,
            AssumeElderDuties => self.begin_transition_to_elder().await,
            InitSectionWallet(wallet_info) => self.finish_transition_to_elder(wallet_info).await,
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
        let wrapping =
            NodeMsgWrapping::new(self.node_info.keys(), sn_data_types::NodeDuties::NodeConfig);
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
        let wrapping =
            NodeMsgWrapping::new(self.node_info.keys(), sn_data_types::NodeDuties::NodeConfig);
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

    async fn assume_adult_duties(&mut self) -> Result<NodeOperation> {
        trace!("Assuming Adult duties..");
        use DutyLevel::*;
        let used_space = UsedSpace::new(self.node_info.max_storage_capacity);
        if let Ok(duties) = AdultDuties::new(&self.node_info, used_space).await {
            self.duty_level = Adult(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());
        }
        Ok(NodeDuty::RegisterWallet(self.node_info.reward_key).into())
    }

    async fn begin_transition_to_elder(&mut self) -> Result<NodeOperation> {
        if matches!(self.duty_level, DutyLevel::Elder(_)) {
            return Ok(NodeOperation::NoOp);
        }

        if self.node_info.first {
            return self
                .finish_transition_to_elder(WalletInfo {
                    replicas: self.network_api.public_key_set().await?,
                    history: vec![],
                })
                .await;
        }

        trace!("Beginning transition to Elder duties.");
        let wrapping =
            NodeMsgWrapping::new(self.node_info.keys(), sn_data_types::NodeDuties::NodeConfig);
        if let Some(wallet_id) = self.network_api.section_public_key().await {
            use NodeTransferQuery::GetNewSectionWallet;
            return wrapping
                .send_to_section(
                    Message::NodeQuery {
                        query: NodeQuery::Transfers(GetNewSectionWallet(wallet_id)),
                        id: MessageId::new(),
                    },
                    true,
                )
                .await
                .convert();
        }

        Ok(NodeOperation::NoOp)
    }

    async fn finish_transition_to_elder(
        &mut self,
        wallet_info: WalletInfo,
    ) -> Result<NodeOperation> {
        use DutyLevel::*;
        if matches!(self.duty_level, Elder(_)) {
            return Ok(NodeOperation::NoOp);
        }

        trace!("Finishing transition to Elder..");
        let used_space = UsedSpace::new(self.node_info.max_storage_capacity);
        match ElderDuties::new(
            &self.node_info,
            wallet_info,
            used_space,
            self.network_api.clone(),
        )
        .await
        {
            Ok(duties) => {
                let mut duties = duties;
                let mut ops: Vec<NodeOperation> = vec![];

                // 1. Initiate duties.
                ops.push(duties.initiate(self.node_info.first).await?);

                self.duty_level = Elder(duties);
                // NB: This is wrong, shouldn't write to disk here,
                // let it be upper layer resp.
                // Also, "Error-to-Unit" is not a good conversion..
                //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())
                info!("Successfully assumed Elder duties!");

                let node_id = self.network_api.name().await;

                // 2. Add own node id to rewards.
                ops.push(
                    RewardDuty::ProcessCmd {
                        cmd: RewardCmd::AddNewNode(node_id),
                        msg_id: MessageId::new(),
                        origin: Address::Node(node_id),
                    }
                    .into(),
                );

                // 3. Add own wallet to rewards.
                ops.push(
                    RewardDuty::ProcessCmd {
                        cmd: RewardCmd::SetNodeWallet {
                            node_id,
                            wallet_id: self.node_info.reward_key,
                        },
                        msg_id: MessageId::new(),
                        origin: Address::Node(node_id),
                    }
                    .into(),
                );

                Ok(ops.into())
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
