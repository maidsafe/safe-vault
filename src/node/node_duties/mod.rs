// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

pub mod messaging;
mod elder_constellation;
mod msg_analysis;
mod network_events;

use self::elder_constellation::ElderConstellation;
use crate::{
    node::{
        adult_duties::AdultDuties,
        elder_duties::ElderDuties,
        msg_wrapping::NodeMsgWrapping,
        node_duties::messaging::Messaging,
        node_ops::{IntoNodeOp, NodeDuty, NodeOperation, RewardCmd, RewardDuty},
        NodeInfo,
    },
    AdultState, ElderState, NodeState,
};
use crate::{Error, Network, Result};
use log::{info, trace};
use msg_analysis::NetworkMsgAnalysis;
use network_events::NetworkEvents;
use sn_data_types::{PublicKey, WalletInfo};
use sn_messaging::{
    Address, Message, MessageId, NodeCmd, NodeDuties as MsgNodeDuties, NodeQuery, NodeSystemCmd,
    NodeTransferQuery,
};

#[allow(clippy::large_enum_variant)]
pub enum Stage {
    Infant,
    Adult(AdultDuties),
    Elder(ElderConstellation),
}

/// Node duties are those that all nodes
/// carry out. (TBD: adjust for Infant level, which might be doing nothing now).
/// Within the duty level, there are then additional
/// duties to be carried out, depending on the level.
pub struct NodeDuties {
    node_info: NodeInfo,
    stage: Stage,
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
            stage: Stage::Infant,
            network_events,
            messaging,
            network_api,
        }
    }

    pub fn adult_duties(&mut self) -> Option<&mut AdultDuties> {
        use Stage::*;
        match &mut self.stage {
            Adult(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn elder_duties(&mut self) -> Option<&mut ElderDuties> {
        match &mut self.stage {
            Stage::Elder(ref mut elder) => Some(elder.duties()),
            _ => None,
        }
    }

    fn adult_state(&mut self) -> Result<AdultState> {
        Ok(match self.adult_duties() {
            Some(duties) => duties.state().clone(),
            None => return Err(Error::InvalidOperation),
        })
    }

    fn node_state(&mut self) -> Result<NodeState> {
        Ok(match self.elder_duties() {
            Some(duties) => NodeState::Elder(duties.state().clone()),
            None => match self.adult_duties() {
                Some(duties) => NodeState::Adult(duties.state().clone()),
                None => return Err(Error::InvalidOperation),
            },
        })
    }

    pub async fn process_node_duty(&mut self, duty: NodeDuty) -> Result<NodeOperation> {
        use NodeDuty::*;
        info!("Processing Node duty: {:?}", duty);
        match duty {
            RegisterWallet(wallet) => self.register_wallet(wallet).await,
            AssumeAdultDuties => self.assume_adult_duties().await,
            AssumeElderDuties => self.begin_transition_to_elder().await,
            InitiateElderChange { prefix, key, .. } => {
                self.initiate_elder_change(prefix, key).await
            }
            FinishElderChange {
                previous_key,
                new_key,
            } => self.finish_elder_change(previous_key, new_key).await,
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
        let adult_state = match self.adult_duties() {
            Some(duties) => duties.state().clone(),
            None => return Err(Error::InvalidOperation),
        };
        let wrapping =
            NodeMsgWrapping::new(NodeState::Adult(adult_state), MsgNodeDuties::NodeConfig);
        let node_id = self.node_info.node_id;
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
        let node_state = self.node_state()?;
        let wrapping = NodeMsgWrapping::new(node_state.clone(), MsgNodeDuties::NodeConfig);
        wrapping
            .send_to_section(
                Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet {
                        wallet,
                        section: PublicKey::Ed25519(node_state.node_id()).into(),
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
        if let Ok(duties) = AdultDuties::new(self.adult_state()?).await {
            self.stage = Stage::Adult(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());
        }
        Ok(NodeDuty::RegisterWallet(self.node_info.reward_key).into())
    }

    async fn begin_transition_to_elder(&mut self) -> Result<NodeOperation> {
        if matches!(self.stage, Stage::Elder(_)) {
            return Ok(NodeOperation::NoOp);
        }

        if self.node_info.genesis {
            return self
                .finish_transition_to_elder(WalletInfo {
                    replicas: self.network_api.public_key_set().await?,
                    history: vec![],
                })
                .await;
        }

        trace!("Beginning transition to Elder duties.");

        let wrapping = NodeMsgWrapping::new(
            NodeState::Adult(self.adult_state()?),
            sn_messaging::NodeDuties::NodeConfig,
        );
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
        if matches!(self.stage, Stage::Elder(_)) {
            return Ok(NodeOperation::NoOp);
        }

        trace!("Finishing transition to Elder..");

        let mut ops: Vec<NodeOperation> = vec![];
        let state = ElderState::new(&self.node_info, self.network_api.clone()).await?;
        let mut duties = ElderDuties::new(wallet_info, state.clone()).await?;

        // 1. Initiate duties.
        ops.push(duties.initiate(self.node_info.genesis).await?);
        self.stage = Stage::Elder(ElderConstellation::new(
            self.node_info.clone(),
            duties,
            self.network_api.clone(),
        ));
        // NB: This is wrong, shouldn't write to disk here,
        // let it be upper layer resp.
        // Also, "Error-to-Unit" is not a good conversion..
        //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())
        info!("Successfully assumed Elder duties!");

        let node_id = state.node_name();

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

    ///
    async fn initiate_elder_change(
        &mut self,
        prefix: sn_routing::Prefix,
        new_section_key: PublicKey,
    ) -> Result<NodeOperation> {
        match &mut self.stage {
            Stage::Infant => Ok(NodeOperation::NoOp),
            Stage::Adult(_adult) => {
                let state =
                    AdultState::new(self.node_info.clone(), self.network_api.clone()).await?;
                let duties = AdultDuties::new(state).await?;
                self.stage = Stage::Adult(duties);
                Ok(NodeOperation::NoOp)
            }
            Stage::Elder(elder) => elder.initiate_elder_change(prefix, new_section_key).await,
        }
    }

    ///
    pub async fn finish_elder_change(
        &mut self,
        previous_key: PublicKey,
        new_key: PublicKey,
    ) -> Result<NodeOperation> {
        match &mut self.stage {
            Stage::Infant | Stage::Adult(_) => Ok(NodeOperation::NoOp),
            Stage::Elder(elder) => elder.finish_elder_change(previous_key, new_key).await,
        }
    }
}
