// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod level_up;

use super::{
    messaging::{send, send_to_nodes},
    node_ops::{NodeDuties, NodeDuty},
    work::{
        genesis::begin_forming_genesis_section, genesis::receive_genesis_accumulation,
        genesis::receive_genesis_proposal, genesis_stage::GenesisStage,
    },
};
use crate::{Node, Result};

impl Node {
    ///
    pub async fn handle(&mut self, duty: NodeDuty) -> Result<NodeDuties> {
        match duty {
            NodeDuty::GetNodeWalletKey {
                old_node_id,
                new_node_id,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::ActivateNodeRewards {
                id,
                node_id,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::PropagateTransfer {
                proof,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::RegisterSectionPayout {
                debit_agreement,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::SetNodeWallet {
                wallet_id,
                node_id,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::ReceivePayoutValidation {
                validation,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::GetTransferReplicaEvents { msg_id, origin } => {
                return Ok(vec![]);
            }
            NodeDuty::ValidateSectionPayout {
                signed_transfer,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::ReadChunk {
                read,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::WriteChunk {
                write,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }
            NodeDuty::CompleteWalletTransition {
                replicas,
                msg_id,
                origin,
            } => {
                return Ok(vec![]);
            }

            // ---------------------
            NodeDuty::GetSectionElders { msg_id, origin } => {}
            NodeDuty::BeginFormingGenesisSection => {
                self.genesis_stage =
                    begin_forming_genesis_section(self.network_api.clone()).await?;
            }
            NodeDuty::ReceiveGenesisProposal { credit, sig } => {
                self.genesis_stage = receive_genesis_proposal(
                    credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
            }
            NodeDuty::ReceiveGenesisAccumulation { signed_credit, sig } => {
                self.genesis_stage = receive_genesis_accumulation(
                    signed_credit,
                    sig,
                    self.genesis_stage.clone(),
                    self.network_api.clone(),
                )
                .await?;
                let genesis_tx = match &self.genesis_stage {
                    GenesisStage::Completed(genesis_tx) => genesis_tx.clone(),
                    _ => return Ok(vec![]),
                };
                self.level_up(Some(genesis_tx)).await?;
            }
            NodeDuty::LevelUp => {
                self.level_up(None).await?;
            }
            NodeDuty::LevelDown => {
                self.meta_data = None;
                self.transfers = None;
                self.section_funds = None;
            }
            NodeDuty::AssumeAdultDuties => {}
            NodeDuty::UpdateElderInfo {
                prefix,
                key,
                elders,
                sibling_key,
            } => {}
            NodeDuty::CompleteElderChange {
                previous_key,
                new_key,
            } => {}
            NodeDuty::InformNewElders => {}
            NodeDuty::CompleteTransitionToElder {
                section_wallet,
                node_rewards,
                user_wallets,
            } => {}
            NodeDuty::ProcessNewMember(_) => {}
            NodeDuty::ProcessLostMember { name, age } => {}
            NodeDuty::ProcessRelocatedMember {
                old_node_id,
                new_node_id,
                age,
            } => {}
            NodeDuty::ReachingMaxCapacity => {}
            NodeDuty::IncrementFullNodeCount { node_id } => {}
            NodeDuty::SwitchNodeJoin(_) => {}
            NodeDuty::Send(msg) => send(msg, self.network_api.clone()).await?,
            NodeDuty::SendToNodes { targets, msg } => {
                send_to_nodes(targets, &msg, self.network_api.clone()).await?
            }
            NodeDuty::ProcessRead { query, id, origin } => {
                if let Some(ref meta_data) = self.meta_data {
                    return Ok(vec![meta_data.read(query, id, origin).await?]);
                }
            }
            NodeDuty::ProcessWrite { cmd, id, origin } => {
                if let Some(ref mut meta_data) = self.meta_data {
                    return Ok(vec![meta_data.write(cmd, id, origin).await?]);
                }
            }
            NodeDuty::NoOp => {}
        }
        Ok(vec![])
    }
}
