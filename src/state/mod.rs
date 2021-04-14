// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod commands;
mod roles;

pub(crate) use commands::{AdultStateCommand, ElderStateCommand};

use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    chunk_store::UsedSpace,
    chunks::Chunks,
    event_mapping::{map_routing_event, LazyError, Mapping, MsgContext},
    metadata::{adult_reader::AdultReader, Metadata},
    network::Network,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{
        reward_stage::RewardStage, reward_wallets::RewardWallets, Credits, SectionFunds,
    },
    state_db::store_new_reward_keypair,
    transfers::{
        get_replicas::transfer_replicas, replica_signing::ReplicaSigningImpl,
        replicas::ReplicaInfo, Transfers,
    },
    Config, Error, Result,
};
use bls::SecretKey;
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use hex_fmt::HexFmt;
use log::{debug, error, info, trace, warn};
use roles::{AdultRole, ElderRole, Role};
use sn_data_types::{
    ActorHistory, Blob, BlobAddress, CreditAgreementProof, CreditId, NodeAge, PublicKey,
    RewardAccumulation, RewardProposal, SectionElders, Token, TransferPropagated, WalletHistory,
};
use sn_messaging::{
    client::{
        Message, NodeCmd, NodeEvent, NodeQuery, NodeQueryResponse, NodeSystemCmd, NodeSystemQuery,
        NodeSystemQueryResponse, NodeTransferCmd,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::{
    Event as RoutingEvent, EventStream, NodeElderChange, Prefix, XorName,
    ELDER_SIZE as GENESIS_ELDER_COUNT, MIN_AGE,
};
use sn_transfers::{TransferActor, Wallet};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

// Data kept in the node's state
struct StateData {
    root_dir: PathBuf,
    node_name: XorName,
    node_id: Ed25519PublicKey,
    used_space: UsedSpace,
    prefix: Prefix,
    // The key used by the node to receive earned rewards.
    reward_key: PublicKey,
    role: Role,
}

// Node's state
#[derive(Clone)]
pub struct State(Arc<Mutex<StateData>>);

impl State {
    pub async fn new(
        root_dir: PathBuf,
        network_api: &Network,
        max_capacity: u64,
        reward_key: PublicKey,
    ) -> Result<Self> {
        let used_space = UsedSpace::new(max_capacity);
        let prefix = network_api.our_prefix().await;
        let node_name = network_api.our_name().await;
        let chunks = Some(Chunks::new(node_name, root_dir.as_path(), used_space.clone()).await?);
        let role = Role::Adult(AdultRole {
            chunks: Chunks::new(node_name, root_dir.as_path(), used_space.clone()).await?,
        });

        let state_data = StateData {
            root_dir,
            node_name,
            node_id: network_api.public_key().await,
            used_space,
            prefix,
            reward_key,
            role,
        };

        Ok(Self(Arc::new(Mutex::new(state_data))))
    }

    pub async fn reward_key(&self) -> PublicKey {
        self.0.lock().await.reward_key
    }

    pub async fn node_name(&self) -> XorName {
        self.0.lock().await.node_name
    }

    pub async fn node_root_dir(&self) -> PathBuf {
        self.0.lock().await.root_dir.clone()
    }

    pub async fn used_space(&self) -> UsedSpace {
        self.0.lock().await.used_space.clone()
    }

    pub async fn reset_used_space(&self) {
        self.0.lock().await.used_space.reset().await;
    }

    pub async fn transfers_managed_amount(&self) -> Result<Token> {
        match self.0.lock().await.role.as_elder() {
            Err(err) => Err(err),
            Ok(elder) => elder.transfers.managed_amount().await,
        }
    }

    pub async fn wallets_and_payments(&self) -> Result<(RewardWallets, Token)> {
        match self.0.lock().await.role.as_elder() {
            Err(err) => Err(err),
            Ok(elder) => match &elder.section_funds {
                SectionFunds::KeepingNodeWallets { wallets, payments }
                | SectionFunds::Churning {
                    wallets, payments, ..
                } => Ok((wallets.clone(), payments.sum())),
            },
        }
    }

    pub async fn set_elder_role(
        &mut self,
        meta_data: Metadata,
        transfers: Transfers,
        section_funds: SectionFunds,
    ) {
        self.0.lock().await.role = Role::Elder(ElderRole {
            meta_data,
            transfers,
            section_funds,
        });
    }

    pub async fn demote_to_adult_role(&mut self) -> Result<()> {
        let mut state = self.0.lock().await;
        let adult_role = Role::Adult(AdultRole {
            chunks: Chunks::new(
                state.node_name,
                state.root_dir.as_path(),
                state.used_space.clone(),
            )
            .await?,
        });
        state.role = adult_role;

        Ok(())
    }

    pub async fn section_wallets(&self) -> BTreeMap<XorName, (NodeAge, PublicKey)> {
        if let Ok(ElderRole { section_funds, .. }) = &self.0.lock().await.role.as_elder() {
            section_funds.node_wallets()
        } else {
            BTreeMap::new()
        }
    }

    pub async fn user_wallets(&self) -> BTreeMap<PublicKey, ActorHistory> {
        if let Ok(ElderRole { transfers, .. }) = &self.0.lock().await.role.as_elder() {
            transfers.user_wallets()
        } else {
            BTreeMap::new()
        }
    }

    pub async fn adult_command(&mut self, adult_cmd: AdultStateCommand) -> Result<NodeDuties> {
        match self.0.lock().await.role.as_adult_mut() {
            Err(err) => Err(err),
            Ok(mut adult) => match adult_cmd {
                AdultStateCommand::GetChunkForReplication {
                    address,
                    id,
                    section,
                } => {
                    let op = adult
                        .chunks
                        .get_chunk_for_replication(address, id, section)
                        .await?;
                    Ok(vec![op])
                }
                AdultStateCommand::StoreChunkForReplication(data) => {
                    adult.chunks.store_for_replication(data).await?;
                    Ok(vec![])
                }
                AdultStateCommand::WriteChunk {
                    write,
                    msg_id,
                    origin,
                } => {
                    let op = adult.chunks.write(&write, msg_id, origin).await?;
                    Ok(vec![op])
                }
                AdultStateCommand::ReadChunk {
                    read,
                    msg_id,
                    origin,
                } => {
                    let op = adult.chunks.read(&read, msg_id, origin).await?;
                    Ok(vec![op])
                }
                AdultStateCommand::CheckStorage => adult.chunks.check_storage().await,
            },
        }
    }

    pub async fn elder_command(&mut self, elder_cmd: ElderStateCommand) -> Result<NodeDuties> {
        match self.0.lock().await.role.as_elder_mut() {
            Err(err) => Err(err),
            Ok(mut elder) => {
                match elder_cmd {
                    ElderStateCommand::ReceiveWalletAccumulation {
                        accumulation,
                        section_key,
                    } => {
                        info!("Handling Churn proposal as an Elder");
                        let (churn_process, wallets, payments) =
                            elder.section_funds.as_churning_mut()?;

                        let mut ops = vec![
                            churn_process
                                .receive_wallet_accumulation(accumulation)
                                .await?,
                        ];

                        if let RewardStage::Completed(credit_proofs) = churn_process.stage() {
                            let reward_sum = credit_proofs.sum();
                            ops.extend(propagate_credits(credit_proofs.clone())?);
                            // update state
                            elder.section_funds = SectionFunds::KeepingNodeWallets {
                                wallets: wallets.clone(),
                                payments: payments.clone(),
                            };

                            info!(
                                "COMPLETED SPLIT. New section: ({}). Total rewards paid: {}.",
                                section_key, reward_sum
                            );
                        }

                        Ok(ops)
                    }
                    ElderStateCommand::ReceiveChurnProposal(proposal) => {
                        info!("Handling Churn proposal as an Elder");
                        let (churn_process, _, _) = elder.section_funds.as_churning_mut()?;
                        let op = churn_process.receive_churn_proposal(proposal).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::MergeUserWallets(user_wallets) => {
                        elder.transfers.merge(user_wallets);
                        Ok(vec![])
                    }
                    ElderStateCommand::SetNodeRewardsWallets(node_wallets) => {
                        for (key, (age, wallet)) in node_wallets {
                            elder.section_funds.set_node_wallet(key, wallet, age);
                        }
                        Ok(vec![])
                    }
                    ElderStateCommand::SetSectionFunds(section_funds) => {
                        elder.section_funds = section_funds;
                        Ok(vec![])
                    }
                    ElderStateCommand::RemoveNodeWallet(name) => {
                        elder.section_funds.remove_node_wallet(name);
                        Ok(vec![])
                    }
                    ElderStateCommand::AddPayment(credit) => {
                        elder.section_funds.add_payment(credit);
                        Ok(vec![])
                    }
                    ElderStateCommand::UpdateReplicaInfo(info) => {
                        elder.transfers.update_replica_info(info);
                        Ok(vec![])
                    }
                    ElderStateCommand::DecreaseFullNodeCount(name) => {
                        elder
                            .transfers
                            .decrease_full_node_count_if_present(name)
                            .await?;
                        Ok(vec![])
                    }
                    ElderStateCommand::IncreaseFullNodeCount(node_id) => {
                        elder.transfers.increase_full_node_count(node_id).await?;
                        Ok(vec![])
                    }
                    ElderStateCommand::TriggerChunkReplication(name) => {
                        elder.meta_data.trigger_chunk_replication(name).await
                    }
                    ElderStateCommand::FinishChunkReplication(data) => {
                        let op = elder.meta_data.finish_chunk_replication(data).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::ProcessPayment { msg, origin } => {
                        elder.transfers.process_payment(&msg, origin).await
                    }
                    ElderStateCommand::WriteDataCmd { cmd, id, origin } => {
                        let op = elder.meta_data.write(cmd, id, origin).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::ReadDataCmd { query, id, origin } => {
                        let op = elder.meta_data.read(query, id, origin).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::RegisterTransfer { proof, msg_id } => {
                        let op = elder.transfers.register(&proof, msg_id).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::GetStoreCost {
                        bytes,
                        msg_id,
                        origin,
                    } => Ok(elder.transfers.get_store_cost(bytes, msg_id, origin).await),
                    ElderStateCommand::GetTransfersBalance { at, msg_id, origin } => {
                        let op = elder.transfers.balance(at, msg_id, origin).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::GetTransfersHistory { at, msg_id, origin } => {
                        let op = elder.transfers.history(&at, msg_id, origin).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::CreditWithoutProof(transfer) => {
                        let op = elder.transfers.credit_without_proof(transfer).await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::ValidateTransfer {
                        signed_transfer,
                        msg_id,
                        origin,
                    } => {
                        let op = elder
                            .transfers
                            .validate(signed_transfer, msg_id, origin)
                            .await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::ReceivePropagated {
                        proof,
                        msg_id,
                        origin,
                    } => {
                        let op = elder
                            .transfers
                            .receive_propagated(&proof, msg_id, origin)
                            .await?;
                        Ok(vec![op])
                    }
                    ElderStateCommand::GetTransferReplicaEvents { msg_id, origin } => {
                        let op = elder.transfers.all_events(msg_id, origin).await?;
                        Ok(vec![op])
                    }
                }
            }
        }
    }
}

fn propagate_credits(
    credit_proofs: BTreeMap<CreditId, CreditAgreementProof>,
) -> Result<NodeDuties> {
    let mut ops = vec![];

    for (_, credit_proof) in credit_proofs {
        let location = XorName::from(credit_proof.recipient());
        let msg_id = MessageId::from_content(&credit_proof.debiting_replicas_sig)?;
        ops.push(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::Transfers(NodeTransferCmd::PropagateTransfer(credit_proof)),
                id: msg_id,
                target_section_pk: None,
            },
            section_source: true, // i.e. errors go to our section
            dst: DstLocation::Section(location),
            aggregation: Aggregation::AtDestination, // not necessary, but will be slimmer
        }))
    }
    Ok(ops)
}
