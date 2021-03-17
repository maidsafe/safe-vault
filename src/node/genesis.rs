// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    genesis_stage::{GenesisAccumulation, GenesisProposal, GenesisStage},
    messaging::send,
};
use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    node_ops::OutgoingMsg,
    transfers::{
        replica_signing::ReplicaSigningImpl,
        replicas::{ReplicaInfo, Replicas},
        Transfers,
    },
    Error, Network, Node, NodeInfo, Result,
};
use log::{debug, info, trace, warn};
use sn_data_types::{
    ActorHistory, Credit, NodeRewardStage, PublicKey, SignatureShare, SignedCredit, Token,
    TransferPropagated,
};
use sn_messaging::{
    client::{Message, NodeCmd, NodeSystemCmd},
    Aggregation, DstLocation, MessageId,
};
use sn_routing::{XorName, ELDER_SIZE as GENESIS_ELDER_COUNT};
use std::collections::BTreeMap;

///
pub async fn begin_forming_genesis_section(network_api: Network) -> Result<GenesisStage> {
    let is_genesis_section = network_api.our_prefix().await.is_empty();
    let elder_count = network_api.our_elder_names().await.len();
    let section_chain_len = network_api.section_chain().await.len();
    let our_pk_set = network_api.our_public_key_set().await?;

    debug!(
        "begin_transition_to_elder. is_genesis_section: {}, elder_count: {}, section_chain_len: {}",
        is_genesis_section, elder_count, section_chain_len
    );
    if is_genesis_section
        && elder_count == GENESIS_ELDER_COUNT
        && section_chain_len <= GENESIS_ELDER_COUNT
    {
        // this is the case when we are the GENESIS_ELDER_COUNT-th Elder!
        debug!("**********threshold reached; proposing genesis!");

        // let rewards_and_wallets = RewardsAndWallets::new(network_api.clone()).await?;
        let genesis_balance = u32::MAX as u64 * 1_000_000_000;
        let credit = Credit {
            id: Default::default(),
            amount: Token::from_nano(genesis_balance),
            recipient: network_api
                .section_public_key()
                .await
                .ok_or(Error::NoSectionPublicKey)?,
            msg: "genesis".to_string(),
        };

        let mut bootstrap = GenesisProposal {
            proposal: credit.clone(),
            pk_set: our_pk_set,
            signatures: Default::default(),
            pending_agreement: None,
        };

        let our_sig = network_api.sign_as_elder(&credit).await?;
        bootstrap.add(our_sig.clone())?;

        let msg = OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                    credit: credit.clone(),
                    sig: our_sig,
                }),
                id: MessageId::new(),
                target_section_pk: None,
            },
            dst: DstLocation::Section(credit.recipient.into()),
            section_source: false, // sent as single node
            aggregation: Aggregation::None,
        };

        send(msg, network_api).await?;

        Ok(GenesisStage::ProposingGenesis(bootstrap))
    } else if is_genesis_section
        && elder_count < GENESIS_ELDER_COUNT
        && section_chain_len <= GENESIS_ELDER_COUNT
    {
        debug!("AwaitingGenesisThreshold!");
        Ok(GenesisStage::AwaitingGenesisThreshold)
    } else {
        debug!("HITTING GENESIS ELSE FOR SOME REASON....");
        Err(Error::InvalidOperation(
            "Only for genesis formation".to_string(),
        ))
    }
}

// TODO: validate the credit...
pub async fn receive_genesis_proposal(
    credit: Credit,
    sig: SignatureShare,
    stage: GenesisStage,
    network_api: Network,
) -> Result<GenesisStage> {
    if matches!(stage, GenesisStage::AccumulatingGenesis(_)) {
        return Ok(stage);
    }
    let our_prefix = network_api.our_prefix().await;
    match stage {
        GenesisStage::AwaitingGenesisThreshold => {
            let mut bootstrap = GenesisProposal {
                proposal: credit.clone(),
                pk_set: network_api.our_public_key_set().await?,
                signatures: Default::default(),
                pending_agreement: None,
            };
            bootstrap.add(sig)?;

            let our_sig = network_api.sign_as_elder(&credit).await?;
            bootstrap.add(our_sig.clone())?;

            let msg = OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                        credit: credit.clone(),
                        sig: our_sig,
                    }),
                    id: MessageId::new(),
                    target_section_pk: None,
                },
                section_source: false, // sent as single node
                dst: DstLocation::Section(our_prefix.name()),
                aggregation: Aggregation::None,
            };

            send(msg, network_api).await?;

            Ok(GenesisStage::ProposingGenesis(bootstrap))
        }
        GenesisStage::ProposingGenesis(mut bootstrap) => {
            debug!("Adding incoming genesis proposal.");
            bootstrap.add(sig)?;

            if let Some(signed_credit) = &bootstrap.pending_agreement {
                info!("******* there is a genesis proposal agreement");
                // replicas signatures over > signed_credit <
                let mut bootstrap = GenesisAccumulation {
                    agreed_proposal: signed_credit.clone(),
                    pk_set: bootstrap.pk_set,
                    signatures: Default::default(),
                    pending_agreement: None,
                };
                let our_sig = network_api.sign_as_elder(&signed_credit).await?;
                bootstrap.add(our_sig.clone())?;

                let msg = OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis {
                            signed_credit: signed_credit.clone(),
                            sig: our_sig,
                        }),
                        id: MessageId::new(),
                        target_section_pk: None,
                    },
                    section_source: false, // sent as single node
                    dst: DstLocation::Section(our_prefix.name()),
                    aggregation: Aggregation::None,
                };

                send(msg, network_api).await?;

                Ok(GenesisStage::AccumulatingGenesis(bootstrap))
            } else {
                Ok(GenesisStage::ProposingGenesis(bootstrap))
            }
        }
        GenesisStage::AccumulatingGenesis(_) => {
            info!("Already accumulating, no need to handle proposal for genesis.");
            Ok(stage)
        }
        GenesisStage::Completed(_) => {
            info!("Already completed, no need to handle proposal for genesis.");
            Ok(stage)
        }
        GenesisStage::None => Err(Error::InvalidGenesisStage),
    }
}

/// Receive genesis accumulation
pub async fn receive_genesis_accumulation(
    signed_credit: SignedCredit,
    sig: SignatureShare,
    stage: GenesisStage,
    network_api: Network,
) -> Result<GenesisStage> {
    match stage {
        GenesisStage::AwaitingGenesisThreshold => {
            let mut bootstrap = GenesisAccumulation {
                agreed_proposal: signed_credit.clone(),
                pk_set: network_api.our_public_key_set().await?,
                signatures: Default::default(),
                pending_agreement: None,
            };
            bootstrap.add(sig)?;

            // replicas' signatures over > signed_credit <
            let our_sig = network_api.sign_as_elder(&signed_credit).await?;
            bootstrap.add(our_sig)?;

            Ok(GenesisStage::AccumulatingGenesis(bootstrap))
        }
        GenesisStage::ProposingGenesis(bootstrap) => {
            let mut bootstrap = GenesisAccumulation {
                agreed_proposal: signed_credit.clone(),
                pk_set: bootstrap.pk_set,
                signatures: Default::default(),
                pending_agreement: None,
            };
            bootstrap.add(sig)?;

            // replicas' signatures over > signed_credit <
            let our_sig = network_api.sign_as_elder(&signed_credit).await?;
            bootstrap.add(our_sig)?;

            Ok(GenesisStage::AccumulatingGenesis(bootstrap))
        }
        GenesisStage::AccumulatingGenesis(mut bootstrap) => {
            bootstrap.add(sig)?;
            if let Some(genesis) = bootstrap.pending_agreement {
                debug!(">>>>>>>>>>>>>>>>>>>>>>>>. GENESIS AGREEMENT PRODUCED!!!!");
                Ok(GenesisStage::Completed(genesis))
            } else {
                Ok(GenesisStage::AccumulatingGenesis(bootstrap))
            }
        }
        GenesisStage::Completed(_) => {
            info!("Already completed, no need to handle proposal for genesis.");
            Ok(stage)
        }
        GenesisStage::None => Err(Error::InvalidGenesisStage),
    }
}

/// Wallet info of our constellation is supplied here
pub async fn complete_elder_setup(
    node_info: &NodeInfo,
    genesis: Option<TransferPropagated>,
    network_api: Network,
) -> Result<()> {
    debug!(">>>>>>>>>>> Completing transition to elder!!!");
    debug!("????");
    trace!(">>> Setting up node dbs etc...");

    let dbs = ChunkHolderDbs::new(node_info.root_dir.as_path())?;
    let rate_limit = RateLimit::new(network_api.clone(), Capacity::new(dbs.clone()));
    let user_wallets = BTreeMap::<PublicKey, ActorHistory>::new();
    let replicas = transfer_replicas(&node_info, network_api.clone(), user_wallets).await?;

    let transfers = Transfers::new(replicas, rate_limit);

    let node_rewards = BTreeMap::<XorName, NodeRewardStage>::new();
    let node_id = network_api.our_name().await;
    let no_wallet_found = match node_rewards.get(&node_id) {
        None => true,
        Some(stage) => match stage {
            NodeRewardStage::NewNode | NodeRewardStage::AwaitingActivation(_) => true,
            NodeRewardStage::Active { .. } | NodeRewardStage::AwaitingRelocation(_) => false,
        },
    };

    if let Some(genesis) = genesis {
        // if we are genesis
        // does local init, with no roundrip via network messaging
        transfers.genesis(genesis).await?;
    }

    // // 3. Set new stage
    // node_info.used_space.reset().await;

    // self.stage = Stage::Elder(ElderConstellation::new(
    //     elder_duties,
    //     network_api.clone(),
    // ));

    // self.network_events = NetworkEvents::new(ReceivedMsgAnalysis::new(NodeState::Elder(
    //     rewards_and_wallets.clone(),
    // )));

    if no_wallet_found {
        register_wallet(node_info.reward_key, network_api).await?
    }

    Ok(())
}

async fn register_wallet(reward_key: PublicKey, network_api: Network) -> Result<()> {
    let address = network_api.our_prefix().await.name();
    info!("Registering wallet: {}", reward_key);
    let msg = OutgoingMsg {
        msg: Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(reward_key)),
            id: MessageId::new(),
            target_section_pk: None,
        },
        section_source: false, // sent as single node
        dst: DstLocation::Section(address),
        aggregation: Aggregation::None,
    };
    send(msg, network_api).await
}

async fn transfer_replicas(
    node_info: &NodeInfo,
    network: Network,
    user_wallets: BTreeMap<PublicKey, ActorHistory>,
) -> Result<Replicas<ReplicaSigningImpl>> {
    let root_dir = node_info.root_dir.clone();
    let id = network
        .our_public_key_share()
        .await?
        .bls_share()
        .ok_or(Error::ProvidedPkIsNotBlsShare)?;
    let key_index = network.our_index().await?;
    let peer_replicas = network.our_public_key_set().await?;
    let signing = ReplicaSigningImpl::new(network.clone());
    let info = ReplicaInfo {
        id,
        key_index,
        peer_replicas,
        section_chain: network.section_chain().await,
        signing,
        initiating: true,
    };
    Replicas::new(root_dir, info, user_wallets).await
}
