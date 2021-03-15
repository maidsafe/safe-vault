// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeMap;

use super::genesis_stage::{GenesisAccumulation, GenesisProposal, GenesisStage};
use crate::{
    capacity::{Capacity, ChunkHolderDbs, RateLimit},
    node::{
        messaging::send,
        node_ops::OutgoingMsg,
        transfers::{
            replica_signing::ReplicaSigningImpl,
            replicas::{ReplicaInfo, Replicas},
            Transfers,
        },
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

///
pub async fn begin_forming_genesis_section(network_api: Network) -> Result<GenesisStage> {
    let is_genesis_section = network_api.our_prefix().await.is_empty();
    let elder_count = network_api.our_elder_names().await.len();
    let section_chain_len = network_api.section_chain().await.len();
    let our_pk_share = network_api.our_public_key_share().await?;
    let our_index = network_api.our_index().await?;

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
        let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
        let credit_sig_share = network_api.sign_as_elder(&credit).await?;
        let _ = signatures.insert(our_index, credit_sig_share.clone());

        let msg = OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                    credit: credit.clone(),
                    sig: SignatureShare {
                        share: credit_sig_share,
                        index: our_index,
                    },
                }),
                id: MessageId::new(),
                target_section_pk: None,
            },
            dst: DstLocation::Section(credit.recipient.into()),
            section_source: false, // sent as single node
            aggregation: Aggregation::None,
        };

        send(msg, network_api).await?;

        Ok(GenesisStage::ProposingGenesis(GenesisProposal {
            proposal: credit.clone(),
            signatures,
            pending_agreement: None,
        }))
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
    let our_index = network_api.our_index().await?;
    match stage {
        GenesisStage::AwaitingGenesisThreshold => {
            let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
            let _ = signatures.insert(sig.index, sig.share);

            let credit_sig_share = network_api.sign_as_elder(&credit).await?;
            let _ = signatures.insert(our_index, credit_sig_share.clone());

            let dst = DstLocation::Section(XorName::from(
                network_api
                    .section_public_key()
                    .await
                    .ok_or(Error::NoSectionPublicKey)?,
            ));

            let msg = OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ProposeGenesis {
                        credit: credit.clone(),
                        sig: SignatureShare {
                            share: credit_sig_share,
                            index: our_index,
                        },
                    }),
                    id: MessageId::new(),
                    target_section_pk: None,
                },
                section_source: false, // sent as single node
                dst,
                aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
            };

            send(msg, network_api).await?;

            Ok(GenesisStage::ProposingGenesis(GenesisProposal {
                proposal: credit.clone(),
                signatures,
                pending_agreement: None,
            }))
        }
        GenesisStage::ProposingGenesis(mut bootstrap) => {
            debug!("Adding incoming genesis proposal.");
            let section_pk_set = network_api
                .our_public_key_set()
                .await
                .map_err(|_| Error::NoSectionPublicKeySet)?;
            let section_pk = PublicKey::Bls(section_pk_set.public_key());
            bootstrap.add(sig, section_pk_set)?;
            if let Some(signed_credit) = &bootstrap.pending_agreement {
                info!("******* there is an agreement");
                // replicas signatures over > signed_credit <
                let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
                let credit_sig_share = network_api.sign_as_elder(&signed_credit).await?;
                let _ = signatures.insert(our_index, credit_sig_share.clone());

                let msg = OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::System(NodeSystemCmd::AccumulateGenesis {
                            signed_credit: signed_credit.clone(),
                            sig: SignatureShare {
                                share: credit_sig_share,
                                index: our_index,
                            },
                        }),
                        id: MessageId::new(),
                        target_section_pk: None,
                    },
                    section_source: false, // sent as single node
                    dst: DstLocation::Section(XorName::from(section_pk)),
                    aggregation: Aggregation::None, // TODO: to_be_aggregated: Aggregation::AtDestination,
                };

                send(msg, network_api).await?;

                Ok(GenesisStage::AccumulatingGenesis(GenesisAccumulation {
                    agreed_proposal: signed_credit.clone(),
                    signatures,
                    pending_agreement: None,
                }))
            } else {
                Ok(GenesisStage::ProposingGenesis(bootstrap))
            }
        }
        _ => {
            warn!("Recevied an out of order proposal for genesis.");
            warn!(
                "We may already have seen + verified genesis, in which case this can be ignored."
            );

            // TODO: do we want to Lazy err here?

            Ok(stage)
        }
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
        GenesisStage::ProposingGenesis(_) => {
            // replicas signatures over > signed_credit <
            let mut signatures: BTreeMap<usize, bls::SignatureShare> = Default::default();
            let _ = signatures.insert(sig.index, sig.share);
            let our_sig_index = network_api.our_index().await?;

            let credit_sig_share = network_api.sign_as_elder(&signed_credit).await?;
            let _ = signatures.insert(our_sig_index, credit_sig_share);

            Ok(GenesisStage::AccumulatingGenesis(GenesisAccumulation {
                agreed_proposal: signed_credit,
                signatures,
                pending_agreement: None,
            }))
        }
        GenesisStage::AccumulatingGenesis(mut bootstrap) => {
            let section_pk_set = network_api
                .our_public_key_set()
                .await
                .map_err(|_| Error::NoSectionPublicKeySet)?;
            bootstrap.add(sig, section_pk_set)?;

            if let Some(genesis) = bootstrap.pending_agreement.take() {
                // TODO: do not take this? (in case of fail further blow)
                let our_sig_index = network_api.our_index().await?;
                let credit_sig_share = network_api.sign_as_elder(&genesis).await?;
                let _ = bootstrap.signatures.insert(our_sig_index, credit_sig_share);

                Ok(GenesisStage::Completed(TransferPropagated {
                    credit_proof: genesis.clone(),
                }))
            } else {
                Ok(GenesisStage::AccumulatingGenesis(bootstrap))
            }
        }
        _ => Err(Error::InvalidGenesisStage),
    }

    // if genesis_tx.is_some() {
    //     debug!(">>>>>>>>>>>>>>>>>>>>>>>>. GENSIS AGREEMENT PROVED!!!!");
    //     return complete_elder_setup(genesis_tx, network_api).await;
    // }
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

    info!("Successfully assumed Elder duties!");

    if no_wallet_found {
        register_wallet(node_info.reward_key, network_api).await?
    }

    debug!(">>>> I AM ELDER");
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
