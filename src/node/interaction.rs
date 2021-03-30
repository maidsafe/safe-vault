// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeMap;

use crate::{
    node::{level_up::section_elders, update_transfers::update_transfers},
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{
        self, churn_payout_stage::AccumulatedAgreements, section_wallet::SectionWallet,
        SectionFunds,
    },
    transfers::{
        replica_signing::ReplicaSigningImpl,
        replicas::{ReplicaInfo, Replicas},
    },
    Error, Node, Result,
};
use log::{debug, info};
use section_funds::{
    churn_payout_stage::ChurnPayoutStage,
    churn_process::{Churn, ChurnProcess},
    elder_signing::ElderSigning,
    reward_wallets::RewardWallets,
};
use sn_data_types::{
    ActorHistory, CreditAgreementProof, PublicKey, SectionElders, Token, WalletHistory,
};
use sn_messaging::{
    client::{
        Message, NodeCmd, NodeEvent, NodeQuery, NodeQueryResponse, NodeSystemCmd, NodeSystemQuery,
        NodeSystemQueryResponse, NodeTransferCmd,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::{Elders, XorName};
use sn_transfers::TransferActor;

impl Node {
    ///
    pub(crate) async fn begin_churn_as_newbie(
        &mut self,
        our_elders: Elders,
        sibling_elders: Option<Elders>,
    ) -> Result<NodeDuties> {
        debug!("begin_churn_as_newbie: Zero balance.");

        self.level_up().await?;

        let our_elders_name = XorName::from(our_key);

        let churn = if let Some(sibling_key) = &sibling_key {
            Churn::Split {
                our_elders,
                sibling_elders: sibling_elders.to_owned(),
            }
        } else {
            Churn::Regular(our_elders)
        };

        let mut process = ChurnProcess::new(
            Token::zero(),
            churn,
            ElderSigning::new(self.network_api.clone()).await?,
        );

        let members = section_elders(&self.network_api).await?;
        if our_elders_name != members.name() {
            return Err(Error::Logic(format!(
                "Some failure.. our_elders_name: {:?}, members' name: {:?}",
                our_elders_name,
                members.name()
            )));
        }
        let wallets = RewardWallets::new(BTreeMap::<XorName, (u8, PublicKey)>::new());

        self.section_funds = Some(SectionFunds::Churning {
            process,
            wallets,
            replicas: None,
        });

        Ok(vec![get_wallet_replica_elders(section_key)])
    }

    /// Called on ElderChanged event from routing layer.
    pub(crate) async fn begin_churn_as_oldie(
        &mut self,
        our_elders: Elders,
        sibling_elders: Option<Elders>,
    ) -> Result<NodeDuties> {
        let user_wallets = if let Some(transfers) = &mut self.transfers {
            update_transfers(self.node_info.path(), transfers, &self.network_api).await?;
            transfers.user_wallets()
        } else {
            return Err(Error::Logic("No transfers on this node".to_string()));
        };

        let (section_wallet, wallets) = if let Some(SectionFunds::KeepingNodeWallets {
            section_wallet,
            wallets,
        }) = &mut self.section_funds
        {
            debug!("Node wallets: {:?}", wallets.node_wallets());
            (section_wallet.clone(), wallets.clone())
        } else {
            return Err(Error::Logic("No section funds on this node".to_string()));
        };

        // extract some info before moving our_elders..
        let our_peers = our_elders.prefix.name();
        let section_key = our_elders.key();

        let churn = if let Some(sibling_elders) = &sibling_elders {
            debug!(
                "@@@@@@ SPLIT: Our prefix: {:?}, neighbour: {:?}",
                our_elders.prefix, sibling_elders.prefix
            );
            debug!(
                "@@@@@@ SPLIT: Our key: {:?}, neighbour: {:?}",
                our_elders.key(),
                sibling_elders.key()
            );
            Churn::Split {
                our_elders,
                sibling_elders: sibling_elders.to_owned(),
            }
        } else {
            Churn::Regular(our_elders)
        };

        let mut ops = vec![];

        debug!("Section balance: {}", section_wallet.balance());

        // generate reward and minting proposal
        let mut process = ChurnProcess::new(
            section_wallet.balance(),
            churn,
            ElderSigning::new(self.network_api.clone()).await?,
        );
        ops.push(process.reward_and_mint(wallets.node_wallets()).await?);

        self.section_funds = Some(SectionFunds::Churning {
            process,
            wallets: wallets.clone(),
            replicas: None,
        });

        // query the network for the section elders of the new wallet
        ops.push(get_wallet_replica_elders(section_key));

        let msg_id = MessageId::combine(vec![our_peers, section_key.into()]);

        // push out data to our new (and old..) peers
        ops.push(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards: wallets.node_wallets(),
                    user_wallets: user_wallets.clone(),
                }),
                id: MessageId::new(), //MessageId::in_response_to(&msg_id), //
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an event..
            dst: DstLocation::Section(our_peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
            aggregation: Aggregation::None,       // AtDestination
        }));

        if let Some(sibling_elders) = &sibling_elders {
            // push out data to our sibling peers (i.e. our old peers, and new ones that were promoted)
            let our_sibling_peers = sibling_elders.prefix.name();
            let msg_id = MessageId::combine(vec![our_sibling_peers, sibling_elders.key().into()]);
            ops.push(NodeDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                        node_rewards: wallets.node_wallets(),
                        user_wallets: user_wallets.clone(),
                    }),
                    id: MessageId::new(), //MessageId::in_response_to(&msg_id), //
                    target_section_pk: None,
                },
                section_source: false, // strictly this is not correct, but we don't expect responses to an event..
                dst: DstLocation::Section(our_sibling_peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
                aggregation: Aggregation::None,               // AtDestination
            }));
        }

        Ok(ops)
    }

    pub(crate) fn propagate_credits(credit_proofs: AccumulatedAgreements) -> Result<NodeDuties> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        let mut ops = vec![];
        let location = XorName::from(credit_proofs.section_wallet.recipient());
        let msg_id = MessageId::from_content(&credit_proofs.section_wallet.debiting_replicas_sig)?;
        ops.push(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::NodeCmd {
                cmd: Transfers(PropagateTransfer(credit_proofs.section_wallet)),
                id: msg_id,
                target_section_pk: None,
            },
            section_source: true, // i.e. errors go to our section
            dst: DstLocation::Section(location),
            aggregation: Aggregation::AtDestination, // not necessary, but will be slimmer
        }));

        for (_, credit_proof) in credit_proofs.rewards {
            let location = XorName::from(credit_proof.recipient());
            let msg_id = MessageId::from_content(&credit_proof.debiting_replicas_sig)?;
            ops.push(NodeDuty::Send(OutgoingMsg {
                msg: ProcessMsg::NodeCmd {
                    cmd: Transfers(PropagateTransfer(credit_proof)),
                    id: msg_id,
                },
                section_source: true, // i.e. errors go to our section
                dst: DstLocation::Section(location),
                aggregation: Aggregation::AtDestination, // not necessary, but will be slimmer
            }))
        }
        Ok(ops)
    }

    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub(crate) async fn get_section_elders(
        &self,
        msg_id: MessageId,
        origin: SrcLocation,
    ) -> Result<NodeDuty> {
        let elders = SectionElders {
            prefix: self.network_api.our_prefix().await,
            names: self.network_api.our_elder_names().await,
            key_set: self.network_api.our_public_key_set().await?,
        };
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeQueryResponse {
                response: NodeQueryResponse::System(NodeSystemQueryResponse::GetSectionElders(
                    elders,
                )),
                correlation_id: msg_id,
                id: MessageId::in_response_to(&msg_id), // MessageId::new(), //
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to a response..
            dst: origin.to_dst(),  // this will be a section
            aggregation: Aggregation::AtDestination, // None,
        }))
    }

    ///
    pub(crate) async fn notify_section_of_our_storage(&mut self) -> Result<NodeDuty> {
        let node_id = PublicKey::from(self.network_api.public_key().await);
        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::StorageFull {
                    section: node_id.into(),
                    node_id,
                }),
                id: MessageId::new(),
                target_section_pk: None,
            },
            section_source: false, // sent as single node
            dst: DstLocation::Section(node_id.into()),
            aggregation: Aggregation::None,
        }))
    }

    ///
    pub(crate) async fn register_wallet(&self) -> OutgoingMsg {
        let address = self.network_api.our_prefix().await.name();
        OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(self.node_info.reward_key)),
                id: MessageId::new(),
                target_section_pk: None,
            },
            section_source: false, // sent as single node
            dst: DstLocation::Section(address),
            aggregation: Aggregation::None,
        }
    }
}

// called by both newbies and oldies, which means it will accumulate at dst
pub(crate) fn get_wallet_replica_elders(wallet: PublicKey) -> NodeDuty {
    // deterministic msg id for aggregation
    let msg_id = MessageId::combine(vec![wallet.into()]);
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id: msg_id,
            target_section_pk: None,
        },
        section_source: true,
        dst: DstLocation::Section(wallet.into()),
        aggregation: Aggregation::AtDestination,
    })
}

pub(crate) struct CompletedWalletChurn {
    pub wallets: RewardWallets,
    pub credit_proofs: AccumulatedAgreements,
    pub replicas: SectionElders,
}
