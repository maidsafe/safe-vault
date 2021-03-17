// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{self, reward_payout::Validator, rewards::Rewards, SectionFunds},
    Error, Node, Result,
};
use log::debug;
use section_funds::{
    churn_process::{Churn, ChurnProcess},
    elder_signing::ElderSigning,
    rewards::RewardCalc,
    wallet_stage::WalletStage,
};
use sn_data_types::{ActorHistory, CreditAgreementProof, PublicKey, SectionElders, WalletHistory};
use sn_messaging::{
    client::{
        Message, NodeCmd, NodeEvent, NodeQuery, NodeQueryResponse, NodeSystemCmd, NodeSystemQuery,
        NodeSystemQueryResponse,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::Elders;
use sn_transfers::TransferActor;

impl Node {
    /// Called on ElderChanged event from routing layer.
    pub async fn begin_churn(
        &mut self,
        our_elders: Elders,
        sibling_elders: Option<Elders>,
    ) -> Result<NodeDuties> {
        let user_wallets = if let Some(transfers) = &self.transfers {
            transfers.user_wallets()
        } else {
            return Err(Error::Logic("No transfers on this node".to_string()));
        };

        let rewards = if let Some(SectionFunds::Rewarding(rewards)) = &self.section_funds {
            if rewards.has_payout_in_flight() {
                return Err(Error::Logic(
                    "TODO: Fix this. Reward payout still in flight..".to_string(),
                ));
            }
            rewards.clone()
        } else {
            return Err(Error::Logic("No section funds on this node".to_string()));
        };

        // extract some info before moving our_elders..
        let our_peers = our_elders.prefix.name();
        let section_key = our_elders.key();

        let churn = if let Some(sibling_elders) = &sibling_elders {
            Churn::Split {
                our_elders,
                sibling_elders: sibling_elders.to_owned(),
            }
        } else {
            Churn::Regular(our_elders)
        };

        let mut ops = vec![];

        debug!("Current balance: {}", rewards.balance());

        // generate new wallet proposal
        let mut process = ChurnProcess::new(
            rewards.balance(),
            churn,
            ElderSigning::new(self.network_api.clone()).await?,
        );
        ops.push(process.move_wallet().await?);

        self.section_funds = Some(SectionFunds::Churning {
            process,
            rewards: rewards.clone(),
            replicas: None,
        });

        // query the network for the section elders of the new wallet
        ops.push(get_wallet_replica_elders(section_key));

        debug!("@@@@@@ SYNCHING DATA TO PEERS");

        let msg_id = MessageId::combine(vec![our_peers, section_key.into()]);

        // push out data to our new (and old..) peers
        ops.push(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards: rewards.node_rewards(),
                    user_wallets: user_wallets.clone(),
                }),
                id: MessageId::in_response_to(&msg_id), // MessageId::new(), //
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an event..
            dst: DstLocation::Section(our_peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
            aggregation: Aggregation::AtDestination,
        }));

        if let Some(sibling_elders) = &sibling_elders {
            // push out data to our sibling peers (i.e. our old peers, and new ones that were promoted)
            let our_sibling_peers = sibling_elders.prefix.name();
            let msg_id = MessageId::combine(vec![our_sibling_peers, sibling_elders.key().into()]);
            ops.push(NodeDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                        node_rewards: rewards.node_rewards(),
                        user_wallets: user_wallets.clone(),
                    }),
                    id: MessageId::in_response_to(&msg_id), // MessageId::new(), //
                    target_section_pk: None,
                },
                section_source: false, // strictly this is not correct, but we don't expect responses to an event..
                dst: DstLocation::Section(our_sibling_peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
                aggregation: Aggregation::AtDestination,
            }));
        }

        Ok(ops)
    }

    /// set funds to Rewarding stage
    pub async fn create_section_wallet(
        &mut self,
        mut rewards: Rewards,
        replicas: SectionElders,
        credit_proof: CreditAgreementProof,
    ) -> Result<NodeDuty> {
        let section_wallet = WalletHistory {
            replicas,
            history: ActorHistory {
                credits: vec![credit_proof.clone()],
                debits: vec![],
            },
        };

        /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
        #[allow(clippy::eval_order_dependence)]
        let members = SectionElders {
            prefix: self.network_api.our_prefix().await,
            names: self.network_api.our_elder_names().await,
            key_set: self.network_api.our_public_key_set().await?,
        };

        let our_section_address = members.address();
        let msg_id = MessageId::combine(vec![members.name(), our_section_address]);

        let reward_calc = RewardCalc::new(members.prefix);
        let signing = ElderSigning::new(self.network_api.clone()).await?;
        let actor = TransferActor::from_info(signing, section_wallet.clone(), Validator {})?;
        let mut rewards = rewards.clone();
        rewards.set(actor, members, reward_calc);
        self.section_funds = Some(SectionFunds::Rewarding(rewards));

        Ok(NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeEvent {
                event: NodeEvent::SectionWalletCreated(section_wallet),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                target_section_pk: None,
            },
            dst: DstLocation::Section(our_section_address),
            section_source: false,
            aggregation: Aggregation::AtDestination,
        }))
    }

    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub async fn get_section_elders(
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
            dst: origin.to_dst(),  // this will be a single Node
            aggregation: Aggregation::AtDestination, // None,
        }))
    }
}

// called by a subset of elders..
pub fn get_wallet_replica_elders(wallet: PublicKey) -> NodeDuty {
    // deterministic msg id for aggregation
    let msg_id = MessageId::combine(vec![wallet.into()]);
    NodeDuty::Send(OutgoingMsg {
        msg: Message::NodeQuery {
            query: NodeQuery::System(NodeSystemQuery::GetSectionElders),
            id: msg_id, // MessageId::new(), //
            target_section_pk: None,
        },
        section_source: true,
        dst: DstLocation::Section(wallet.into()),
        aggregation: Aggregation::AtDestination, // None,
    })
}
