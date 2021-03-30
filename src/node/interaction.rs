// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeMap;

use crate::{
    node::update_transfers::update_transfers,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{self, section_wallet::SectionWallet, SectionFunds},
    transfers::{
        replica_signing::ReplicaSigningImpl,
        replicas::{ReplicaInfo, Replicas},
    },
    Error, Node, Result,
};
use dashmap::DashMap;
use log::{debug, info};
use section_funds::{
    elder_signing::ElderSigning,
    reward_process::{OurSection, RewardProcess},
    reward_stage::RewardStage,
    reward_wallets::RewardWallets,
};
use sn_data_types::{
    ActorHistory, CreditAgreementProof, CreditId, NodeAge, PublicKey, SectionElders, Token,
    WalletHistory,
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
    /// Called on split reported from routing layer.
    pub(crate) async fn begin_split_as_newbie(
        &mut self,
        our_key: PublicKey,
        our_prefix: Prefix,
    ) -> Result<()> {
        let section_key = self.network_api.section_public_key().await?;
        if our_key != section_key {
            return Err(Error::Logic(format!(
                "Some failure.. our_key: {}, section_key: {}",
                our_key, section_key
            )));
        }

        debug!("begin_split_as_newbie");

        self.level_up().await?;

        let section = OurSection {
            our_prefix,
            our_key,
        };

        let mut process = RewardProcess::new(
            Token::zero(),
            section,
            ElderSigning::new(self.network_api.clone()).await?,
        );

        let wallets = RewardWallets::new(BTreeMap::<XorName, (NodeAge, PublicKey)>::new());

        self.section_funds = Some(SectionFunds::Churning {
            process,
            wallets,
            payments: Default::default(),
        });

        Ok(())
    }

    /// Called on split reported from routing layer.
    pub(crate) async fn begin_split_as_oldie(
        &mut self,
        our_prefix: Prefix,
        our_key: PublicKey,
        sibling_key: PublicKey,
    ) -> Result<NodeDuties> {
        let user_wallets = if let Some(transfers) = &mut self.transfers {
            update_transfers(self.node_info.path(), transfers, &self.network_api).await?;
            transfers.user_wallets()
        } else {
            return Err(Error::Logic("No transfers on this node".to_string()));
        };

        let (wallets, section_balance) =
            if let Some(SectionFunds::KeepingNodeWallets { wallets, payments }) =
                &mut self.section_funds
            {
                debug!("Node wallets: {:?}", wallets.node_wallets());
                (wallets.clone(), sum(payments))
            } else {
                return Err(Error::NoSectionFunds);
            };

        // extract some info before moving our_elders..
        let our_peers = our_elders.prefix.name();
        let section_key = our_elders.key();

        debug!(
            "@@@@@@ SPLIT: Our prefix: {:?}, neighbour: {:?}",
            our_prefix,
            our_prefix.sibling()
        );
        debug!(
            "@@@@@@ SPLIT: Our key: {:?}, neighbour: {:?}",
            our_key, sibling_key
        );

        let mut ops = vec![];

        debug!("Section balance: {}", section_balance);

        // generate reward and minting proposal
        let mut process = RewardProcess::new(
            section_balance,
            OurSection {
                our_prefix,
                our_key,
            },
            ElderSigning::new(self.network_api.clone()).await?,
        );
        ops.push(process.reward_and_mint(wallets.node_wallets()).await?);

        self.section_funds = Some(SectionFunds::Churning {
            process,
            wallets: wallets.clone(),
            payments: Default::default(), // clear old payments
        });

        let msg_id = MessageId::combine(vec![our_peers, XorName::from(our_key)]);

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

        // push out data to our sibling peers (i.e. our old peers, and new ones that were promoted)
        let our_sibling_peers = our_prefix.sibling().name();

        let msg_id = MessageId::combine(vec![our_sibling_peers, XorName::from(sibling_key)]);
        ops.push(NodeDuty::Send(OutgoingMsg {
            msg: ProcessMsg::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards: wallets.node_wallets(),
                    user_wallets: user_wallets.clone(),
                }),
                id: MessageId::new(), //MessageId::in_response_to(&msg_id), //
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an event..
            dst: DstLocation::Section(our_sibling_peers), // swarming to our peers, if splitting many will be needing this, otherwise only one..
            aggregation: Aggregation::None,               // AtDestination
        }));

        Ok(ops)
    }

    pub(crate) fn propagate_credits(
        credit_proofs: BTreeMap<CreditId, CreditAgreementProof>,
    ) -> Result<NodeDuties> {
        use NodeCmd::*;
        use NodeTransferCmd::*;
        let mut ops = vec![];

        for (_, credit_proof) in credit_proofs {
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

fn sum(payments: &DashMap<CreditId, CreditAgreementProof>) -> Token {
    Token::from_nano(payments.iter().map(|c| (*c).amount().as_nano()).sum())
}
