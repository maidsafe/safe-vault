// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{self, SectionFunds},
    transfers::{
        get_replicas::replica_info,
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
    Credits,
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
use sn_routing::{Prefix, XorName};
use sn_transfers::TransferActor;
use std::collections::BTreeMap;

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
            let info = replica_info(&self.node_info, &self.network_api).await?;
            transfers.update_replica_info(info);
            transfers.user_wallets()
        } else {
            return Err(Error::Logic("No transfers on this node".to_string()));
        };

        let (wallets, section_balance) =
            if let Some(SectionFunds::KeepingNodeWallets { wallets, payments }) =
                &mut self.section_funds
            {
                debug!("Node wallets: {:?}", wallets.node_wallets());
                (wallets.clone(), payments.sum())
            } else {
                return Err(Error::NoSectionFunds);
            };

        let our_peers = our_prefix.name();

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

        Ok(ops)
    }
}
