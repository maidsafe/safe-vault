// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::DutyHandler;
use crate::{
    network::Network,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    section_funds::{self, SectionFunds},
    state::State,
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

impl DutyHandler {
    /// https://github.com/rust-lang/rust-clippy/issues?q=is%3Aissue+is%3Aopen+eval_order_dependence
    #[allow(clippy::eval_order_dependence)]
    pub(crate) async fn get_section_elders(
        &mut self,
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
    pub(crate) async fn notify_section_of_our_storage(&self) -> Result<NodeDuty> {
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

    /// Push our state to the given dst
    pub(crate) async fn push_state(&self, prefix: Prefix, msg_id: MessageId) -> NodeDuty {
        let dst = DstLocation::Section(prefix.name());

        let user_wallets = self.state.user_wallets().await;

        let node_rewards = self.state.section_wallets().await;

        NodeDuty::Send(OutgoingMsg {
            msg: Message::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::ReceiveExistingData {
                    node_rewards,
                    user_wallets,
                }),
                id: msg_id,
                target_section_pk: None,
            },
            section_source: false, // strictly this is not correct, but we don't expect responses to an event..
            dst,
            aggregation: Aggregation::None,
        })
    }
}

pub(crate) async fn register_wallet(network_api: &Network, state: &State) -> OutgoingMsg {
    let address = network_api.our_prefix().await.name();
    OutgoingMsg {
        msg: Message::NodeCmd {
            cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(state.reward_key().await)),
            id: MessageId::new(),
            target_section_pk: None,
        },
        section_source: false, // sent as single node
        dst: DstLocation::Section(address),
        aggregation: Aggregation::None,
    }
}
