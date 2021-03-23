// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Node, Result,
};
use sn_data_types::{CreditAgreementProof, CreditId, PublicKey, SectionElders};
use sn_messaging::{
    client::{
        NodeCmd, NodeQueryResponse, NodeSystemCmd, NodeSystemQueryResponse, NodeTransferCmd,
        ProcessMsg,
    },
    Aggregation, DstLocation, MessageId, SrcLocation,
};
use sn_routing::{Prefix, XorName};
use std::collections::BTreeMap;

impl Node {
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
                msg: Message::NodeCmd {
                    cmd: Transfers(PropagateTransfer(credit_proof)),
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
            msg: ProcessMsg::NodeQueryResponse {
                response: NodeQueryResponse::System(NodeSystemQueryResponse::GetSectionElders(
                    elders,
                )),
                correlation_id: msg_id,
                id: MessageId::in_response_to(&msg_id), // MessageId::new(), //
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
            msg: ProcessMsg::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::StorageFull {
                    section: node_id.into(),
                    node_id,
                }),
                id: MessageId::new(),
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
            msg: ProcessMsg::NodeCmd {
                cmd: NodeCmd::System(NodeSystemCmd::RegisterWallet(self.node_info.reward_key)),
                id: MessageId::new(),
            },
            section_source: false, // sent as single node
            dst: DstLocation::Section(address),
            aggregation: Aggregation::None,
        }
    }

    /// Push our state to the given dst
    pub fn push_state(&self, prefix: Prefix, msg_id: MessageId) -> NodeDuty {
        let dst = DstLocation::Section(prefix.name());

        let user_wallets = if let Ok(elder) = &self.role.as_elder() {
            elder.transfers.user_wallets()
        } else {
            BTreeMap::new()
        };

        let node_rewards = if let Ok(elder) = &self.role.as_elder() {
            elder.section_funds.node_wallets()
        } else {
            BTreeMap::new()
        };

        // only push that what should be in dst
        let user_wallets = user_wallets
            .into_iter()
            .filter(|(key, _)| dst.contains(&XorName::from(*key), &prefix))
            .collect();
        let node_rewards = node_rewards
            .into_iter()
            .filter(|(name, _)| dst.contains(name, &prefix))
            .collect();

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
