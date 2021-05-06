// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    node::interaction::push_state,
    node_ops::NodeDuties,
    section_funds::{self, SectionFunds},
    transfers::get_replicas::replica_info,
    Error, Node, Result,
};
use dashmap::DashMap;
use log::debug;
use section_funds::{
    elder_signing::ElderSigning,
    reward_process::{OurSection, RewardProcess},
    reward_wallets::RewardWallets,
    Credits,
};
use sn_data_types::{NodeAge, PublicKey, Token};
use sn_messaging::MessageId;
use sn_routing::{Prefix, XorName};
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

        let elder = self.role.as_elder_mut()?;

        let process =
            RewardProcess::new(section, ElderSigning::new(self.network_api.clone()).await?);

        let wallets = RewardWallets::new(BTreeMap::<XorName, (NodeAge, PublicKey)>::new());

        elder.section_funds = SectionFunds::Churning {
            process,
            wallets,
            payments: DashMap::new(),
        };

        Ok(())
    }

    /// Called on split reported from routing layer.
    pub(crate) async fn begin_split_as_oldie(
        &mut self,
        our_prefix: Prefix,
        our_key: PublicKey,
        sibling_key: PublicKey,
    ) -> Result<NodeDuties> {
        let elder = self.role.as_elder_mut()?;

        let info = replica_info(&self.network_api).await?;
        elder.transfers.update_replica_info(info);

        let (wallets, payments) = match &mut elder.section_funds {
            SectionFunds::KeepingNodeWallets { wallets, payments }
            | SectionFunds::Churning {
                wallets, payments, ..
            } => (wallets.clone(), payments.sum()),
        };

        let sibling_prefix = our_prefix.sibling();

        debug!(
            "@@@@@@ SPLIT: Our prefix: {:?}, neighbour: {:?}",
            our_prefix, sibling_prefix,
        );
        debug!(
            "@@@@@@ SPLIT: Our key: {:?}, neighbour: {:?}",
            our_key, sibling_key
        );

        let mut ops = vec![];

        if payments > Token::zero() {
            let section_managed = elder.transfers.managed_amount().await?;

            // payments made since last churn
            debug!("Payments: {}", payments);
            // total amount in wallets
            debug!("Managed amount: {}", section_managed);

            // generate reward and minting proposal
            let mut process = RewardProcess::new(
                OurSection {
                    our_prefix,
                    our_key,
                },
                ElderSigning::new(self.network_api.clone()).await?,
            );

            ops.push(
                process
                    .reward_and_mint(payments, section_managed, wallets.node_wallets())
                    .await?,
            );

            elder.section_funds = SectionFunds::Churning {
                process,
                wallets: wallets.clone(),
                payments: DashMap::new(), // clear old payments
            };
        } else {
            debug!("Not paying out rewards, as no payments have been received since last split.");
        }

        // replicate state to our new elders
        let msg_id = MessageId::combine(vec![our_prefix.name(), XorName::from(our_key)]);
        ops.push(push_state(elder, our_prefix, msg_id).await?);

        // replicate state to our neighbour's new elders
        let msg_id = MessageId::combine(vec![sibling_prefix.name(), XorName::from(sibling_key)]);
        ops.push(push_state(elder, sibling_prefix, msg_id).await?);

        // drop metadata state
        elder
            .meta_data
            .retain_members_only(self.network_api.our_adults().await)
            .await?;

        // drop transfers state
        elder.transfers.keep_keys_of(our_prefix).await?;

        // drop reward wallets state
        elder.section_funds.keep_wallets_of(our_prefix);

        Ok(ops)
    }
}
