// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::ElderDuties;
use crate::{ElderState, Network, NodeInfo, Result};

use crate::{node::node_ops::NetworkDuties, Error};
use log::{debug, info};
use sn_data_types::PublicKey;
use sn_routing::Prefix;

// we want a consistent view of the elder constellation

// when we have an ElderChange, underlying sn_routing will
// return the new key set on querying (caveats in high churn?)
// but we want a snapshot of the state to work with, before we use the new keys

// so, to correctly transition between keys, we need to not mix states,
// and keep a tidy order, i.e. use one constellation at a time.

///
pub struct ElderConstellation {
    network: Network,
    duties: ElderDuties,
    pending_changes: Vec<ConstellationChange>,
}

struct ConstellationChange {
    prefix: Prefix,
    section_key: PublicKey,
}

impl ElderConstellation {
    ///
    pub fn new(duties: ElderDuties, network: Network) -> Self {
        Self {
            network,
            duties,
            pending_changes: vec![],
        }
    }

    ///
    pub fn duties(&mut self) -> &mut ElderDuties {
        &mut self.duties
    }

    ///
    pub async fn initiate_elder_change(
        &mut self,
        prefix: Prefix,
        new_section_key: PublicKey,
        sibling_key: Option<PublicKey>,
    ) -> Result<NetworkDuties> {
        let elder_state = self.duties.state();
        debug!(">> Prefix we have w/ elder change: {:?}", prefix);
        debug!(">> New section key w/ change {:?}", new_section_key);
        debug!(">> IS THERE A SIBLING KEY??? {:?}", sibling_key);

        if new_section_key == elder_state.section_public_key()
            || self
                .pending_changes
                .iter()
                .any(|c| c.section_key == new_section_key)
        {
            return Ok(vec![]);
        }

        info!(">>Elder change updates initiated");
        info!(
            ">>Pending changes len before {:?}",
            self.pending_changes.len()
        );
        self.pending_changes.push(ConstellationChange {
            section_key: new_section_key,
            prefix,
        });
        info!(
            ">>Pending changes len after {:?}",
            self.pending_changes.len()
        );

        // handle changes sequentially
        if self.pending_changes.len() > 1 {
            debug!(">> more changes so we return a vec?");
            return Ok(vec![]);
        }

        // 1. First we must update data section..
        // TODO: Query network for data corresponding to provided "new_section_key"!!!!
        // Otherwise there is no guarantee of not getting more recent info than expected!
        let new_elder_state = ElderState::new(self.network.clone()).await?;
        self.duties
            .initiate_elder_change(new_elder_state, sibling_key)
            .await
    }

    ///
    pub async fn complete_elder_change(
        &mut self,
        node_info: &NodeInfo,
        previous_key: PublicKey,
        new_key: PublicKey,
    ) -> Result<NetworkDuties> {
        debug!(">>>> Completing elder change!!");
        debug!(">>>>new key: {:?}", new_key);
        debug!(">>>> previous_key: {:?}", previous_key);

        if new_key == previous_key {
            debug!(">>>> !! same keys; IS AN error w/o the key transfer op.");
            return Err(Error::InvalidOperation(
                "new_key == previous_key".to_string(),
            ));
        }

        debug!(">>>> past the noops");

        let mut ops: NetworkDuties = Vec::new();
        // pop the pending change..
        // 2. We must load _current_ elder state..
        // TODO: Query network for data corresponding to provided "new_section_key"!!!!
        // Otherwise there is no guarantee of not getting more recent info than expected!
        let new_elder_state = ElderState::new(self.network.clone()).await?;
        // 3. And update key section with it.
        self.duties
            .complete_elder_change(node_info, new_elder_state.clone())
            .await?;

        debug!(">>>>Key section completed elder change update.");
        debug!(">>>>Elder change update completed.");

        if !self.pending_changes.is_empty() {
            // debug!(">>>>  !! no changes, so return here empty vec");
            // return Ok(vec![]);
            let old_elder_state = self.duties.state().clone();
            if old_elder_state.section_public_key() != previous_key
                || new_key != self.pending_changes[0].section_key
            {
                debug!(
                    ">>>> !!old state key is not same as prev. ??  {:?}, {:?}",
                    old_elder_state.section_public_key(),
                    previous_key
                );
                debug!(
                    ">>>> !! OR  new key isnt pending change {:?}, {:?}",
                    self.pending_changes[0].section_key, new_key
                );

                return Ok(vec![]);
            }
            // if ! self.pending_changes.is_empty() {
            let change = self.pending_changes.remove(0);

            // split section _after_ transition to new constellation
            if &change.prefix != old_elder_state.prefix() {
                info!(">>>>Split occurred");
                info!(">>>>New prefix is: {:?}", change.prefix);
                let duties = self.duties.split_section(change.prefix).await?;
                if !duties.is_empty() {
                    ops.extend(duties)
                };
            }
            // }
        }

        // if changes have queued up, make sure the queue is worked down
        if !self.pending_changes.is_empty() {
            let change = self.pending_changes.remove(0);
            debug!(">>Extending ops, NO sibling pk here... should there be?");
            ops.extend(
                self.initiate_elder_change(change.prefix, change.section_key, None)
                    .await?,
            );
        }

        Ok(ops)
    }
}
