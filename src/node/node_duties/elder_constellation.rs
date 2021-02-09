// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// we want a consistent view of the elder constellation

// when we have an ElderChange, underlying sn_routing will
// return the new key set on querying (caveats in high churn?)
// but we want a snapshot of the state to work with, before we use the new keys

// so, to correctly transition between keys, we need to not mix states,
// and keep a tidy order, i.e. use one constellation at a time.

// What things do we _need_ to snapshot?
// - Public/Secret KeySet
// - ..
// What things do we _need_ to access most current state of?
// - ..

use super::ElderDuties;
use crate::{ElderState, Network, NodeInfo, Result};

use crate::{node::node_ops::NodeOperation, Error};
use log::{debug, info};
use sn_data_types::PublicKey;
use sn_routing::Prefix;

///
pub struct ElderConstellation {
    info: NodeInfo,
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
    pub fn new(info: NodeInfo, duties: ElderDuties, network: Network) -> Self {
        Self {
            info,
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
    ) -> Result<NodeOperation> {
        info!(">>Elder change update called...");

        debug!(">> Prefix we have w/ elder change: {:?}", prefix);
        debug!(">> New section key w/ change {:?}", new_section_key);

        let elder_state = self.duties.state();

        if new_section_key == elder_state.section_public_key()
            || self
                .pending_changes
                .iter()
                .any(|c| c.section_key == new_section_key)
        {
            return Ok(NodeOperation::NoOp);
        }

        info!(">>Elder change updates initiated");

        let _ = self.pending_changes.push(ConstellationChange {
            section_key: new_section_key,
            prefix,
        });

        // handle changes sequentially
        if self.pending_changes.len() > 1 {
            return Ok(NodeOperation::NoOp);
        }

        // 1. First we must update data section..
        // TODO: Query network for data corresponding to provided "new_section_key"!!!!
        // Otherwise there is no guarantee of not getting more recent info than expected!
        let new_elder_state = ElderState::new(&self.info, self.network.clone()).await?;
        self.duties.initiate_elder_change(new_elder_state).await
        
    }

    ///
    pub async fn finish_elder_change(
        &mut self,
        previous_key: PublicKey,
        new_key: PublicKey,
    ) -> Result<NodeOperation> {
        debug!(">>>> Key section Finishing elder change.");
        debug!(">>new key: {:?}", new_key);
        debug!(">>previous_key: {:?}", previous_key);

        if new_key == previous_key {
            debug!(">> same keys; would have been an error w/o the key transfer op. but we dont have it");
            // return Err(Error::InvalidOperation);
        }
        if self.pending_changes.is_empty() {
            debug!(">> empty changes");

            return Ok(NodeOperation::NoOp);
        }
        let old_elder_state = self.duties.state().clone();
        if old_elder_state.section_public_key() != previous_key
            || new_key != self.pending_changes[0].section_key
        {
            debug!(">> old state and key mismatch");
            return Ok(NodeOperation::NoOp);
        }

        debug!(">> Finishing elder change, past noops");

        let mut ops = Vec::new();
        // pop the pending change..
        let change = self.pending_changes.remove(0);

        // 2. We must load _current_ elder state..
        // TODO: Query network for data corresponding to provided "new_section_key"!!!!
        // Otherwise there is no guarantee of not getting more recent info than expected!
        let new_elder_state = ElderState::new(&self.info, self.network.clone()).await?;
        // 3. And update key section with it.
        let _ = self
            .duties
            .finish_elder_change(new_elder_state.clone())
            .await?;

        debug!("Key section completed elder change update.");
        debug!("Elder change update completed.");
        debug!(">> Finishing split. Change prefix: {:?}", change.prefix);
        debug!(">> Finishing split. old state prefix: {:?}", old_elder_state.prefix());
        // split section _after_ transition to new constellation
        if &change.prefix != old_elder_state.prefix() {
            info!(">> Split occurred");
            info!(">>New prefix is: {:?}", change.prefix);
            match self.duties.split_section(change.prefix).await? {
                NodeOperation::NoOp => (),
                op => ops.push(op),
            };
        }

        // if changes have queued up, make sure the queue is worked down
        if !self.pending_changes.is_empty() {
            let change = self.pending_changes.remove(0);
            ops.push(
                self.initiate_elder_change(change.prefix, change.section_key)
                    .await?,
            );
        }

        Ok(ops.into())
    }
}
