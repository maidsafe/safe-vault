// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunks::Chunks,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
};
use itertools::Itertools;
use log::{info, warn};
use sn_data_types::BlobAddress;
use sn_messaging::{
    client::{Message, NodeCmd, NodeSystemCmd},
    Aggregation, DstLocation, MessageId,
};
use sn_routing::XorName;
use std::collections::BTreeSet;

pub(crate) struct AdultRole {
    // immutable chunks
    pub chunks: Chunks,
    // Adult list
    pub adult_list: BTreeSet<XorName>,
}

impl AdultRole {
    pub async fn handle_adults_changed(
        &mut self,
        new_adult_list: BTreeSet<XorName>,
        our_name: XorName,
    ) -> NodeDuties {
        let new_adults = new_adult_list
            .difference(&self.adult_list)
            .cloned()
            .collect::<BTreeSet<_>>();
        let lost_adults = self
            .adult_list
            .difference(&new_adult_list)
            .cloned()
            .collect::<BTreeSet<_>>();
        let old_adult_list = std::mem::replace(&mut self.adult_list, new_adult_list);
        self.reorganize_chunks(our_name, new_adults, lost_adults, old_adult_list)
            .await
    }

    async fn reorganize_chunks(
        &mut self,
        our_name: XorName,
        new_adults: BTreeSet<XorName>,
        lost_adults: BTreeSet<XorName>,
        old_adult_list: BTreeSet<XorName>,
    ) -> NodeDuties {
        let keys = self.chunks.keys();
        let mut ops = vec![];
        for addr in keys.iter() {
            if let Some(operation) = self
                .republish_and_cache(addr, &our_name, &new_adults, &lost_adults, &old_adult_list)
                .await
            {
                ops.push(operation);
            }
        }
        ops
    }

    async fn republish_and_cache(
        &mut self,
        addr: &BlobAddress,
        our_name: &XorName,
        new_adults: &BTreeSet<XorName>,
        lost_adults: &BTreeSet<XorName>,
        old_adult_list: &BTreeSet<XorName>,
    ) -> Option<NodeDuty> {
        let new_holders = self.compute_holders(addr, &self.adult_list);
        let old_holders = self.compute_holders(addr, old_adult_list);

        let we_are_not_holder_anymore = !new_holders.contains(our_name);
        let new_adult_is_holder = !new_holders.is_disjoint(new_adults);
        let lost_old_holder = !old_holders.is_disjoint(lost_adults);

        if we_are_not_holder_anymore || new_adult_is_holder || lost_old_holder {
            let id = MessageId::new();
            info!("Republishing chunk at {:?} with MessageId {:?}", addr, id);
            info!("We are not a holder anymore? {}, New Adult is Holder? {}, Lost Adult was holder? {}", we_are_not_holder_anymore, new_adult_is_holder, lost_old_holder);
            let chunk = self.chunks.get_chunk(addr).ok()?;
            if we_are_not_holder_anymore {
                if let Err(err) = self.chunks.remove_chunk(addr).await {
                    warn!("Error deleting chunk during republish: {:?}", err);
                }
            }
            // TODO: Push to LRU cache
            Some(NodeDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::RepublishChunk(chunk)),
                    id,
                },
                dst: DstLocation::Section(*addr.name()),
                section_source: false,
                aggregation: Aggregation::None,
            }))
        } else {
            None
        }
    }

    fn compute_holders(
        &self,
        addr: &BlobAddress,
        adult_list: &BTreeSet<XorName>,
    ) -> BTreeSet<XorName> {
        adult_list
            .iter()
            .sorted_by(|lhs, rhs| addr.name().cmp_distance(lhs, rhs))
            .cloned()
            .collect()
    }
}
