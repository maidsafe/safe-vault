// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    chunks::Chunks,
    metadata::CHUNK_COPY_COUNT,
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
};
use itertools::Itertools;
use log::{info, trace, warn};
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
}

impl AdultRole {
    pub async fn reorganize_chunks(
        &mut self,
        our_name: XorName,
        new_adults: BTreeSet<XorName>,
        lost_adults: BTreeSet<XorName>,
        remaining: BTreeSet<XorName>,
    ) -> NodeDuties {
        let keys = self.chunks.keys();
        let mut ops = vec![];
        for addr in keys.iter() {
            if let Some(operation) = self
                .republish_and_cache(addr, &our_name, &new_adults, &lost_adults, &remaining)
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
        remaining: &BTreeSet<XorName>,
    ) -> Option<NodeDuty> {
        let old_adult_list = remaining.union(lost_adults).copied().collect();
        let new_adult_list = remaining.union(new_adults).copied().collect();
        let new_holders = self.compute_holders(addr, &new_adult_list);
        let old_holders = self.compute_holders(addr, &old_adult_list);

        let we_are_not_holder_anymore = !new_holders.contains(our_name);
        let new_adult_is_holder = !new_holders.is_disjoint(new_adults);
        let lost_old_holder = !old_holders.is_disjoint(lost_adults);

        if we_are_not_holder_anymore || new_adult_is_holder || lost_old_holder {
            let id = MessageId::new();
            info!("Republishing chunk at {:?} with MessageId {:?}", addr, id);
            trace!("We are not a holder anymore? {}, New Adult is Holder? {}, Lost Adult was holder? {}", we_are_not_holder_anymore, new_adult_is_holder, lost_old_holder);
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
            .take(CHUNK_COPY_COUNT)
            .cloned()
            .collect()
    }
}
