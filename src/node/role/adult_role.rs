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
use sn_data_types::{Blob, BlobAddress};
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
        let mut data_for_replication = BTreeSet::new();
        for addr in keys.iter() {
            if let Some(data) = self
                .republish_and_cache(addr, &our_name, &new_adults, &lost_adults, &remaining)
                .await
            {
                let _ = data_for_replication.insert(data);
            }
        }
        data_for_replication
            .into_iter()
            .map(|data| {
                let data_name = *data.name();
                NodeDuty::Send(OutgoingMsg {
                    msg: Message::NodeCmd {
                        cmd: NodeCmd::System(NodeSystemCmd::RepublishChunk(data)),
                        id: MessageId::new(),
                    },
                    dst: DstLocation::Section(data_name),
                    section_source: false,
                    aggregation: Aggregation::None,
                })
            })
            .collect::<Vec<_>>()
    }

    async fn republish_and_cache(
        &mut self,
        addr: &BlobAddress,
        our_name: &XorName,
        new_adults: &BTreeSet<XorName>,
        lost_adults: &BTreeSet<XorName>,
        remaining: &BTreeSet<XorName>,
    ) -> Option<Blob> {
        let old_adult_list = remaining.union(lost_adults).copied().collect();
        let new_adult_list = remaining.union(new_adults).copied().collect();
        let new_holders = self.compute_holders(addr, &new_adult_list);
        let old_holders = self.compute_holders(addr, &old_adult_list);

        let we_are_not_holder_anymore = !new_holders.contains(our_name);
        let new_adult_is_holder = !new_holders.is_disjoint(new_adults);
        let lost_old_holder = !old_holders.is_disjoint(lost_adults);

        if we_are_not_holder_anymore || new_adult_is_holder || lost_old_holder {
            info!("Republishing chunk at {:?}", addr);
            trace!("We are not a holder anymore? {}, New Adult is Holder? {}, Lost Adult was holder? {}", we_are_not_holder_anymore, new_adult_is_holder, lost_old_holder);
            let chunk = self.chunks.get_chunk(addr).ok()?;
            if we_are_not_holder_anymore {
                if let Err(err) = self.chunks.remove_chunk(addr).await {
                    warn!("Error deleting chunk during republish: {:?}", err);
                }
            }
            // TODO: Push to LRU cache
            Some(chunk)
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
