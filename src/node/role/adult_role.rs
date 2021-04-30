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
        new_adults: BTreeSet<XorName>,
        our_name: XorName,
    ) -> NodeDuties {
        let _adults_added = new_adults
            .difference(&self.adult_list)
            .collect::<BTreeSet<_>>();
        let _adults_removed = self
            .adult_list
            .difference(&new_adults)
            .collect::<BTreeSet<_>>();
        self.adult_list = new_adults;
        self.reorganize_chunks(our_name).await
    }

    async fn reorganize_chunks(&mut self, our_name: XorName) -> NodeDuties {
        let keys = self.chunks.keys();
        let mut ops = vec![];
        for addr in keys.iter() {
            if let Some(operation) = self.republish_and_cache(addr, &our_name).await {
                ops.push(operation);
            }
        }
        ops
    }

    async fn republish_and_cache(
        &mut self,
        addr: &BlobAddress,
        our_name: &XorName,
    ) -> Option<NodeDuty> {
        let holders = self.compute_new_holders(addr);
        if !holders.contains(our_name) {
            let chunk = self.chunks.remove_chunk(addr).await.ok()?;
            // TODO: Push to LRU cache
            Some(NodeDuty::Send(OutgoingMsg {
                msg: Message::NodeCmd {
                    cmd: NodeCmd::System(NodeSystemCmd::RepublishChunk(chunk)),
                    id: MessageId::new(),
                },
                dst: DstLocation::Section(*addr.name()),
                section_source: false,
                aggregation: Aggregation::None,
            }))
        } else {
            None
        }
    }

    fn compute_new_holders(&self, addr: &BlobAddress) -> BTreeSet<&XorName> {
        self.adult_list
            .iter()
            .sorted_by(|lhs, rhs| addr.name().cmp_distance(lhs, rhs))
            .collect()
    }
}
