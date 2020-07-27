// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::utils;
use log::{error, info};
use safe_nd::{BlsProof, MessageId, MsgEnvelope, MsgSender, Proof, SignatureShare};
use std::collections::{hash_map::Entry, HashMap, HashSet};

type RequestInfo = (MsgEnvelope, MsgSender, Vec<SignatureShare>);
//type DuplicationInfo = (BlobAddress, BTreeSet<XorName>, Vec<SignatureShare>);

pub struct Accumulation {
    messages: HashMap<MessageId, RequestInfo>,
    completed: HashSet<MessageId>,
}

impl Accumulation {
    pub fn new() -> Self {
        Self {
            messages: Default::default(),
            completed: Default::default(),
        }
    }

    pub(crate) fn process(&mut self, msg: &MsgEnvelope) -> Option<MsgEnvelope> {
        if self.completed.contains(&msg.id()) {
            info!("Message already processed.");
            return None;
        }
        let signature = match msg.most_recent_sender() {
            MsgSender::Node {
                proof: Proof::BlsShare(share),
                ..
            } => SignatureShare {
                index: share.index,
                share: share.signature_share.clone(),
            },
            MsgSender::Section { .. } => return Some(msg.clone()), // already group signed, no need to accumulate (check sig though?, or somewhere else, earlier on?)
            _ => return None,                                      // no other variation is valid
        };
        info!(
            "{}: Accumulating signatures for {:?}",
            "should be id here",
            //&id,
            msg.id()
        );
        match self.messages.entry(msg.id()) {
            Entry::Vacant(entry) => {
                let _ = entry.insert((msg.clone(), msg.origin.clone(), vec![signature]));
            }
            Entry::Occupied(mut entry) => {
                let (_, _, signatures) = entry.get_mut();
                signatures.push(signature);
            }
        }
        self.try_aggregate(msg)
    }

    fn try_aggregate(&mut self, msg: &MsgEnvelope) -> Option<MsgEnvelope> {
        let msg_id = msg.id();
        let (_, _, signatures) = self.messages.get(&msg_id)?;

        let public_key_set = match msg.most_recent_sender() {
            MsgSender::Node {
                proof: Proof::BlsShare(share),
                ..
            } => &share.public_key_set,
            _ => return None,
        };

        info!(
            "Got {} signatures. We need {}",
            signatures.len(),
            public_key_set.threshold() + 1
        );
        if public_key_set.threshold() >= signatures.len() {
            return None;
        }

        let (msg, _sender, signatures) = self.messages.remove(&msg_id)?;
        let signed_data = utils::serialise(&msg);
        for sig in &signatures {
            if !public_key_set
                .public_key_share(sig.index)
                .verify(&sig.share, &signed_data)
            {
                error!("Invalid signature share");
                // should not just return, instead:
                // remove the faulty sig, then insert
                // the rest back into messages.
                // One bad egg can't be allowed to ruin it all.
                return None;
            }
        }
        let signature = public_key_set
            .combine_signatures(signatures.iter().map(|sig| (sig.index, &sig.share)))
            .ok()?;
        if public_key_set.public_key().verify(&signature, &signed_data) {
            let _ = self.completed.insert(msg_id);

            let proof = BlsProof {
                public_key: public_key_set.public_key(),
                signature,
            };

            // upgrade sender to Section, since it accumulated
            let sender = match msg.most_recent_sender() {
                MsgSender::Node { duty, .. } => MsgSender::Section { duty: *duty, proof },
                _ => return None, // invalid use case, we only accumulate from Nodes
            };
            // Replace the Node with the Section.
            let mut msg = msg;
            let _ = msg.proxies.pop();
            Some(msg.with_proxy(sender))
        // beware that we might have to forgo the proxies vector
        // and instead just have a most recent proxy, if we are seeing
        // different order on the proxies on the msgs to be accumulated
        // (otherwise, the signature won't aggregate, since it is not over the same data)
        // perhaps it can be solved by ordering the vec, but maybe that defeats
        // part of the purpose; to see the path.
        } else {
            error!("Accumulated signature is invalid");
            None
        }
    }
}
