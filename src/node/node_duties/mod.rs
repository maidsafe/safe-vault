// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod accumulation;
pub mod messaging;
mod msg_analysis;
mod network_events;

use crate::network::Routing;
use crate::node::{
    adult_duties::AdultDuties,
    elder_duties::ElderDuties,
    node_duties::messaging::Messaging,
    node_ops::{NodeDuty, NodeOperation},
    section_querying::SectionQuerying,
    state_db::NodeInfo,
};
use log::{info, warn};
use msg_analysis::NetworkMsgAnalysis;
use network_events::NetworkEvents;
use rand::{CryptoRng, Rng};
use std::{cell::Cell, rc::Rc};

#[allow(clippy::large_enum_variant)]
pub enum DutyLevel<R: CryptoRng + Rng, N: Routing + Clone> {
    Infant,
    Adult(AdultDuties<N>),
    Elder(ElderDuties<R, N>),
}

/// Node duties are those that all nodes
/// carry out. (TBD: adjust for Infant level, which might be doing nothing now).
/// Within the duty level, there are then additional
/// duties to be carried out, depending on the level.
pub struct NodeDuties<R: CryptoRng + Rng, N: Routing + Clone> {
    node_info: NodeInfo<N>,
    duty_level: DutyLevel<R, N>,
    network_events: NetworkEvents<N>,
    messaging: Messaging<N>,
    routing: N,
    rng: Option<R>,
}

impl<R: CryptoRng + Rng, N: Routing + Clone> NodeDuties<R, N> {
    pub fn new(node_info: NodeInfo<N>, routing: N, rng: R) -> Self {
        let network_events = NetworkEvents::new(NetworkMsgAnalysis::new(SectionQuerying::new(
            routing.clone(),
        )));
        let messaging = Messaging::new(routing.clone());
        Self {
            node_info,
            duty_level: DutyLevel::Infant,
            network_events,
            messaging,
            routing,
            rng: Some(rng),
        }
    }

    pub fn adult_duties(&mut self) -> Option<&mut AdultDuties<N>> {
        use DutyLevel::*;
        match &mut self.duty_level {
            Adult(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn elder_duties(&mut self) -> Option<&mut ElderDuties<R, N>> {
        use DutyLevel::*;
        match &mut self.duty_level {
            Elder(ref mut duties) => Some(duties),
            _ => None,
        }
    }

    pub fn process(&mut self, duty: NodeDuty) -> Option<NodeOperation> {
        use NodeDuty::*;
        info!("Processing: {:?}", duty);
        match duty {
            BecomeAdult => self.become_adult(),
            BecomeElder => self.become_elder(),
            ProcessMessaging(duty) => self.messaging.process(duty),
            ProcessNetworkEvent(event) => self.network_events.process(event),
        }
    }

    fn become_adult(&mut self) -> Option<NodeOperation> {
        use DutyLevel::*;
        let total_used_space = Rc::new(Cell::new(0));
        if let Ok(duties) = AdultDuties::new(self.node_info.clone(), &total_used_space) {
            self.duty_level = Adult(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Adult, self.node_info.path(), &self.id).unwrap_or(());
        }
        None
    }

    fn become_elder(&mut self) -> Option<NodeOperation> {
        use DutyLevel::*;
        let total_used_space = Rc::new(Cell::new(0));
        info!("Attempting to assume Elder duties..");
        if matches!(self.duty_level, Elder(_)) {
            return None;
        }
        if let Ok(duties) = ElderDuties::new(
            self.node_info.clone(),
            &total_used_space,
            self.routing.clone(),
            self.rng.take()?,
        ) {
            let mut duties = duties;
            let op = duties.initiate();
            self.duty_level = Elder(duties);
            // NB: This is wrong, shouldn't write to disk here,
            // let it be upper layer resp.
            // Also, "Error-to-Unit" is not a good conversion..
            //dump_state(AgeGroup::Elder, self.node_info.path(), &self.id).unwrap_or(())
            info!("Successfully assumed Elder duties!");
            op
        } else {
            warn!("Was not able to assume Elder duties!");
            None
        }
    }
}
