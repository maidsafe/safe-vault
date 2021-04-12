// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
mod test;

use crate::{
    node_ops::{NodeDuties, NodeDuty, OutgoingMsg},
    Error, Result,
};
use bytes::Bytes;
use serde::Serialize;
use sn_data_types::{CreditAgreementProof as CreditProof, PublicKey, Signature, Token};
use sn_messaging::{
    client::{
        AgentId, AgentType, ClientId, Event, GPMGroupCmd, GPMGroupQuery, GPMMsg, GroupConfig,
        GroupId, Message, MsgReceived, MsgSettings, QueryResponse,
    },
    Aggregation, DstLocation, EndUser, MessageId, SrcLocation,
};
use sn_routing::XorName;
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub struct Group {
    cfg: GroupConfig,
    producers: BTreeMap<AgentId, EndUser>,
    consumers: BTreeMap<AgentId, EndUser>,
    client_to_agent_map: BTreeMap<ClientId, AgentId>,
    agent_to_client_map: BTreeMap<AgentId, ClientId>,
}

/// General Purpose Messaging
pub struct GPMessaging {
    groups: BTreeMap<GroupId, Group>,
}

impl GPMessaging {
    pub fn receive_query(
        &mut self,
        query: GPMGroupQuery,
        origin: EndUser,
        msg_id: MessageId,
    ) -> Result<NodeDuty> {
        use GPMGroupQuery::*;
        match query {
            GetConfig(group_id) => {
                let result = match self.groups.get(&group_id) {
                    Some(group) => Ok(group.cfg.clone()),
                    None => return Err(Error::Logic("No such group.".to_string())),
                };
                Ok(NodeDuty::Send(OutgoingMsg {
                    msg: Message::QueryResponse {
                        response: QueryResponse::GetGroupConfig(result),
                        id: MessageId::in_response_to(&msg_id),
                        correlation_id: msg_id,
                        target_section_pk: None,
                    },
                    section_source: true,
                    dst: DstLocation::EndUser(origin),
                    aggregation: Aggregation::AtDestination,
                }))
            }
        }
    }

    pub fn receive_cmd(
        &mut self,
        group_id: GroupId,
        cmd: GPMGroupCmd,
        origin: EndUser,
        msg_id: MessageId,
    ) -> Result<NodeDuties> {
        //let sender = signed_msg.src;
        // if signed_msg
        //     .src
        //     .id()
        //     .verify(&signed_msg.sig, bincode::serialize(&msg).ok()?)
        //     .is_err()
        // {
        //     return None;
        // }

        use GPMGroupCmd::*;
        match cmd {
            SetOrCreate(cfg) => self.set_or_create(group_id, cfg, origin),
            Join(agent_type) => self.join(group_id, agent_type, origin),
            Leave(agent_type) => self.leave(group_id, agent_type, origin),
            Send { agent, msg } => self.send(group_id, agent, msg, origin, msg_id),
            SendToAll(msg) => self.send_to_all(group_id, msg, origin, msg_id),
            Block { agent, agent_type } => Ok(vec![]),
            BlockAll(agent_type) => Ok(vec![]),
        }
    }

    fn set_or_create(
        &mut self,
        group_id: GroupId,
        cfg: GroupConfig,
        origin: EndUser,
    ) -> Result<NodeDuties> {
        if group_id != cfg.id() {
            return Err(Error::InvalidOperation(
                "The config does not belong to the group with the provided id.".to_string(),
            ));
        }
        match self.groups.get_mut(&cfg.id()) {
            Some(group) => {
                if group.cfg.owner() == &origin {
                    group.cfg = cfg;
                } else {
                    return Err(Error::InvalidOwners(*cfg.owner().id()));
                }
            }
            None => {
                let _ = self.groups.insert(
                    cfg.id(),
                    Group {
                        cfg,
                        producers: BTreeMap::new(),
                        consumers: BTreeMap::new(),
                        client_to_agent_map: BTreeMap::new(),
                        agent_to_client_map: BTreeMap::new(),
                    },
                );
            }
        }
        Ok(vec![])
    }

    fn join(
        &mut self,
        group_id: GroupId,
        agent_type: AgentType,
        origin: EndUser,
    ) -> Result<NodeDuties> {
        let group = match self.groups.get_mut(&group_id) {
            Some(group) => group,
            None => return Err(Error::Logic("No such group.".to_string())),
        };
        let agent_id = group.agent_to_client_map.len() as u64;
        let _ = group.client_to_agent_map.insert(origin.name(), agent_id);
        let _ = group.agent_to_client_map.insert(agent_id, origin.name());
        match agent_type {
            AgentType::Both => {
                let _ = group.consumers.insert(agent_id, origin);
                let _ = group.producers.insert(agent_id, origin);
            }
            AgentType::Consumer => {
                let _ = group.consumers.insert(agent_id, origin);
            }
            AgentType::Producer => {
                let _ = group.producers.insert(agent_id, origin);
            }
            AgentType::Either => {
                return Err(Error::Logic("Must choose a type (or both).".to_string()))
            }
        }
        Ok(vec![])
    }

    fn leave(
        &mut self,
        group_id: GroupId,
        agent_type: AgentType,
        origin: EndUser,
    ) -> Result<NodeDuties> {
        let group = match self.groups.get_mut(&group_id) {
            Some(group) => group,
            None => return Err(Error::Logic("No such group.".to_string())),
        };
        let agent_id = match group.client_to_agent_map.remove(&origin.name()) {
            Some(id) => id,
            None => return Err(Error::Logic("Origin is not part of the group.".to_string())),
        };
        let _ = group.agent_to_client_map.remove(&agent_id);
        match agent_type {
            AgentType::Both => {
                let _ = group.consumers.remove(&agent_id);
                let _ = group.producers.remove(&agent_id);
            }
            AgentType::Consumer => {
                let _ = group.consumers.remove(&agent_id);
            }
            AgentType::Producer => {
                let _ = group.producers.remove(&agent_id);
            }
            AgentType::Either => {
                return Err(Error::Logic("Must choose a type (or both).".to_string()))
            }
        }
        Ok(vec![])
    }

    fn send(
        &self,
        group_id: GroupId,
        agent: u64,
        msg: GPMMsg,
        origin: EndUser,
        msg_id: MessageId,
    ) -> Result<NodeDuties> {
        let group = match self.groups.get(&group_id) {
            Some(group) => group,
            None => return Err(Error::Logic("No such group.".to_string())),
        };
        let sender_agent = match group.client_to_agent_map.get(&origin.name()) {
            Some(id) => id,
            None => return Err(Error::Logic("Origin is not part of the group.".to_string())),
        };
        // validate msg
        match group.cfg.get_settings(&msg.msg_type) {
            Some(settings) => {
                if !self.valid_agent(sender_agent, &settings.sent_by, group) {
                    return Err(Error::Logic(
                        "This msg type cannot be sent by the origin.".to_string(),
                    ));
                }
                if !self.valid_agent(&agent, &settings.sent_to, group) {
                    return Err(Error::Logic(
                        "This msg type cannot be sent to the recipient.".to_string(),
                    ));
                }
            }
            // unknown msg type
            None => return Err(Error::Logic("No such msg type in this group.".to_string())),
        };
        let enduser = match self.get_enduser(&agent, group) {
            Some(user) => user,
            None => return Err(Error::Logic("No such recipient in this group.".to_string())),
        };
        Ok(vec![NodeDuty::Send(OutgoingMsg {
            msg: Message::Event {
                event: Event::Messaging(MsgReceived { src: group_id, msg }),
                id: MessageId::in_response_to(&msg_id),
                correlation_id: msg_id,
                target_section_pk: None,
            },
            section_source: true,
            dst: DstLocation::EndUser(enduser),
            aggregation: Aggregation::AtDestination,
        })])
    }

    fn send_to_all(
        &self,
        group_id: GroupId,
        msg: GPMMsg,
        origin: EndUser,
        msg_id: MessageId,
    ) -> Result<NodeDuties> {
        let group = match self.groups.get(&group_id) {
            Some(group) => group,
            None => return Err(Error::Logic("No such group.".to_string())),
        };
        let sender_agent = match group.client_to_agent_map.get(&origin.name()) {
            Some(id) => id,
            None => return Err(Error::Logic("Origin is not part of the group.".to_string())),
        };
        // validate msg
        let recipient_type = match group.cfg.get_settings(&msg.msg_type) {
            Some(settings) => {
                if !self.valid_agent(sender_agent, &settings.sent_by, group) {
                    return Err(Error::Logic(
                        "This msg type cannot be sent by the origin.".to_string(),
                    ));
                }
                &settings.sent_to
            }
            // unknown msg type
            None => return Err(Error::Logic("No such msg type in this group.".to_string())),
        };
        let endusers = self.get_endusers(recipient_type, group);
        Ok(endusers
            .into_iter()
            .map(|enduser| {
                NodeDuty::Send(OutgoingMsg {
                    msg: Message::Event {
                        event: Event::Messaging(MsgReceived {
                            src: group_id,
                            msg: msg.clone(),
                        }),
                        id: MessageId::combine(vec![msg_id.0, enduser.name()]),
                        correlation_id: msg_id,
                        target_section_pk: None,
                    },
                    section_source: true,
                    dst: DstLocation::EndUser(enduser),
                    aggregation: Aggregation::AtDestination,
                })
            })
            .collect())
    }

    fn get_endusers(&self, agent_type: &AgentType, group: &Group) -> HashSet<EndUser> {
        match agent_type {
            AgentType::Both => {
                let consumers: HashSet<&EndUser> = group.consumers.values().collect();
                let producers: HashSet<&EndUser> = group.producers.values().collect();

                consumers.intersection(&producers).map(|e| **e).collect()
            }
            AgentType::Either => {
                let consumers: HashSet<&EndUser> = group.consumers.values().collect();
                let producers: HashSet<&EndUser> = group.producers.values().collect();

                consumers.union(&producers).map(|e| **e).collect()
            }
            AgentType::Consumer => group.consumers.values().copied().collect(),
            AgentType::Producer => group.producers.values().copied().collect(),
        }
    }

    fn valid_agent(&self, agent: &u64, required_type: &AgentType, group: &Group) -> bool {
        match required_type {
            AgentType::Both => {
                group.consumers.contains_key(agent) && group.producers.contains_key(agent)
            }
            AgentType::Either => {
                group.consumers.contains_key(agent) || group.producers.contains_key(agent)
            }
            AgentType::Consumer => group.consumers.contains_key(agent),
            AgentType::Producer => group.producers.contains_key(agent),
        }
    }

    fn get_enduser(&self, agent: &u64, group: &Group) -> Option<EndUser> {
        let res_1 = group.consumers.get(agent);
        let res = if res_1.is_some() {
            res_1
        } else {
            group.producers.get(agent)
        };
        res.map(|c| c.to_owned())
    }
}
