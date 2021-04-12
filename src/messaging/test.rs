// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_messaging::client::CostScheme;

use super::*;

#[test]
fn creates_group() -> Result<()> {
    // arrange
    let mut gpm = GPMessaging {
        groups: BTreeMap::new(),
    };
    let owner = EndUser::AllClients(get_random_pk());
    let mut msgs = BTreeMap::new();
    let _ = msgs.insert(
        0,
        MsgSettings {
            msg_type: 0,
            schema: None,
            cost_scheme: CostScheme::None,
            sent_to: AgentType::Either,
            sent_by: AgentType::Either,
        },
    );
    let group_name = "TestGroup".to_string();
    let cfg = GroupConfig::new(group_name, owner, msgs)?;
    let group_id = cfg.id();
    let cmd = GPMGroupCmd::SetOrCreate(cfg.clone());

    // act
    let duties = gpm.receive_cmd(group_id, cmd, owner, MessageId::new())?;

    // assert
    assert_eq!(duties.len(), 0);

    let query = GPMGroupQuery::GetConfig(group_id);
    let msg_id_1 = MessageId::new();
    let msg_id_2 = MessageId::in_response_to(&msg_id_1);

    let result = gpm.receive_query(query, owner, msg_id_1)?;

    match result {
        NodeDuty::Send(OutgoingMsg {
            msg:
                Message::QueryResponse {
                    response: QueryResponse::GetGroupConfig(Ok(result_cfg)),
                    id,
                    correlation_id,
                    target_section_pk,
                },
            section_source,
            dst: DstLocation::EndUser(enduser),
            aggregation,
        }) => {
            // cfg
            assert_eq!(cfg.id(), result_cfg.id());
            assert_eq!(cfg.name(), result_cfg.name());
            assert_eq!(cfg.owner(), result_cfg.owner());
            assert_eq!(cfg.get_settings(&0), result_cfg.get_settings(&0));
            // msg
            assert_eq!(id, msg_id_2);
            assert_eq!(correlation_id, msg_id_1);
            assert_eq!(section_source, true);
            assert_eq!(enduser, owner);
            assert_eq!(aggregation, Aggregation::AtDestination);

            Ok(())
        }
        _ => Err(Error::Logic("Failed test".to_string())),
    }
}

#[test]
fn enables_chat_implementation() -> Result<()> {
    // arrange
    let mut gpm = GPMessaging {
        groups: BTreeMap::new(),
    };
    let owner = EndUser::AllClients(get_random_pk());
    let mut msgs = BTreeMap::new();
    let _ = msgs.insert(
        0,
        MsgSettings {
            msg_type: 0,
            schema: None,
            cost_scheme: CostScheme::None,
            sent_to: AgentType::Either,
            sent_by: AgentType::Either,
        },
    );
    let group_name = "Chat".to_string();
    let cfg = GroupConfig::new(group_name, owner, msgs)?;
    let group_id = cfg.id();
    let cmd = GPMGroupCmd::SetOrCreate(cfg.clone());

    let _ = gpm.receive_cmd(group_id, cmd, owner, MessageId::new())?;

    // register users
    let cmd = GPMGroupCmd::Join(AgentType::Consumer);
    let sender_1 = EndUser::AllClients(get_random_pk());
    let _ = gpm.receive_cmd(group_id, cmd, sender_1, MessageId::new())?;

    let cmd = GPMGroupCmd::Join(AgentType::Consumer);
    let sender_2 = EndUser::AllClients(get_random_pk());
    let _ = gpm.receive_cmd(group_id, cmd, sender_2, MessageId::new())?;

    // send msg
    let original_msg = GPMMsg {
        msg_type: 0,
        group: group_id,
        payment: None,
        msg: format!("Hello {:?} from {:?}", sender_1, sender_2)
            .as_bytes()
            .to_vec(),
    };
    let cmd = GPMGroupCmd::Send {
        agent: 0,
        msg: original_msg.clone(),
    };
    let msg_id_1 = MessageId::new();
    let msg_id_2 = MessageId::in_response_to(&msg_id_1);
    let result = gpm.receive_cmd(group_id, cmd, sender_2, msg_id_1)?;

    // assert
    assert_eq!(result.len(), 1);

    match result.get(0).unwrap() {
        NodeDuty::Send(OutgoingMsg {
            msg:
                Message::Event {
                    event: Event::Messaging(MsgReceived { src, msg }),
                    id,
                    correlation_id,
                    target_section_pk,
                },
            section_source,
            dst: DstLocation::EndUser(enduser),
            aggregation,
        }) => {
            // payload
            assert_eq!(src, &group_id);
            assert_eq!(
                bincode::serialize(&msg)?,
                bincode::serialize(&original_msg)?
            );
            // msg
            assert_eq!(id, &msg_id_2);
            assert_eq!(correlation_id, &msg_id_1);
            assert_eq!(*section_source, true);
            assert_eq!(enduser, &sender_1);
            assert_eq!(aggregation, &Aggregation::AtDestination);

            Ok(())
        }
        _ => Err(Error::Logic("Failed test".to_string())),
    }
}

fn get_random_pk() -> PublicKey {
    PublicKey::from(bls::SecretKey::random().public_key())
}
