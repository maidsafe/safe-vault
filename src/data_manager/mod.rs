// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![allow(dead_code)]

mod database;

use std::cmp;
use cbor;
use cbor::Decoder;
use rustc_serialize::Encodable;

use maidsafe_types::data_tags;
use routing::{closer_to_target, NameType};
use routing::error::{InterfaceError, ResponseError};
use routing::node_interface::MethodCall;
use routing::sendable::Sendable;
use routing::types::{GROUP_SIZE, MessageAction};

use data_parser::Data;
use transfer_parser::transfer_tags::DATA_MANAGER_STATS_TAG;
use utils::median;

type Address = NameType;

pub use self::database::DataManagerSendable;

pub static PARALLELISM: usize = 4;

pub struct DataManager {
  db_ : database::DataManagerDatabase,
  // the higher the index is, the slower the farming rate will be
  resource_index : u64
}

#[derive(RustcEncodable, RustcDecodable, Clone, PartialEq, Eq, Debug)]
pub struct DataManagerStatsSendable {
    name: NameType,
    resource_index: u64
}

impl DataManagerStatsSendable {
    pub fn new(name: NameType, resource_index: u64) -> DataManagerStatsSendable {
        DataManagerStatsSendable {
            name: name,
            resource_index: resource_index
        }
    }

    pub fn get_resource_index(&self) -> u64 {
        self.resource_index
    }
}

impl Sendable for DataManagerStatsSendable {
    fn name(&self) -> NameType {
        self.name.clone()
    }

    fn type_tag(&self) -> u64 {
        DATA_MANAGER_STATS_TAG
    }

    fn serialised_contents(&self) -> Vec<u8> {
        let mut e = cbor::Encoder::from_memory();
        e.encode(&[&self]).unwrap();
        e.into_bytes()
    }

    fn refresh(&self)->bool {
        true
    }

    fn merge(&self, responses: Vec<Box<Sendable>>) -> Option<Box<Sendable>> {
        let mut resource_indexes: Vec<u64> = Vec::new();
        for value in responses {
            let mut d = cbor::Decoder::from_bytes(value.serialised_contents());
            let tmp_senderable: DataManagerStatsSendable = d.decode().next().unwrap().unwrap();
            resource_indexes.push(tmp_senderable.get_resource_index());
        }
        assert!(resource_indexes.len() < (GROUP_SIZE + 1) / 2);
        Some(Box::new(DataManagerStatsSendable::new(NameType([0u8; 64]),
                                                    median(&resource_indexes))))
    }
}



impl DataManager {
  pub fn new() -> DataManager {
    DataManager { db_: database::DataManagerDatabase::new(), resource_index: 1 }
  }

  pub fn handle_get(&mut self, name : &NameType) ->Result<MessageAction, InterfaceError> {
	  let result = self.db_.get_pmid_nodes(name);
	  if result.len() == 0 {
	    return Err(From::from(ResponseError::NoData));
	  }

	  let mut dest_pmids : Vec<NameType> = Vec::new();
	  for pmid in result.iter() {
        dest_pmids.push(pmid.clone());
	  }
	  Ok(MessageAction::SendOn(dest_pmids))
  }

  pub fn handle_put<Data: Sendable>(&mut self, data: Data, nodes_in_table: &mut Vec<NameType>)
          -> Result<MessageAction, InterfaceError> {
    let data_name = data.name();
    if self.db_.exist(&data_name) {
      return Err(InterfaceError::Abort);
    }

    nodes_in_table.sort_by(|a, b|
        if closer_to_target(&a, &b, &data_name) {
          cmp::Ordering::Less
        } else {
          cmp::Ordering::Greater
        });
    let pmid_nodes_num = cmp::min(nodes_in_table.len(), PARALLELISM);
    let mut dest_pmids: Vec<NameType> = Vec::new();
    for index in 0..pmid_nodes_num {
      dest_pmids.push(nodes_in_table[index].clone());
    }
    self.db_.put_pmid_nodes(&data_name, dest_pmids.clone());
    if data.type_tag() == data_tags::IMMUTABLE_DATA_SACRIFICIAL_TAG {
      self.resource_index = cmp::min(1048576, self.resource_index + dest_pmids.len() as u64);
    }
    Ok(MessageAction::SendOn(dest_pmids))
  }

  pub fn handle_get_response(&mut self, response: Vec<u8>) -> MethodCall {
      let mut name: NameType;
      let mut decoder = Decoder::from_bytes(&response[..]);
      if let Some(parsed_data) = decoder.decode().next().and_then(|result| result.ok()) {
          match parsed_data {
              Data::Immutable(parsed) => name = parsed.name(),
              Data::PublicMaid(parsed) => name = parsed.name(),
              _ => return MethodCall::None,
          }
      } else {
          return MethodCall::None;
      }

      let replicate_to = self.replicate_to(&name);
      match replicate_to {
          Some(pmid_node) => {
              self.db_.add_pmid_node(&name, pmid_node.clone());
              return MethodCall::Put {
                  destination: pmid_node,
                  content: Box::new(DataManagerSendable::with_content(name, response)),
              };
          },
          None => {}
      }
      MethodCall::None
  }

  pub fn handle_put_response(&mut self, response: &Result<Vec<u8>, ResponseError>,
                             from_address: &NameType) -> MethodCall {
    // TODO: assumption is the content in Result is the full payload of failed to store data
    //       or the removed Sacrificial copy, which indicates as a failure response.
    if response.is_err() {
      return MethodCall::None;
    }
    let data = response.clone().unwrap();
    let mut decoder = Decoder::from_bytes(&data[..]);
    let mut name: NameType;
    let mut replicate = false;
    if let Some(parsed_data) = decoder.decode().next().and_then(|result| result.ok()) {
      match parsed_data {
        Data::Immutable(parsed) => {
          name = parsed.name();
          replicate = true;
        },
        Data::ImmutableBackup(parsed) => name = parsed.name(),
        Data::ImmutableSacrificial(parsed) => {
          name = parsed.name();
          self.resource_index = cmp::max(1, self.resource_index - 1);
        },
        Data::PublicMaid(parsed) => {
          name = parsed.name();
          replicate = true;
        },
        _ => return MethodCall::None,
      }
    } else {
      return MethodCall::None;
    }

    self.db_.remove_pmid_node(&name, from_address.clone());

    // No replication for Backup and Sacrificial copies.
    if !replicate {
      return MethodCall::None;
    }

    let replicate_to = self.replicate_to(&name);
    match replicate_to {
        Some(pmid_node) => {
            self.db_.add_pmid_node(&name, pmid_node.clone());
            return MethodCall::Put {
                destination: pmid_node,
                content: Box::new(DataManagerSendable::with_content(name, data)),
            };
        },
        None => {}
    }
    MethodCall::None
  }

  pub fn handle_account_transfer(&mut self, merged_account: DataManagerSendable) {
      self.db_.handle_account_transfer(&merged_account);
  }

  pub fn handle_stats_transfer(&mut self, merged_stats: DataManagerStatsSendable) {
      // TODO: shall give more priority to the incoming stats?
      self.resource_index = (self.resource_index + merged_stats.get_resource_index()) / 2;
  }

  pub fn retrieve_all_and_reset(&mut self, close_group: &mut Vec<NameType>) -> Vec<MethodCall> {
      // TODO: as Vault doesn't have access to what ID it is, we have to use the first one in the
      //       close group as its ID
      let mut result = self.db_.retrieve_all_and_reset(close_group);
      let data_manager_stats_sendable =
          DataManagerStatsSendable::new(close_group[0].clone(), self.resource_index);
      let mut encoder = cbor::Encoder::from_memory();
      if encoder.encode(&[data_manager_stats_sendable]).is_ok() {
          result.push(MethodCall::Refresh {
              type_tag: DATA_MANAGER_STATS_TAG, from_group: data_manager_stats_sendable.name(),
              payload: encoder.as_bytes().to_vec()
          });
      }
      result
  }

  fn replicate_to(&mut self, name : &NameType) -> Option<NameType> {
      match self.db_.temp_storage_after_churn.get(name) {
          Some(pmid_nodes) => {
              if pmid_nodes.len() < 3 {
                  self.db_.close_grp_from_churn.sort_by(|a, b| {
                      if closer_to_target(&a, &b, &name) {
                        cmp::Ordering::Less
                      } else {
                        cmp::Ordering::Greater
                      }
                  });
                  let mut close_grp_node_to_add = NameType::new([0u8; 64]);
                  for close_grp_it in self.db_.close_grp_from_churn.iter() {
                      if pmid_nodes.iter().find(|a| **a == *close_grp_it).is_none() {
                          close_grp_node_to_add = close_grp_it.clone();
                          break;
                      }
                  }
                  return Some(close_grp_node_to_add);
              }
          },
          None => {}
      }
      None
  }

}

#[cfg(test)]
mod test {
  extern crate cbor;
  extern crate maidsafe_types;
  extern crate routing;

  use super::{DataManager, DataManagerStatsSendable};
  use super::database::DataManagerSendable;
  use maidsafe_types::{ImmutableData, PayloadTypeTag, Payload};
  use routing::types::{MessageAction, array_as_vector};
  use routing::NameType;
  use routing::sendable::Sendable;

  #[test]
  fn handle_put_get() {
    let mut data_manager = DataManager::new();
    let value = routing::types::generate_random_vec_u8(1024);
    let data = ImmutableData::new(value);
    let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
    let mut encoder = cbor::Encoder::from_memory();
    let encode_result = encoder.encode(&[&payload]);
    assert_eq!(encode_result.is_ok(), true);
    let mut nodes_in_table = vec![NameType::new([1u8; 64]), NameType::new([2u8; 64]), NameType::new([3u8; 64]), NameType::new([4u8; 64]),
                                  NameType::new([5u8; 64]), NameType::new([6u8; 64]), NameType::new([7u8; 64]), NameType::new([8u8; 64])];
    let put_result = data_manager.handle_put(&array_as_vector(encoder.as_bytes()), &mut nodes_in_table);
    assert_eq!(put_result.is_err(), false);
    match put_result.ok().unwrap() {
      MessageAction::SendOn(ref x) => {
        assert_eq!(x.len(), super::PARALLELISM);
        assert_eq!(x[0], nodes_in_table[0]);
        assert_eq!(x[1], nodes_in_table[1]);
        assert_eq!(x[2], nodes_in_table[2]);
        assert_eq!(x[3], nodes_in_table[3]);
      }
      MessageAction::Reply(_) => panic!("Unexpected"),
    }
    let data_name = NameType::new(data.name().get_id());
    let get_result = data_manager.handle_get(&data_name);
    assert_eq!(get_result.is_err(), false);
    match get_result.ok().unwrap() {
      MessageAction::SendOn(ref x) => {
        assert_eq!(x.len(), super::PARALLELISM);
        assert_eq!(x[0], nodes_in_table[0]);
        assert_eq!(x[1], nodes_in_table[1]);
        assert_eq!(x[2], nodes_in_table[2]);
        assert_eq!(x[3], nodes_in_table[3]);
      }
      MessageAction::Reply(_) => panic!("Unexpected"),
    }
  }

    #[test]
    fn handle_account_transfer() {
        let mut data_manager = DataManager::new();
        let name : NameType = routing::test_utils::Random::generate_random();
        let account_wrapper = DataManagerSendable::new(name.clone(), vec![]);
        let payload = Payload::new(PayloadTypeTag::DataManagerAccountTransfer, &account_wrapper);
        data_manager.handle_account_transfer(payload);
        assert_eq!(data_manager.db_.exist(&name), true);
    }

    #[test]
    fn handle_stats_transfer() {
        let mut data_manager = DataManager::new();
        let name : NameType = routing::test_utils::Random::generate_random();
        let stats_sendable = DataManagerStatsSendable::new(name.clone(), 1023);
        let payload = Payload::new(PayloadTypeTag::DataManagerStatsTransfer, &stats_sendable);
        data_manager.handle_stats_transfer(payload);
        assert_eq!(data_manager.resource_index, 512);
    }
}
