// Copyright 2015 MaidSafe.net limited
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe
// Software.

#![allow(dead_code)]

extern crate routing;
extern crate maidsafe_types;

mod database;

use cbor::{ Decoder };

type CloseGroupDifference = self::routing::types::CloseGroupDifference;
type Address = self::routing::types::Address;

pub struct MaidManager {
  db_ : database::MaidManagerDatabase
}

impl MaidManager {
  pub fn new() -> MaidManager {
    MaidManager { db_: database::MaidManagerDatabase::new() }
  }

  // pub fn handle_create_account(&mut self,
  //                              public_maid: &maidsafe_types::public_maid::PublicMaid,
  //                              public_anmaid: &maidsafe_types::public_an_maid::PublicAnMaid,
  //                              space_offered: usize) {
  //     // let maid_name: Vec<Address> = Vec::with_capacity(64);
  //     // maid_name.push_all(&public_maid.get_name());
  //     // assert!(db_.exist(&maid_name));

  //     // let mut d = Decoder::from_bytes(&maid_name[..]);
  //     // let immutable_data: maidsafe_types::ImmutableData = d.decode().next().unwrap().unwrap();
  //     // let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());
  //     // db_.put_data(
  // }

  pub fn handle_put(&mut self, from : &routing::types::Address, data : &Vec<u8>) ->Result<routing::Action, routing::RoutingError> {
    // TODO the data_type shall be passed down or data needs to be name + content
    //      here assuming data is serialised_data of ImmutableData
    let mut d = Decoder::from_bytes(&data[..]);
    let immutable_data: maidsafe_types::ImmutableData = d.decode().next().unwrap().unwrap();
    let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());

    if !self.db_.put_data(from, data.len() as u64) {
      return Err(routing::RoutingError::InvalidRequest);
    }

    let mut destinations : Vec<routing::DhtIdentity> = Vec::new();
    destinations.push(routing::DhtIdentity { id : immutable_data.get_name().get_id() });

    Ok(routing::Action::SendOn(destinations))
  }

  pub fn handle_churn(&mut self, close_group_difference: &CloseGroupDifference) {
      let old_accounts = close_group_difference.0.clone();
      for old_account in &old_accounts {
          let mut d = Decoder::from_bytes(&old_account[..]);
          let immutable_data: maidsafe_types::ImmutableData = d.decode().next().unwrap().unwrap();
          let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());

          self.db_.delete_data(old_account, data_name.len() as u64);
      }

      let send_accounts = close_group_difference.1.clone();
      for send_account in &send_accounts {
          let mut d = Decoder::from_bytes(&send_account[..]);
          let immutable_data: maidsafe_types::ImmutableData = d.decode().next().unwrap().unwrap();
          let data_name = self::routing::types::array_as_vector(&immutable_data.get_name().get_id());

          self.db_.delete_data(send_account, data_name.len() as u64);
      }
  }

  pub fn has_account(&mut self, name: &routing::types::Identity) -> bool {
      self.db_.exist(name)
  }
}
