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

use cbor::Decoder;
use routing::NameType;
use routing::types::MessageAction;
use routing::error::{ResponseError, InterfaceError};
use maidsafe_types::data_tags;
use routing::node_interface::MethodCall;
use routing::sendable::Sendable;
pub use self::database::{MaidManagerAccountWrapper, MaidManagerAccount};
use data_parser::Data;

type Address = NameType;

pub struct MaidManager {
  db_ : database::MaidManagerDatabase
}

impl MaidManager {
  pub fn new() -> MaidManager {
    MaidManager { db_: database::MaidManagerDatabase::new() }
  }

  pub fn handle_put(&mut self, from : &NameType, serialised_data : &Vec<u8>) ->Result<MessageAction, InterfaceError> {
      let data : Box<Sendable>;
      let mut destinations : Vec<NameType> = Vec::new();
      let mut free_of_charge = false;
      let mut suppress_error = false;
      let mut decoder = Decoder::from_bytes(&serialised_data[..]);
      if let Some(parsed_data) = decoder.decode().next().and_then(|result| result.ok()) {
          match parsed_data {
              Data::Immutable(parsed) => data = Box::new(parsed),
              Data::ImmutableBackup(parsed) => {
                  data = Box::new(parsed);
                  suppress_error = true;
              },
              Data::ImmutableSacrificial(parsed) => {
                  data = Box::new(parsed);
                  suppress_error = true;
              },
              Data::Structured(parsed) => data = Box::new(parsed),
              Data::PublicMaid(parsed) => {
                  data = Box::new(parsed);
                  free_of_charge = true;
              },
              Data::PublicMpid(parsed) => {
                  data = Box::new(parsed);
                  free_of_charge = true;
              },
              _ => return Err(From::from(ResponseError::InvalidRequest)),
          }
      } else {
          return Err(From::from(ResponseError::InvalidRequest));
      }

      let data_name = data.name();
      // FIXME: is there a direct way to get to the data length? (this call re-encodes it)
      let data_length = data.serialised_contents().len() as u64;

      if !self.db_.put_data(from, data_length)
          && !free_of_charge {
          if !suppress_error {
              // FIXME: report clear payment error ?
              return Err(From::from(ResponseError::InvalidRequest));
          } else {
              return Err(InterfaceError::Abort);
          }
      }
      destinations.push(data_name);
      Ok(MessageAction::SendOn(destinations))
  }

  pub fn handle_account_transfer(&mut self, payload : maidsafe_types::Payload) {
      let maid_account_wrapper : MaidManagerAccountWrapper = payload.get_data();
      self.db_.handle_account_transfer(&maid_account_wrapper);
  }

  pub fn retrieve_all_and_reset(&mut self) -> Vec<MethodCall> {
    self.db_.retrieve_all_and_reset()
  }

}

#[cfg(test)]
mod test {
    use cbor;
    use maidsafe_types::{ ImmutableData, Payload, PayloadTypeTag };
    use routing;
    use super::*;
    use routing::types::*;
    use routing::NameType;
    use routing::sendable::Sendable;

    #[test]
    fn handle_put() {
        let mut maid_manager = MaidManager::new();
        let from: NameType = routing::test_utils::Random::generate_random();
        let value = generate_random_vec_u8(1024);
        let data = ImmutableData::new(value);
        let payload = Payload::new(PayloadTypeTag::ImmutableData, &data);
        let mut encoder = cbor::Encoder::from_memory();
        let encode_result = encoder.encode(&[&payload]);
        assert_eq!(encode_result.is_ok(), true);
        let put_result = maid_manager.handle_put(&from, &array_as_vector(encoder.as_bytes()));
        assert_eq!(put_result.is_err(), false);
        match put_result.ok().unwrap() {
            MessageAction::SendOn(ref x) => {
                assert_eq!(x.len(), 1);
                assert_eq!(x[0], data.name());
            }
            MessageAction::Reply(_) => panic!("Unexpected"),
        }
    }

    #[test]
    fn handle_account_transfer() {
        let mut maid_manager = MaidManager::new();
        let name : NameType = routing::test_utils::Random::generate_random();
        let account_wrapper = MaidManagerAccountWrapper::new(name.clone(), MaidManagerAccount::new());
        let payload = Payload::new(PayloadTypeTag::MaidManagerAccountTransfer, &account_wrapper);
        maid_manager.handle_account_transfer(payload);
        assert_eq!(maid_manager.db_.exist(&name), true);
    }
}
