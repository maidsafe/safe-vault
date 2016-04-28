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

use std::mem;
use std::convert::From;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::rc::Rc;

use error::InternalError;
use safe_network_common::client_errors::MutationError;
use maidsafe_utilities::serialisation;
use routing::{ImmutableData, StructuredData, Authority, Data, MessageId, RequestMessage,
              DataIdentifier};
use utils;
use vault::RoutingNode;
use xor_name::XorName;

// It has now been decided that the charge will be by unit
// i.e. each chunk incurs a default charge of one unit, no matter of the data size
// FIXME - restore this constant to 1024 or greater
const DEFAULT_ACCOUNT_SIZE: u64 = 50;  // 1024 units, max 1GB for immutable_data (1MB per chunk)

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
struct Refresh(XorName, Account);

#[derive(RustcEncodable, RustcDecodable, PartialEq, Eq, Debug, Clone)]
pub struct Account {
    data_stored: u64,
    space_available: u64,
    version: u64,
}

impl Default for Account {
    fn default() -> Account {
        Account {
            data_stored: 0,
            space_available: DEFAULT_ACCOUNT_SIZE,
            version: 0,
        }
    }
}

impl Account {
    fn put_data(&mut self) -> Result<(), MutationError> {
        if self.space_available < 1 {
            return Err(MutationError::LowBalance);
        }
        self.data_stored += 1;
        self.space_available -= 1;
        self.version += 1;
        Ok(())
    }

    fn delete_data(&mut self) {
        self.data_stored -= 1;
        self.space_available += 1;
        self.version += 1;
    }
}



pub struct MaidManager {
    routing_node: Rc<RoutingNode>,
    accounts: HashMap<XorName, Account>,
    request_cache: HashMap<MessageId, RequestMessage>,
}

impl MaidManager {
    pub fn new(routing_node: Rc<RoutingNode>) -> MaidManager {
        MaidManager {
            routing_node: routing_node,
            accounts: HashMap::new(),
            request_cache: HashMap::new(),
        }
    }

    pub fn handle_put(&mut self,
                      request: &RequestMessage,
                      data: &Data,
                      msg_id: &MessageId)
                      -> Result<(), InternalError> {
        match *data {
            Data::Immutable(ref immut_data) => {
                self.handle_put_immutable_data(request, immut_data, msg_id)
            }
            Data::Structured(ref struct_data) => {
                self.handle_put_structured_data(request, struct_data, msg_id)
            }
            _ => {
                self.reply_with_put_failure(request.clone(),
                                            *msg_id,
                                            &MutationError::InvalidOperation)
            }
        }
    }

    pub fn handle_put_success(&mut self,
                              data_id: &DataIdentifier,
                              msg_id: &MessageId)
                              -> Result<(), InternalError> {
        match self.request_cache.remove(msg_id) {
            Some(client_request) => {
                // Send success response back to client
                let src = client_request.dst;
                let dst = client_request.src;
                let _ = self.routing_node.send_put_success(src, dst, *data_id, *msg_id);
                Ok(())
            }
            None => Err(InternalError::FailedToFindCachedRequest(*msg_id)),
        }
    }

    pub fn handle_put_failure(&mut self,
                              msg_id: &MessageId,
                              external_error_indicator: &[u8])
                              -> Result<(), InternalError> {
        match self.request_cache.remove(msg_id) {
            Some(client_request) => {
                // Refund account
                match self.accounts.get_mut(&utils::client_name(&client_request.src)) {
                    Some(account) => account.delete_data(),
                    None => return Ok(()),
                }
                // Send failure response back to client
                let error =
                    try!(serialisation::deserialise::<MutationError>(external_error_indicator));
                self.reply_with_put_failure(client_request, *msg_id, &error)
            }
            None => Err(InternalError::FailedToFindCachedRequest(*msg_id)),
        }
    }

    pub fn handle_refresh(&mut self, serialised_msg: &[u8]) -> Result<(), InternalError> {
        let Refresh(maid_name, account) =
            try!(serialisation::deserialise::<Refresh>(serialised_msg));

        match self.routing_node.close_group(maid_name) {
            Ok(None) | Err(_) => return Ok(()),
            Ok(Some(_)) => (),
        }
        match self.accounts.entry(maid_name) {
            Entry::Vacant(entry) => {
                let _ = entry.insert(account);
            }
            Entry::Occupied(mut entry) => {
                if entry.get().version < account.version {
                    let _ = entry.insert(account);
                }
            }
        }
        Ok(())
    }

    pub fn handle_node_added(&mut self, node_name: &XorName) {
        // Only retain accounts for which we're still in the close group
        let accounts = mem::replace(&mut self.accounts, HashMap::new());
        self.accounts = accounts.into_iter()
                                .filter(|&(ref maid_name, ref account)| {
                                    match self.routing_node
                                              .close_group(*maid_name) {
                                        Ok(None) => {
                                            trace!("No longer a MM for {}", maid_name);
                                            let requests = mem::replace(&mut self.request_cache,
                                                                        HashMap::new());
                                            self.request_cache =
                                                requests.into_iter()
                                                        .filter(|&(_, ref r)| {
                                                            utils::client_name(&r.src) != *maid_name
                                                        })
                                                        .collect();
                                            false
                                        }
                                        Ok(Some(_)) => {
                                            self.send_refresh(
                                                  maid_name,
                                                  account,
                                                  MessageId::from_added_node(*node_name));
                                            true
                                        }
                                        Err(error) => {
                                            error!("Failed to get close group: {:?} for {}",
                                                   error,
                                                   maid_name);
                                            false
                                        }
                                    }
                                })
                                .collect();
    }

    pub fn handle_node_lost(&mut self, node_name: &XorName) {
        for (maid_name, account) in &self.accounts {
            self.send_refresh(maid_name, account, MessageId::from_lost_node(*node_name));
        }
    }

    fn send_refresh(&self, maid_name: &XorName, account: &Account, msg_id: MessageId) {
        let src = Authority::ClientManager(*maid_name);
        let refresh = Refresh(*maid_name, account.clone());
        if let Ok(serialised_refresh) = serialisation::serialise(&refresh) {
            trace!("MM sending refresh for account {}", src.name());
            let _ = self.routing_node
                        .send_refresh_request(src.clone(), src.clone(), serialised_refresh, msg_id);
        }
    }

    #[cfg_attr(feature="clippy", allow(cast_possible_truncation, cast_precision_loss,
                                       cast_sign_loss))]
    fn handle_put_immutable_data(&mut self,
                                 request: &RequestMessage,
                                 data: &ImmutableData,
                                 msg_id: &MessageId)
                                 -> Result<(), InternalError> {
        self.forward_put_request(utils::client_name(&request.src),
                                 Data::Immutable(data.clone()),
                                 *msg_id,
                                 request)
    }

    fn handle_put_structured_data(&mut self,
                                  request: &RequestMessage,
                                  data: &StructuredData,
                                  msg_id: &MessageId)
                                  -> Result<(), InternalError> {
        // If the type_tag is 0, the account must not exist, else it must exist.
        let client_name = utils::client_name(&request.src);
        if data.get_type_tag() == 0 {
            if self.accounts.contains_key(&client_name) {
                let error = MutationError::AccountExists;
                try!(self.reply_with_put_failure(request.clone(), *msg_id, &error));
                return Err(From::from(error));
            }

            // Create the account, the SD incurs charge later on
            let _ = self.accounts.insert(client_name, Account::default());
        }
        self.forward_put_request(client_name,
                                 Data::Structured(data.clone()),
                                 *msg_id,
                                 request)
    }

    fn forward_put_request(&mut self,
                           client_name: XorName,
                           data: Data,
                           msg_id: MessageId,
                           request: &RequestMessage)
                           -> Result<(), InternalError> {
        // Account must already exist to Put Data.
        let result = self.accounts
                         .get_mut(&client_name)
                         .ok_or(MutationError::NoSuchAccount)
                         .and_then(|account| account.put_data());
        if let Err(error) = result {
            trace!("MM responds put_failure of data {}, due to error {:?}",
                   data.name(),
                   error);
            try!(self.reply_with_put_failure(request.clone(), msg_id, &error));
            return Err(From::from(error));
        }
        self.send_refresh(&client_name,
                          self.accounts.get(&client_name).expect("Account not found."),
                          MessageId::zero());
        {
            // forwarding data_request to NAE Manager
            let src = request.dst.clone();
            let dst = Authority::NaeManager(data.name());
            trace!("MM forwarding put request to {:?}", dst);
            let _ = self.routing_node
                        .send_put_request(src, dst, data, msg_id);
        }

        if let Some(prior_request) = self.request_cache
                                         .insert(msg_id, request.clone()) {
            error!("Overwrote existing cached request: {:?}", prior_request);
        }

        Ok(())
    }

    fn reply_with_put_failure(&self,
                              request: RequestMessage,
                              msg_id: MessageId,
                              error: &MutationError)
                              -> Result<(), InternalError> {
        let src = request.dst.clone();
        let dst = request.src.clone();
        let external_error_indicator = try!(serialisation::serialise(error));
        let _ = self.routing_node
                    .send_put_failure(src, dst, request, external_error_indicator, msg_id);
        Ok(())
    }

    #[cfg(feature = "use-mock-crust")]
    pub fn get_put_count(&self, client_name: &XorName) -> Option<u64> {
        self.accounts.get(client_name).map(|account| account.data_stored)
    }
}


#[cfg(test)]
#[cfg_attr(feature="clippy", allow(indexing_slicing))]
#[cfg(not(feature="use-mock-crust"))]
mod test {
    use super::*;
    use super::Refresh;
    use error::InternalError;
    use safe_network_common::client_errors::MutationError;
    use maidsafe_utilities::serialisation;
    use rand::{thread_rng, random};
    use rand::distributions::{IndependentSample, Range};
    use routing::{Authority, Data, ImmutableData, MessageId, RequestContent, RequestMessage,
                  ResponseContent, StructuredData};
    use sodiumoxide::crypto::hash::sha512;
    use sodiumoxide::crypto::sign;
    use std::rc::Rc;
    use std::sync::mpsc;
    use utils;
    use utils::generate_random_vec_u8;
    use vault::RoutingNode;
    use xor_name::XorName;

    #[test]
    fn account_ok() {
        let mut account = Account::default();

        assert_eq!(0, account.data_stored);
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.space_available);
        for _ in 0..super::DEFAULT_ACCOUNT_SIZE {
            assert!(account.put_data().is_ok());
        }
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.data_stored);
        assert_eq!(0, account.space_available);

        for _ in 0..super::DEFAULT_ACCOUNT_SIZE {
            account.delete_data();
        }
        assert_eq!(0, account.data_stored);
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.space_available);
    }

    #[test]
    fn account_err() {
        let mut account = Account::default();

        assert_eq!(0, account.data_stored);
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.space_available);
        for _ in 0..super::DEFAULT_ACCOUNT_SIZE {
            assert!(account.put_data().is_ok());
        }
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.data_stored);
        assert_eq!(0, account.space_available);
        assert!(account.put_data().is_err());
        assert_eq!(super::DEFAULT_ACCOUNT_SIZE, account.data_stored);
        assert_eq!(0, account.space_available);
    }


    struct Environment {
        our_authority: Authority,
        client: Authority,
        routing: Rc<RoutingNode>,
        maid_manager: MaidManager,
    }

    fn environment_setup() -> Environment {
        let routing = unwrap_result!(RoutingNode::new(mpsc::channel().0, false));
        let from = random::<XorName>();
        let client;

        loop {
            let keys = sign::gen_keypair();
            let name = XorName(sha512::hash(&keys.0[..]).0);
            if let Ok(Some(_)) = routing.close_group(name) {
                client = Authority::Client {
                    client_key: keys.0,
                    peer_id: random(),
                    proxy_node_name: from,
                };
                break;
            }
        }

        let routing = Rc::new(routing);

        Environment {
            our_authority: Authority::ClientManager(utils::client_name(&client)),
            client: client,
            routing: routing.clone(),
            maid_manager: MaidManager::new(routing.clone()),
        }
    }

    fn create_account(env: &mut Environment) {
        if let Authority::Client { client_key, .. } = env.client {
            let identifier = random::<XorName>();
            let sd = unwrap_result!(StructuredData::new(0,
                                                        identifier,
                                                        0,
                                                        vec![],
                                                        vec![client_key],
                                                        vec![],
                                                        None));
            let msg_id = MessageId::new();
            let data = Data::Structured(sd);
            let request = RequestMessage {
                src: env.client.clone(),
                dst: env.our_authority.clone(),
                content: RequestContent::Put(data.clone(), msg_id),
            };

            assert!(env.maid_manager
                       .handle_put(&request, &data, &msg_id)
                       .is_ok());
        };
    }

    fn get_close_node(env: &Environment) -> XorName {
        let mut name = random::<XorName>();

        loop {
            if let Ok(Some(_)) = env.routing.close_group(name) {
                return name;
            } else {
                name = random::<XorName>();
            }
        }
    }

    fn lose_close_node(env: &Environment) -> XorName {
        loop {
            if let Ok(Some(close_group)) = env.routing.close_group(*env.our_authority.name()) {
                let mut rng = thread_rng();
                let range = Range::new(0, close_group.len());
                let our_name = if let Ok(ref name) = env.routing.name() {
                    *name
                } else {
                    unreachable!()
                };
                loop {
                    let index = range.ind_sample(&mut rng);
                    if close_group[index] != our_name {
                        return close_group[index];
                    }
                }
            }
        }
    }


    #[test]
    fn handle_put_without_account() {
        let mut env = environment_setup();

        // Try with valid ImmutableData before account is created
        let immutable_data = ImmutableData::new(generate_random_vec_u8(1024));
        let msg_id = MessageId::new();
        let data = Data::Immutable(immutable_data);
        let valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(data.clone(), msg_id),
        };

        if let Err(InternalError::ClientMutation(MutationError::NoSuchAccount)) =
               env.maid_manager.handle_put(&valid_request, &data, &msg_id) {
        } else {
            unreachable!()
        }

        let put_requests = env.routing.put_requests_given();

        assert!(put_requests.is_empty());

        let put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.client);

        if let ResponseContent::PutFailure { ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, msg_id);
            assert_eq!(*request, valid_request);
            if let MutationError::NoSuchAccount =
                   unwrap_result!(serialisation::deserialise(external_error_indicator)) {
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn handle_put_with_account() {
        let mut env = environment_setup();
        create_account(&mut env);

        let immutable_data = ImmutableData::new(generate_random_vec_u8(1024));
        let msg_id = MessageId::new();
        let data = Data::Immutable(immutable_data.clone());
        let valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(data.clone(), msg_id),
        };

        assert!(env.maid_manager
                   .handle_put(&valid_request, &data, &msg_id)
                   .is_ok());

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());

        let put_requests = env.routing.put_requests_given();

        // put_requests[0] - account creation.
        assert_eq!(put_requests.len(), 2);
        assert_eq!(put_requests[1].src, env.our_authority);
        assert_eq!(put_requests[1].dst,
                   Authority::NaeManager(immutable_data.name()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[1].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, msg_id);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn invalid_put_for_previously_created_account() {
        let mut env = environment_setup();
        create_account(&mut env);

        let immutable_data = ImmutableData::new(generate_random_vec_u8(1024));
        let mut msg_id = MessageId::new();
        let data = Data::Immutable(immutable_data.clone());
        let mut valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(data.clone(), msg_id),
        };

        assert!(env.maid_manager
                   .handle_put(&valid_request, &data, &msg_id)
                   .is_ok());

        let mut put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 2);
        assert_eq!(put_requests[1].src, env.our_authority);
        assert_eq!(put_requests[1].dst,
                   Authority::NaeManager(immutable_data.name()));

        if let RequestContent::Put(Data::Immutable(ref data), ref id) = put_requests[1].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, msg_id);
        } else {
            unreachable!()
        }

        let client_key = if let Authority::Client { client_key, .. } = env.client {
            client_key
        } else {
            unreachable!()
        };

        let identifier = random::<XorName>();
        let sd = unwrap_result!(StructuredData::new(0,
                                                    identifier,
                                                    0,
                                                    vec![],
                                                    vec![client_key],
                                                    vec![],
                                                    None));
        msg_id = MessageId::new();
        let sd_data = Data::Structured(sd);
        valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(sd_data.clone(), msg_id),
        };

        if let Err(InternalError::ClientMutation(MutationError::AccountExists)) =
               env.maid_manager
                  .handle_put(&valid_request, &sd_data, &msg_id) {
        } else {
            unreachable!()
        }

        put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.client);

        if let ResponseContent::PutFailure { ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, msg_id);
            assert_eq!(*request, valid_request);
            if let MutationError::AccountExists =
                   unwrap_result!(serialisation::deserialise(external_error_indicator)) {} else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    #[test]
    fn handle_put_success() {
        let mut env = environment_setup();
        create_account(&mut env);

        let immutable_data = ImmutableData::new(generate_random_vec_u8(1024));
        let mut msg_id = MessageId::new();
        let data = Data::Immutable(immutable_data.clone());
        let valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(data.clone(), msg_id),
        };

        assert!(env.maid_manager
                   .handle_put(&valid_request, &data, &msg_id)
                   .is_ok());

        let put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 2);
        assert_eq!(put_requests[1].src, env.our_authority);
        assert_eq!(put_requests[1].dst,
                   Authority::NaeManager(immutable_data.name()));

        let data = if let RequestContent::Put(Data::Immutable(ref data), ref id) =
                          put_requests[1].content {
            assert_eq!(*data, immutable_data);
            assert_eq!(*id, msg_id);
            data
        } else {
            unreachable!()
        };

        // Valid case.
        assert!(env.maid_manager
                   .handle_put_success(&data.identifier(), &msg_id)
                   .is_ok());

        let put_successes = env.routing.put_successes_given();

        assert_eq!(put_successes.len(), 1);
        assert_eq!(put_successes[0].src, env.our_authority);
        assert_eq!(put_successes[0].dst, env.client);

        if let ResponseContent::PutSuccess(ref name, ref id) = put_successes[0].content {
            assert_eq!(*id, msg_id);
            assert_eq!(*name, data.identifier());
        } else {
            unreachable!()
        }

        // Invalid case.
        msg_id = MessageId::new();

        if let Err(InternalError::FailedToFindCachedRequest(id)) =
               env.maid_manager.handle_put_success(&data.identifier(), &msg_id) {
            assert_eq!(msg_id, id);
        } else {
            unreachable!()
        }
    }

    #[test]
    fn handle_put_failure() {
        let mut env = environment_setup();
        create_account(&mut env);

        let client_key = if let Authority::Client { client_key, .. } = env.client {
            client_key
        } else {
            unreachable!()
        };
        let identifier = random::<XorName>();
        let sd = unwrap_result!(StructuredData::new(1,
                                                    identifier,
                                                    0,
                                                    vec![],
                                                    vec![client_key],
                                                    vec![],
                                                    None));
        let mut msg_id = MessageId::new();
        let data = Data::Structured(sd.clone());
        let valid_request = RequestMessage {
            src: env.client.clone(),
            dst: env.our_authority.clone(),
            content: RequestContent::Put(data.clone(), msg_id),
        };

        assert!(env.maid_manager
                   .handle_put(&valid_request, &data, &msg_id)
                   .is_ok());

        let mut put_failures = env.routing.put_failures_given();
        assert!(put_failures.is_empty());

        let put_requests = env.routing.put_requests_given();

        assert_eq!(put_requests.len(), 2);
        assert_eq!(put_requests[1].src, env.our_authority);
        assert_eq!(put_requests[1].dst, Authority::NaeManager(sd.name()));

        if let RequestContent::Put(Data::Structured(ref data), ref id) = put_requests[1].content {
            assert_eq!(*data, sd);
            assert_eq!(*id, msg_id);
        } else {
            unreachable!()
        }

        // Valid case.
        let error = MutationError::NoSuchData;
        if let Ok(error_indicator) = serialisation::serialise(&error) {
            assert!(env.maid_manager
                       .handle_put_failure(&msg_id, &error_indicator[..])
                       .is_ok());
        } else {
            unreachable!()
        }

        put_failures = env.routing.put_failures_given();

        assert_eq!(put_failures.len(), 1);
        assert_eq!(put_failures[0].src, env.our_authority);
        assert_eq!(put_failures[0].dst, env.client);

        if let ResponseContent::PutFailure { ref id, ref request, ref external_error_indicator } =
               put_failures[0].content {
            assert_eq!(*id, msg_id);
            assert_eq!(*request, valid_request);
            if let Ok(error_indicator) = serialisation::serialise(&error) {
                assert_eq!(*external_error_indicator, error_indicator);
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }

        // Invalid case.
        msg_id = MessageId::new();
        if let Ok(error_indicator) = serialisation::serialise(&error) {
            if let Err(InternalError::FailedToFindCachedRequest(id)) =
                   env.maid_manager.handle_put_failure(&msg_id, &error_indicator[..]) {
                assert_eq!(msg_id, id);
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
    }

    // #[test]
    // fn network_full() {
    //     let mut env = environment_setup();
    //     create_account(&mut env);

    //     let immutable_data = ImmutableData::new(generate_random_vec_u8(1024));
    //     let msg_id = MessageId::new();
    //     let data = Data::Immutable(immutable_data.clone());
    //     let valid_request = RequestMessage {
    //         src: env.client.clone(),
    //         dst: env.our_authority.clone(),
    //         content: RequestContent::Put(data.clone(), msg_id),
    //     };

    // let mut full_pmid_nodes = HashSet::new();

    //     if let Ok(Some(close_group)) = env.routing.close_group(utils::client_name(&env.client)) {
    //         full_pmid_nodes = close_group.iter()
    //                                      .take(close_group.len() / 2)
    //                                      .cloned()
    //                                      .collect::<HashSet<XorName>>();
    //     }

    //     assert!(env.maid_manager
    //                .handle_put(&env.routing, &valid_request, &data, &msg_id)
    //                .is_ok());

    // let put_failures = env.routing.put_failures_given();

    //     assert_eq!(put_failures.len(), 1);
    //     assert_eq!(put_failures[0].src, env.our_authority);
    //     assert_eq!(put_failures[0].dst, env.client);

    //     if let ResponseContent::PutFailure { ref id, ref request, ref external_error_indicator } =
    //            put_failures[0].content {
    //         assert_eq!(*id, msg_id);
    //         assert_eq!(*request, valid_request);
    //         if let Ok(error_indicator) = serialisation::serialise(&MutationError::NetworkFull) {
    //             assert_eq!(*external_error_indicator, error_indicator);
    //         } else {
    //             unreachable!()
    //         }
    //     } else {
    //         unreachable!()
    //     }
    // }

    #[test]
    fn churn_refresh() {
        let mut env = environment_setup();
        create_account(&mut env);

        let mut refresh_count = 1;
        let mut refresh_requests = env.routing.refresh_requests_given();
        assert_eq!(refresh_requests.len(), refresh_count);
        assert_eq!(refresh_requests[0].src, env.our_authority);
        assert_eq!(refresh_requests[0].dst, env.our_authority);

        env.routing.node_added_event(get_close_node(&env));
        env.maid_manager.handle_node_added(&random::<XorName>());

        refresh_requests = env.routing.refresh_requests_given();

        if let Ok(Some(_)) = env.routing.close_group(utils::client_name(&env.client)) {
            assert_eq!(refresh_requests.len(), refresh_count + 1);
            assert_eq!(refresh_requests[refresh_count].src, env.our_authority);
            assert_eq!(refresh_requests[refresh_count].dst, env.our_authority);
            refresh_count += 1;

            if let RequestContent::Refresh(ref serialised_refresh, _) = refresh_requests[0]
                                                                            .content {
                if let Ok(refresh) = serialisation::deserialise(&serialised_refresh) {
                    let refresh: Refresh = refresh;
                    assert_eq!(refresh.0, utils::client_name(&env.client));
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            }
        } else {
            assert_eq!(refresh_requests.len(), refresh_count);
        }

        env.routing.node_lost_event(lose_close_node(&env));
        env.maid_manager.handle_node_lost(&random::<XorName>());

        refresh_requests = env.routing.refresh_requests_given();

        if let Ok(Some(_)) = env.routing.close_group(utils::client_name(&env.client)) {
            assert_eq!(refresh_requests.len(), refresh_count + 1);
            assert_eq!(refresh_requests[refresh_count].src, env.our_authority);
            assert_eq!(refresh_requests[refresh_count].dst, env.our_authority);
            // refresh_count += 1;

            if let RequestContent::Refresh(ref serialised_refresh, _) =
                   refresh_requests[refresh_count].content {
                if let Ok(refresh) = serialisation::deserialise(&serialised_refresh) {
                    let refresh: Refresh = refresh;
                    assert_eq!(refresh.0, utils::client_name(&env.client));
                } else {
                    unreachable!()
                }
            } else {
                unreachable!()
            }
        } else {
            assert_eq!(refresh_requests.len(), refresh_count);
        }
    }
}
