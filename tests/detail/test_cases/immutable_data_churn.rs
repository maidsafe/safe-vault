// Copyright 2016 MaidSafe.net limited.
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

use super::*;
use routing::{Data, DataRequest, ImmutableData, ImmutableDataType, ResponseContent,
              ResponseMessage};

pub fn test(request_count: u32, max_get_attempts: u32) {
    let mut test_group = TestGroup::new("ImmutableData churn test");

    let mut client = Client::new();
    client.create_account();
    let mut stored_data = Vec::with_capacity(request_count as usize);
    for i in 0..request_count {
        let data = Data::Immutable(ImmutableData::new(ImmutableDataType::Normal,
                                                      generate_random_vec_u8(1024)));
        test_group.start_case(&format!("Put ImmutableData {} {}", i, data.name()));
        trace!("Putting ImmutableData {} - {}", i, data.name());
        if let ResponseMessage { content: ResponseContent::PutSuccess(..), .. } =
               unwrap_option!(client.put(data.clone()), "") {} else {
            panic!("Received unexpected response")
        }
        stored_data.push(data);
    }

    for (i, data) in stored_data.iter().enumerate() {
        test_group.start_case(&format!("Get ImmutableData {} {}", i, data.name()));
        let data_request = DataRequest::Immutable(data.name(), ImmutableDataType::Normal);
        trace!("Getting ImmutableData {} - {}", i, data.name());
        if let ResponseMessage { content: ResponseContent::GetSuccess(response_data, _), .. } =
               unwrap_option!(get_with_retry(&mut client, data_request, max_get_attempts),
                              "") {
            assert_eq!(*data, response_data)
        } else {
            panic!("Received unexpected response")
        }
    }

    test_group.release();
}
