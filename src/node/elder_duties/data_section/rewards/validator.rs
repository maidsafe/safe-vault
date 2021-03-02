// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_data_types::PublicKey;
use sn_transfers::ReplicaValidator;

/// Should be validating
/// other replica groups, i.e.
/// make sure they are run at Elders
/// of sections we know of.
/// TBD.
#[derive(Clone)]
pub struct Validator {}

impl ReplicaValidator for Validator {
    fn is_valid(&self, _replica_group: PublicKey) -> bool {
        true
    }
}
