// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use crate::node::NodeInfo;
use qjsonrpc::JsonRpcResponse;
use serde_json::{json, Value};
use sn_node_rpc_data_types::GetRewardsInfoResult;

/// An rpc which returns reward key (Later, along with other rewards info) of this node
pub fn get_rewards_info(node_info: &NodeInfo) -> Result<Value, JsonRpcResponse> {
    let result = GetRewardsInfoResult {
        reward_key: node_info.reward_key,
    };

    Ok(json!(result))
}
