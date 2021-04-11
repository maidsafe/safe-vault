// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
mod logs;
mod rewards;
mod storage;

use crate::{
    chunk_store::UsedSpace,
    node::rpc::error_response::{invalid_param_resp, unimplemented_resp},
    Network, NodeInfo,
};
use log::warn;
use qjsonrpc::JsonRpcResponse;
use serde_json::{from_value, Value};

/// Delegates request handling to individual submodules based on method
/// This function handles param parsing, etc. so that submodules need only
/// worry about the logic required to service the request
pub async fn process_request(
    method: &str,
    payload: &Value,
    id: u32,
    node_info: &NodeInfo,
    used_space: UsedSpace,
    _network: Network,
) -> Result<Value, JsonRpcResponse> {
    use sn_node_rpc_data_types::*;
    match method {
        METHOD_GET_REWARDS_INFO => rewards::get_rewards_info(node_info),
        METHOD_SET_REWARD_KEY => {
            warn!("method '{}' is not yet implemented.", METHOD_SET_REWARD_KEY);
            Err(unimplemented_resp(METHOD_SET_REWARD_KEY, id))
        }
        METHOD_GET_STORAGE_INFO => storage::get_storage_info(node_info, used_space).await,
        METHOD_GET_LOGS => match from_value(payload.clone()) {
            Ok(params) => logs::get_logs(params, id, node_info),
            Err(e) => {
                warn!("{}", &e);
                Err(invalid_param_resp(
                    "payload",
                    "sn_node_rpc_data_types::GetLogsParams",
                    id,
                ))
            }
        },
        other => Err(JsonRpcResponse::error(
            format!("Unkown method '{}' received", other),
            qjsonrpc::JSONRPC_METHOD_NOT_FOUND,
            Some(id),
        )),
    }
}
