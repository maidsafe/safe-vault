// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use crate::{chunk_store::UsedSpace, NodeInfo};
use qjsonrpc::JsonRpcResponse;
use serde_json::{json, Value};
use sn_node_rpc_data_types::GetStorageInfoResult;

/// An rpc which returns information regarding used storage space
pub async fn get_storage_info(
    node_info: &NodeInfo,
    used_space: UsedSpace,
) -> Result<Value, JsonRpcResponse> {
    // general used space info
    let node_root = node_info.root_dir.clone();
    let used = used_space.total().await;
    let total = used_space.max_capacity().await;

    // local store info
    let mut local_store_iter = used_space.iter_local_stores().await;
    let mut local_stores = Vec::new();
    while let Some(ls) = local_store_iter.get_next().await {
        local_stores.push(ls);
    }

    // collect & return
    let result = GetStorageInfoResult {
        node_root,
        used,
        total,
        local_stores,
    };
    Ok(json!(result))
}
