// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use qjsonrpc::JsonRpcResponse;

// application-specific error codes below
pub const NODERPC_ACCESS_DENIED: isize = -32099;

/// response formation for inability to parse param
pub fn invalid_param_resp(param_name: &str, type_str: &str, id: u32) -> JsonRpcResponse {
    JsonRpcResponse::error(
        format!("Invalid method parameter '{}:{}'", param_name, type_str,),
        qjsonrpc::JSONRPC_INVALID_PARAMS,
        Some(id),
    )
}

/// response formation for missing parameter type
pub fn missing_param_resp(param_name: &str, type_str: &str, id: u32) -> JsonRpcResponse {
    JsonRpcResponse::error(
        format!("Missing required parameter '{}: {}'", param_name, type_str,),
        qjsonrpc::JSONRPC_INVALID_PARAMS,
        Some(id),
    )
}

/// response formation for unimplemented RPCs
pub fn unimplemented_resp(method: &str, id: u32) -> JsonRpcResponse {
    JsonRpcResponse::error(
        format!("RPC method '{}' is not yet implemented", method),
        qjsonrpc::JSONRPC_INTERNAL_ERROR,
        Some(id),
    )
}
