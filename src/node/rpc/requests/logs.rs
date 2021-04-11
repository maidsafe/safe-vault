// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
use crate::NodeInfo;
use qjsonrpc::JsonRpcResponse;
use serde_json::{json, Value};
use sn_node_rpc_data_types::{self as rpc_types, GetLogsParams, GetLogsResult};
use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::Path,
};

// TODO: store this somewhere centrally in the node structure for reference
// Maybe in utils.rs...
const PLAINTEXT_LOG_FILENAME: &str = "sn_node.log";

/// An rpc which fetches log lines
pub fn get_logs(
    params: GetLogsParams,
    id: u32,
    node_info: &NodeInfo,
) -> Result<Value, JsonRpcResponse> {
    let log_dir = &node_info.log_dir;
    match params.log_id {
        rpc_types::LOG_ID_PLAINTEXT => get_plaintext_logs(log_dir, &params, id),
        other => {
            let msg = format!(
                "Invalid log id '{}' received. See the documentation for a list of valid log IDs.",
                other
            );
            Err(JsonRpcResponse::error(msg, -1, Some(id)))
        }
    }
}

/// Get the plaintext logs and return the rpc resultant value as JSON
fn get_plaintext_logs<P: AsRef<Path>>(
    log_dir: P,
    params: &GetLogsParams,
    req_id: u32,
) -> Result<Value, JsonRpcResponse> {
    use std::convert::{TryFrom, TryInto};

    // open the log file
    let log_path = log_dir.as_ref().join(PLAINTEXT_LOG_FILENAME);
    let log_file = File::open(&log_path);
    if let Err(e) = log_file {
        log::error!("{:?}", &e);
        return Err(get_log_internal_error_resp(
            rpc_types::LOG_ID_PLAINTEXT,
            req_id,
        ));
    }
    let log_file = log_file.unwrap();

    // fetch lines starting from beginning if start_idx >= 0 or end if start_idx < 0
    let num_lines: usize = params.num_lines.try_into().unwrap_or(usize::MAX); // in case of 32-bit machines
    let lines = if params.start_idx >= 0 {
        // index >= 0 indicates start at first log line
        let reader = BufReader::new(log_file);
        let start_idx = usize::try_from(params.start_idx).unwrap();
        reader
            .lines()
            .skip(start_idx)
            .take(num_lines)
            .filter_map(|line| line.ok())
            .collect::<Vec<String>>()
    } else {
        // get a log file clone for counting lines
        let log_file2 = log_file.try_clone();
        if let Err(e) = log_file2 {
            log::error!("{:?}", &e);
            return Err(get_log_internal_error_resp(
                rpc_types::LOG_ID_PLAINTEXT,
                req_id,
            ));
        }
        let mut log_file2 = log_file2.unwrap();

        // consume clone to count lines and rewind file
        let total_lines: usize = BufReader::new(log_file).lines().fold(0, |c, _| c + 1); // count() equivalent
        if let Err(e) = log_file2.seek(SeekFrom::Start(0)) {
            log::error!("{:?}", &e);
            return Err(get_log_internal_error_resp(
                rpc_types::LOG_ID_PLAINTEXT,
                req_id,
            ));
        }

        // take the last num_lines
        let reader = BufReader::new(log_file2);
        let start_idx =
            total_lines.saturating_sub(usize::try_from(-params.start_idx).unwrap_or(usize::MAX));
        reader
            .lines()
            .skip(start_idx)
            .take(num_lines)
            .filter_map(|line| line.ok())
            .collect::<Vec<String>>()
    };

    Ok(json!(GetLogsResult { lines }))
}

/// Helper to form response for internal errors on catching logs (e.g. io error and such)
fn get_log_internal_error_resp(log_id: u64, req_id: u32) -> JsonRpcResponse {
    JsonRpcResponse::error(
        format!(
            "Node internal error. Unable to fetch log with id '{}'.",
            log_id
        ),
        -1,
        Some(req_id),
    )
}
