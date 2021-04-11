// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
mod error_response;
mod requests;

use crate::{
    chunk_store::UsedSpace,
    state_db::{parse_hex, vec_to_hex},
    Network, NodeInfo, Result,
};
use error_response::*;
use log::{info, warn};
use qjsonrpc::{
    Endpoint, IncomingConn, IncomingJsonRpcRequest, JsonRpcRequest, JsonRpcResponse,
    JsonRpcResponseStream,
};
use rand::prelude::*;
use requests::process_request;
use serde_json::{from_value, Value};
use sn_data_types::{Keypair, PublicKey, SecretKey};
use sn_node_rpc_data_types::Credentials;
use std::{
    fs, io,
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
};

// alias the connection stream and connection
// type in case the underlying implementation ever changes
pub type ConnectionStream = IncomingConn;
pub type Connection = IncomingJsonRpcRequest;

// config constants
const RPC_DIRNAME: &str = "rpc";
const RPC_PK_FILENAME: &str = "rpc_public_key";
const RPC_SK_FILENAME: &str = "rpc_secret_key";
const RPC_CONNECTION_IDLE_TIMEOUT_MS: u64 = 10000;
const RPC_IP_ADDR_STR: &str = "localhost";

// request format constants
const CREDENTIALS_FIELDNAME: &str = "credentials";
const PAYLOAD_FIELDNAME: &str = "payload";

/// A thin wrapper around response stream
/// which would allow the Node to service a node operation
/// and report the result via this object if it succeeds,
/// without knowing about the underlying JsonRpcResponse object
pub struct ResponseStream {
    /// The response to use if respond() is supplied with an Ok
    result: Value,
    /// The underlying id of the request which generated the response
    id: u32,
    /// The wrapped response stream
    resp_stream: JsonRpcResponseStream,
}

impl ResponseStream {
    /// ctor
    fn new(result: Value, id: u32, resp_stream: JsonRpcResponseStream) -> Self {
        Self {
            result,
            id,
            resp_stream,
        }
    }

    /// consume self and respond to the request
    /// using our self.result if node_op_res is ok, or
    /// the error if res is an error.
    /// NOTE: as of now, we don't pass the Node a node op to act on
    /// (e.g. no RPC can be a mutator yet)
    /// due to a lack of public API for it, but this scheme is useful
    /// for the future when RPC mutators are supported by the Duties API.
    pub async fn respond(mut self, node_op_res: Result<()>) -> Result<()> {
        let resp = match node_op_res {
            Ok(_) => JsonRpcResponse::result(self.result, self.id),
            Err(e) => {
                warn!("{}", &e.to_string());
                JsonRpcResponse::error(
                    "Something happened... Node couldn't process resultant operation.".to_string(),
                    -1,
                    Some(self.id),
                )
            }
        };
        self.resp_stream.respond(&resp).await?;
        info!("Rpc with id '{}' responded to succesfully.", self.id);
        Ok(self.resp_stream.finish().await?)
    }
}

/// A thin wrapper around qjsonrpc::Endpoint
/// to provide an rpc interface
pub struct RpcInterface {
    /// The underlying endpoint
    endpoint: Endpoint,

    /// Configured at construction for bind to at runtime
    socket_addr: SocketAddr,

    /// Used to verify that the sender has authority to request info
    public_key: PublicKey,
}

impl RpcInterface {
    /// ctor
    /// Makes a new rpc dir at node_base_dir/rpc and uses it for the RPC credentials
    /// If no rpc_public_key file is found, we create a pk/sk combination and store them.
    /// The same goes for the TLS certification
    pub fn new<P: AsRef<Path>>(node_base_dir: P, port: u16) -> Result<Self> {
        // make rpc base dir if needed
        let rpc_base_dir = node_base_dir.as_ref().join(RPC_DIRNAME);
        if !rpc_base_dir.is_dir() {
            fs::create_dir(&rpc_base_dir)?;
        }

        // load or generate a new pk if none exists
        let public_key = match Self::load_rpc_public_key(&rpc_base_dir)? {
            Some(pk) => pk,
            None => Self::store_new_rpc_keypair(&rpc_base_dir)?,
        };

        // init endpoint
        let endpoint = Endpoint::new(&rpc_base_dir, Some(RPC_CONNECTION_IDLE_TIMEOUT_MS))?;
        let socket_addr = format!("{}:{}", RPC_IP_ADDR_STR, port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        Ok(Self {
            endpoint,
            socket_addr,
            public_key,
        })
    }

    /// wrap the underlying rpc server bind() implentation
    pub fn bind(&mut self) -> Result<ConnectionStream> {
        Ok(self.endpoint.bind(&self.socket_addr)?)
    }

    /// Process an incoming connection stream.
    /// Basically, this wraps `IncomingJsonRpcRequest.get_next()`.
    /// Returns a Some(ResponseStream) if there is a new request to service
    /// or None if not.
    /// NOTE: in future, this can be used to also pass back a node operation,
    /// which means the returned response stream could be used to report
    /// the success/failure of the processing of that node operation
    /// (e.g. to mutate the node state)
    pub async fn process_next(
        &self,
        conn: &mut Connection,
        node_info: &NodeInfo,
        used_space: UsedSpace,
        network: Network,
    ) -> Result<Option<ResponseStream>> {
        if let Some((req, mut qjsonrpc_resp_stream)) = conn.get_next().await {
            info!(
                "Rpc received {{ id: {}, method: {}, params: {} }}",
                &req.id, &req.method, &req.params,
            );

            // validate creds
            if let Err(resp) = self.verify_request(&req) {
                qjsonrpc_resp_stream.respond(&resp).await?;
                qjsonrpc_resp_stream.finish().await?;
                return Ok(None);
            }

            // Delegate the request to the proper submodule to get
            // back the `Value` to respond with
            match process_request(
                req.method.as_str(),
                &req.params[PAYLOAD_FIELDNAME],
                req.id,
                node_info,
                used_space,
                network.clone(),
            )
            .await
            {
                Ok(val) => {
                    let resp_stream = ResponseStream::new(val, req.id, qjsonrpc_resp_stream);
                    Ok(Some(resp_stream))
                }
                Err(resp) => {
                    qjsonrpc_resp_stream.respond(&resp).await?;
                    qjsonrpc_resp_stream.finish().await?;
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Verifies the request or returns an error response to respond with
    fn verify_request(&self, req: &JsonRpcRequest) -> std::result::Result<(), JsonRpcResponse> {
        // credentials are stored in named 'credentials' field
        let creds = {
            let val = req.params.get(CREDENTIALS_FIELDNAME).ok_or_else(|| {
                missing_param_resp("credentials", "sn_node_rpc_data_types::Credentials", req.id)
            })?;
            from_value::<Credentials>(val.clone()).map_err(|_| {
                invalid_param_resp("Credentials", "sn_node_rpc_data_types::Credentials", req.id)
            })
        }?;

        // verify
        self.public_key
            .verify(&creds.signature, &creds.passphrase.as_slice())
            .map_err(|_| bad_credentials_resp(req.id))
    }

    /// Helper which stores a new randomly generated
    /// public and private key as a hex string and gives back
    /// the public key
    fn store_new_rpc_keypair<P: AsRef<Path>>(rpc_base_dir: P) -> Result<PublicKey> {
        // gen key
        let keypair = Keypair::new_ed25519(&mut thread_rng());
        let pk_hex = vec_to_hex(keypair.public_key().to_bytes());
        let sk_hex = match keypair.secret_key().unwrap() {
            SecretKey::Ed25519(sk) => vec_to_hex(sk.as_bytes().to_vec()),
            _ => panic!(),
        };

        // store
        let pk_path = rpc_base_dir.as_ref().join(RPC_PK_FILENAME);
        let sk_path = rpc_base_dir.as_ref().join(RPC_SK_FILENAME);
        fs::write(&pk_path, pk_hex)?;
        fs::write(&sk_path, sk_hex)?;

        Ok(keypair.public_key())
    }

    /// Helper which loads and parses the public key hex
    /// from the file `rpc_root/RPC_PK_FILENAME`.
    /// Returns Ok(maybe_pk) if no errors. maybe_pk
    /// is Some(pk) if the file exists, otherwise None
    fn load_rpc_public_key<P: AsRef<Path>>(rpc_base_dir: P) -> Result<Option<PublicKey>> {
        // check exists
        let pk_path = rpc_base_dir.as_ref().join(RPC_PK_FILENAME);
        if !pk_path.is_file() {
            return Ok(None);
        }

        // fetch & parse
        let pk_hex = String::from_utf8(fs::read(&pk_path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let pk = PublicKey::Ed25519(
            ed25519_dalek::PublicKey::from_bytes(parse_hex(&pk_hex).as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        Ok(Some(pk))
    }
}

/// response formation for inability to verify credentials
fn bad_credentials_resp(id: u32) -> JsonRpcResponse {
    JsonRpcResponse::error(
        "Could not verify credentials. Access denied.".to_string(),
        NODERPC_ACCESS_DENIED,
        Some(id),
    )
}
