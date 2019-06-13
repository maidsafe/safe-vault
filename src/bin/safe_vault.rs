// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! SAFE Vault provides the interface to SAFE routing.  The resulting executable is the Vault node
//! for the SAFE network.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

use env_logger;
use log::info;
use log4rs;
use quic_p2p::Config as QuickP2pConfig;
use safe_vault::{self, Vault};
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
};
use structopt::StructOpt;

/// Vault configuration
#[derive(StructOpt)]
pub struct Config {
    #[allow(missing_docs)]
    #[structopt(flatten)]
    pub quic_p2p_config: QuickP2pConfig,
}

/// Runs a SAFE Network vault.
pub fn main() {
    if safe_vault::log_config_file_path()
        .and_then(|path| log4rs::init_file(path, Default::default()).ok())
        .is_none()
    {
        env_logger::init();
    }

    let config = {
        let mut config = Config::from_args();
        // Override the existing default 0.0.0.0
        let default_listening_ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        config.quic_p2p_config.ip = config.quic_p2p_config.ip.or(default_listening_ip);
        config
    };

    let name = exe_name().unwrap_or_else(|| "vault".to_string());

    let message = format!("Running {} v{}", name, env!("CARGO_PKG_VERSION"));
    info!("\n\n{}\n{}", message, "=".repeat(message.len()));

    match Vault::new(config.quic_p2p_config) {
        Ok(mut vault) => vault.run(),
        Err(e) => {
            println!("Cannot start vault due to error: {:?}", e);
        }
    }
}

fn exe_name() -> Option<String> {
    env::current_exe()
        .ok()?
        .file_stem()?
        .to_str()
        .map(|name| name.to_string())
}
