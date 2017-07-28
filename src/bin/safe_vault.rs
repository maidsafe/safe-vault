// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! SAFE Vault provides the interface to SAFE routing.  The resulting executable is the Vault node
//! for the SAFE network.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "https://maidsafe.net/img/favicon.ico",
       html_root_url = "https://docs.rs/safe_vault")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#[macro_use]
extern crate log;
extern crate maidsafe_utilities;
extern crate clap;
extern crate config_file_handler;
extern crate safe_vault;
#[macro_use]
extern crate unwrap;

use clap::{App, Arg};
use safe_vault::Vault;
use std::ffi::OsString;
use std::fs;

/// Runs a SAFE Network vault.
pub fn main() {
    // TODO - remove the following line once maidsafe_utilities is updated to use log4rs v4.
    let _ = fs::remove_file("Node.log");

    let name = config_file_handler::exe_file_stem().unwrap_or_else(|_| OsString::new());
    let name_and_version = format!("{} v{}", name.to_string_lossy(), env!("CARGO_PKG_VERSION"));

    let matches = App::new(name.to_string_lossy())
        .arg(Arg::with_name("first").short("f").long("first").help(
            "Run as the first Vault of a new network.",
        ))
        .version(env!("CARGO_PKG_VERSION"))
        .get_matches();

    let _ = maidsafe_utilities::log::init(false);

    let mut message = String::from("Running ");
    message.push_str(&name_and_version);
    let underline = unwrap!(String::from_utf8(vec![b'='; message.len()]));
    info!("\n\n{}\n{}", message, underline);

    loop {
        let mut vault = match Vault::new(matches.is_present("first"), true) {
            Ok(vault) => vault,
            Err(e) => {
                println!("Cannot start vault due to error: {:?}", e);
                return;
            }
        };
        if let Ok(true) = vault.run() {
            break;
        }
    }
}
