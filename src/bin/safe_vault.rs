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
// For explanation of lint checks, run `rustc -W help`.
#![deny(unsafe_code)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

fn main() {
    self::detail::main()
}

#[cfg(not(feature = "mock"))]
mod detail {
    use env_logger::{fmt::Formatter, Builder as LoggerBuilder};
    use log::{self, Level, Record};
    use safe_vault::{self, Command, Config, Vault};
    use self_update::cargo_crate_version;
    use self_update::Status;
    use std::{io::Write, process};
    use structopt::StructOpt;

    /// Runs a SAFE Network vault.
    pub fn main() {
        let mut config = Config::new();
        if config.quic_p2p_config().ip.is_none() {
            config.listen_on_loopback();
        }

        let do_format = move |formatter: &mut Formatter, record: &Record<'_>| {
            let now = formatter.timestamp();
            writeln!(
                formatter,
                "{} {} [{}:{}] {}",
                formatter.default_styled_level(record.level()),
                now,
                record.file().unwrap_or_default(),
                record.line().unwrap_or_default(),
                record.args()
            )
        };
        let mut logger = LoggerBuilder::from_default_env();
        let _ = logger.format(do_format).is_test(false);
        if config.verbose() != Level::Error {
            let _ = logger.filter(
                Config::clap().get_bin_name(),
                config.verbose().to_level_filter(),
            );
        }
        let _ = logger.try_init();

        match update() {
            Ok(status) => {
                if let Status::Updated { .. } = status {
                    println!("Vault has been updated. Please restart.");
                    process::exit(0);
                }
            }
            Err(e) => log::error!("Updating vault failed: {:?}", e),
        }

        let message = format!(
            "Running {} v{}",
            Config::clap().get_name(),
            env!("CARGO_PKG_VERSION")
        );
        log::info!("\n\n{}\n{}", message, "=".repeat(message.len()));

        let (command_tx, command_rx) = crossbeam_channel::bounded(1);

        // Shutdown the vault gracefully on SIGINT (Ctrl+C).
        let result = ctrlc::set_handler(move || {
            let _ = command_tx.send(Command::Shutdown);
        });
        if let Err(error) = result {
            log::error!("Failed to set interrupt handler: {:?}", error)
        }

        match Vault::new(config, command_rx) {
            Ok(mut vault) => vault.run(),
            Err(e) => {
                println!("Cannot start vault due to error: {:?}", e);
            }
        }
    }

    fn update() -> Result<Status, Box<dyn (::std::error::Error)>> {
        log::info!("Checking for updates...");
        let target = self_update::get_target()?;
        let releases = self_update::backends::github::ReleaseList::configure()
            .repo_owner("maidsafe")
            .repo_name("safe_vault")
            .with_target(&target)
            .build()?
            .fetch()?;
        if !releases.is_empty() {
            log::debug!("Target for update is {}", target);
            log::debug!("Found releases: {:#?}\n", releases);
            let bin_name = if target.contains("pc-windows") {
                "safe_vault.exe"
            } else {
                "safe_vault"
            };
            let status = self_update::backends::github::Update::configure()?
                .repo_owner("maidsafe")
                .repo_name("safe_vault")
                .target(&target)
                .bin_name(&bin_name)
                .show_download_progress(true)
                .no_confirm(true)
                .current_version(cargo_crate_version!())
                .build()?
                .update()?;
            println!("Update status: `{}`!", status.version());
            return Ok(status);
        }
        log::info!("Current version is {}", cargo_crate_version!());
        log::info!("No releases are available for updates");
        Ok(Status::UpToDate(
            "No releases are available for updates".to_string(),
        ))
    }
}

#[cfg(feature = "mock")]
mod detail {
    pub fn main() {
        println!("Cannot start vault with mock quic-p2p.");
    }
}
