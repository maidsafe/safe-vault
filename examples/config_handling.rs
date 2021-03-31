use anyhow::{anyhow, Result};
use sn_node::Config;
use std::{fs::remove_file, io};
use structopt::StructOpt;

// This example is to demonstrate how the node configuration is constructed
// The node will attempt to read a cached config file from disk
// The node will then overwrite the config using the provided command line args

// Note: This is essentially a test, but, when using test filtering, StructOpt
// tries to parse the filter as an argument passed resulting in a `UnmatchedArument` error.

fn main() -> Result<()> {
    // Create some config and write it to disk
    let mut file_config = Config {
        first: true,
        ..Default::default()
    };

    file_config.network_config.local_ip = Some(
        "192.168.0.1"
            .parse()
            .map_err(|_| anyhow!("Invalid IP address format"))?,
    );
    file_config.network_config.local_port = Some(0);
    file_config.network_config.external_port = Some(12345);
    file_config.write_to_disk()?;

    // This should load the config from disk and
    // use the command line arguments to overwrite the config
    // with any provided arguments
    let config = Config::new()?;

    let command_line_args = Config::from_args();

    if command_line_args.wallet_id.is_some() {
        assert_eq!(command_line_args.wallet_id, config.wallet_id)
    } else {
        assert_eq!(file_config.wallet_id, config.wallet_id)
    }

    if command_line_args.max_capacity.is_some() {
        assert_eq!(command_line_args.max_capacity, config.max_capacity)
    } else {
        assert_eq!(file_config.max_capacity, config.max_capacity)
    }

    if command_line_args.root_dir.is_some() {
        assert_eq!(command_line_args.root_dir, config.root_dir)
    } else {
        assert_eq!(file_config.root_dir, config.root_dir)
    }

    if command_line_args.verbose > 0 {
        assert_eq!(command_line_args.verbose, config.verbose)
    } else {
        assert_eq!(file_config.verbose, config.verbose)
    }

    assert_eq!(
        config.loopback,
        file_config.loopback || command_line_args.loopback
    );
    assert_eq!(config.lan, file_config.lan || command_line_args.lan);
    assert_eq!(config.first, file_config.first || command_line_args.first);

    if command_line_args.completions.is_some() {
        assert_eq!(command_line_args.completions, config.completions)
    } else {
        assert_eq!(file_config.completions, config.completions)
    }

    if command_line_args.log_dir.is_some() {
        assert_eq!(command_line_args.log_dir, config.log_dir)
    } else {
        assert_eq!(file_config.log_dir, config.log_dir)
    }

    assert_eq!(
        config.update,
        file_config.update || command_line_args.update
    );
    assert_eq!(
        config.update_only,
        file_config.update_only || command_line_args.update_only
    );
    assert_eq!(
        config.clear_data,
        file_config.clear_data || command_line_args.clear_data
    );

    if !command_line_args
        .network_config
        .hard_coded_contacts
        .is_empty()
    {
        assert_eq!(
            command_line_args.network_config.hard_coded_contacts,
            config.network_config.hard_coded_contacts
        )
    } else {
        assert_eq!(
            file_config.network_config.hard_coded_contacts,
            config.network_config.hard_coded_contacts
        )
    }

    if command_line_args.network_config.local_port.is_some() {
        assert_eq!(
            command_line_args.network_config.local_port,
            config.network_config.local_port
        )
    } else {
        assert_eq!(
            file_config.network_config.local_port,
            config.network_config.local_port
        )
    }

    if command_line_args.network_config.local_ip.is_some() {
        assert_eq!(
            command_line_args.network_config.local_ip,
            config.network_config.local_ip
        )
    } else {
        assert_eq!(
            file_config.network_config.local_ip,
            config.network_config.local_ip
        )
    }

    assert_eq!(
        config.network_config.forward_port,
        file_config.network_config.forward_port || command_line_args.network_config.forward_port
    );

    if command_line_args.network_config.external_port.is_some() {
        assert_eq!(
            command_line_args.network_config.external_port,
            config.network_config.external_port
        )
    } else {
        assert_eq!(
            file_config.network_config.external_port,
            config.network_config.external_port
        )
    }

    if command_line_args.network_config.external_ip.is_some() {
        assert_eq!(
            command_line_args.network_config.external_ip,
            config.network_config.external_ip
        )
    } else {
        assert_eq!(
            file_config.network_config.external_ip,
            config.network_config.external_ip
        )
    }

    if command_line_args
        .network_config
        .max_msg_size_allowed
        .is_some()
    {
        assert_eq!(
            command_line_args.network_config.max_msg_size_allowed,
            config.network_config.max_msg_size_allowed
        )
    } else {
        assert_eq!(
            file_config.network_config.max_msg_size_allowed,
            config.network_config.max_msg_size_allowed
        )
    }

    if command_line_args.network_config.idle_timeout_msec.is_some() {
        assert_eq!(
            command_line_args.network_config.idle_timeout_msec,
            config.network_config.idle_timeout_msec
        )
    } else {
        assert_eq!(
            file_config.network_config.idle_timeout_msec,
            config.network_config.idle_timeout_msec
        )
    }

    if command_line_args
        .network_config
        .keep_alive_interval_msec
        .is_some()
    {
        assert_eq!(
            command_line_args.network_config.keep_alive_interval_msec,
            config.network_config.keep_alive_interval_msec
        )
    } else {
        assert_eq!(
            file_config.network_config.keep_alive_interval_msec,
            config.network_config.keep_alive_interval_msec
        )
    }

    if command_line_args
        .network_config
        .bootstrap_cache_dir
        .is_some()
    {
        assert_eq!(
            command_line_args.network_config.bootstrap_cache_dir,
            config.network_config.bootstrap_cache_dir
        )
    } else {
        assert_eq!(
            file_config.network_config.bootstrap_cache_dir,
            config.network_config.bootstrap_cache_dir
        )
    }

    if command_line_args
        .network_config
        .upnp_lease_duration
        .is_some()
    {
        assert_eq!(
            command_line_args.network_config.upnp_lease_duration,
            config.network_config.upnp_lease_duration
        )
    } else {
        assert_eq!(
            file_config.network_config.upnp_lease_duration,
            config.network_config.upnp_lease_duration
        )
    }

    clear_disk_config()?;

    Ok(())
}

fn clear_disk_config() -> io::Result<()> {
    let mut path = dirs_next::home_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Home directory not found"))?;

    path.push(".safe");
    path.push("node");
    path.push("node.config");

    remove_file(path)
}
