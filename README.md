# SAFE Vault

An autonomous network capable of data storage/publishing/sharing as well as computation, value transfer (cryptocurrency support), and more.
See the documentation for a more detailed description of the operations involved in data storage.

**Maintainer:** Andreas Fackler (andreas.fackler@maidsafe.net)

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/safe_vault)](https://crates.io/crates/safe_vault)|[![Documentation](https://docs.rs/safe_vault/badge.svg)](https://docs.rs/safe_vault)|[![Build Status](https://travis-ci.org/maidsafe/safe_vault.svg?branch=master)](https://travis-ci.org/maidsafe/safe_vault)|[![Build status](https://ci.appveyor.com/api/projects/status/ohu678c6ufw8b2bn/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/safe-vault/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/safe_vault.png?label=ready&title=Ready)](https://waffle.io/maidsafe/safe_vault)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Development

1. Prerequisites:

    * [Git](https://git-scm.com/downloads) for version control
    * [Cargo](https://www.rustup.rs/) for Rust

2. Clone this GitHub repository:

    ```bash
    git clone https://github.com/maidsafe/safe_vault.git
    ```

3. Build the app for production (this may take several minutes):

    ```bash
    cd safe_vault
    cargo build --release
    ```

    This should produce the SAFE Vault binary in the folder `safe_vault/target/release`.
    It will be called either `safe_vault` or `safe_vault.exe` depending on your platform.

### Running a local network

#### Configuring your vaults

1. In the same folder as above (`safe_vault/target/release`), add a few config files as described [here](https://forum.safedev.org/t/how-to-run-a-local-test-network/842).

    To use some default configs that should work out of the box:

    ```bash
    cp example-configs/*.config target/release/
    ```

2. Start your first vault:

    ```bash
    ./target/release/safe_vault --first
    ```

3. Start any additional vaults in separate terminals (you need to run at least `min_section_size` vaults based on your config):

    ```bash
    ./target/release/safe_vault
    ```

#### Configuring your browser

1. You'll need to use similar configs for your SAFE Browser if you want to connect to your local vaults, e.g. if building on Linux:

    ```bash
    cp example-configs/safe_vault.crust.config ../safe_browser/dist/linux-unpacked/safe-browser.crust.config
    cp example-configs/safe_vault.routing.config ../safe_browser/dist/linux-unpacked/safe-browser.routing.config
    ```

2. Open your SAFE Browser and create an account!

### Testing

To run tests locally:

```bash
cargo test
```

## Further Help

You can discuss development-related questions on the [SAFE Dev Forum](https://forum.safedev.org/).
Here are some good posts to get started:

- [How to run a local test network](https://forum.safedev.org/t/how-to-run-a-local-test-network/842)
- [How to develop for the SAFE Network](https://forum.safedev.org/t/how-to-develop-for-the-safe-network-draft/843)

## License

Licensed under either of

* the MaidSafe.net Commercial License, version 1.0 or later ([LICENSE](LICENSE))
* the General Public License (GPL), version 3 ([COPYING](COPYING) or http://www.gnu.org/licenses/gpl-3.0.en.html)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the MaidSafe Contributor Agreement ([CONTRIBUTOR](CONTRIBUTOR)), shall be
dual licensed as above, and you agree to be bound by the terms of the MaidSafe Contributor Agreement.
