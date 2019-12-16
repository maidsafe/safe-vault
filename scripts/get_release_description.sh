#!/usr/bin/env bash

version=$1
if [[ -z "$version" ]]; then
    echo "You must supply a version number."
    exit 1
fi

# The single quotes around EOF is to stop attempted variable and backtick expansion.
read -r -d '' release_description << 'EOF'
Implements a SAFE Network Vault.

## SHA-256 checksums for release versions:
```
Linux
zip: ZIP_LINUX_CHECKSUM
tar.gz: TAR_LINUX_CHECKSUM

macOS
zip: ZIP_MACOS_CHECKSUM
tar.gz: TAR_MACOS_CHECKSUM

Windows
zip: ZIP_WIN_CHECKSUM
tar.gz: TAR_WIN_CHECKSUM
```

## Related Links
* [SAFE CLI](https://github.com/maidsafe/safe-cli/releases/latest/)
* [SAFE Authenticator CLI](https://github.com/maidsafe/safe-authenticator-cli/releases/latest/)
* [SAFE Browser PoC](https://github.com/maidsafe/safe_browser/releases/)
EOF

zip_linux_checksum=$(sha256sum \
    "./deploy/prod/safe_vault-$version-x86_64-unknown-linux-musl.zip" | \
    awk '{ print $1 }')
zip_macos_checksum=$(sha256sum \
    "./deploy/prod/safe_vault-$version-x86_64-apple-darwin.zip" | \
    awk '{ print $1 }')
zip_win_checksum=$(sha256sum \
    "./deploy/prod/safe_vault-$version-x86_64-pc-windows-gnu.zip" | \
    awk '{ print $1 }')
tar_linux_checksum=$(sha256sum \
    "./deploy/prod/safe_vault-$version-x86_64-unknown-linux-musl.tar.gz" | \
    awk '{ print $1 }')
tar_macos_checksum=$(sha256sum \
    "./deploy/prod/safe_vault-$version-x86_64-apple-darwin.tar.gz" | \
    awk '{ print $1 }')
tar_win_checksum=$(sha256sum \
    "./deploy/prod/safe_vault-$version-x86_64-pc-windows-gnu.tar.gz" | \
    awk '{ print $1 }')

release_description=$(sed "s/ZIP_LINUX_CHECKSUM/$zip_linux_checksum/g" <<< "$release_description")
release_description=$(sed "s/ZIP_MACOS_CHECKSUM/$zip_macos_checksum/g" <<< "$release_description")
release_description=$(sed "s/ZIP_WIN_CHECKSUM/$zip_win_checksum/g" <<< "$release_description")
release_description=$(sed "s/TAR_LINUX_CHECKSUM/$tar_linux_checksum/g" <<< "$release_description")
release_description=$(sed "s/TAR_MACOS_CHECKSUM/$tar_macos_checksum/g" <<< "$release_description")
release_description=$(sed "s/TAR_WIN_CHECKSUM/$tar_win_checksum/g" <<< "$release_description")
echo "$release_description"
