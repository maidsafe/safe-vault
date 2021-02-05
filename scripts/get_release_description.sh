#!/usr/bin/env bash

version=$1
if [[ -z "$version" ]]; then
    echo "You must supply a version number."
    exit 1
fi

# The single quotes around EOF is to stop attempted variable and backtick expansion.
read -r -d '' release_description << 'EOF'
Implements a Safe Network Node.

## Changelog:
CHANGELOG_TEXT


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
* [Safe CLI and Authenticator daemon](https://github.com/maidsafe/sn_api/releases/latest/)
* [Safe Browser](https://github.com/maidsafe/sn_browser/releases/)
EOF

# To include the changelog, which has newlines `\n`, we need to use sed to replace the newlines with `\\n`
changelog_text=$(awk '/# \[/{c++;p=1}{if(c==2){exit}}p;' CHANGELOG.md | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g')
zip_linux_checksum=$(sha256sum \
    "./deploy/prod/sn_node-$version-x86_64-unknown-linux-musl.zip" | \
    awk '{ print $1 }')
zip_macos_checksum=$(sha256sum \
    "./deploy/prod/sn_node-$version-x86_64-apple-darwin.zip" | \
    awk '{ print $1 }')
zip_win_checksum=$(sha256sum \
    "./deploy/prod/sn_node-$version-x86_64-pc-windows-msvc.zip" | \
    awk '{ print $1 }')
tar_linux_checksum=$(sha256sum \
    "./deploy/prod/sn_node-$version-x86_64-unknown-linux-musl.tar.gz" | \
    awk '{ print $1 }')
tar_macos_checksum=$(sha256sum \
    "./deploy/prod/sn_node-$version-x86_64-apple-darwin.tar.gz" | \
    awk '{ print $1 }')
tar_win_checksum=$(sha256sum \
    "./deploy/prod/sn_node-$version-x86_64-pc-windows-msvc.tar.gz" | \
    awk '{ print $1 }')

# Need to use something like `=` instead of the usual `\` in the commands below because the changelog has `\` characters`
release_description=$(sed "s=CHANGELOG_TEXT=$changelog_text=g" <<< "$release_description")
release_description=$(sed "s=ZIP_LINUX_CHECKSUM=$zip_linux_checksum=g" <<< "$release_description")
release_description=$(sed "s=ZIP_MACOS_CHECKSUM=$zip_macos_checksum=g" <<< "$release_description")
release_description=$(sed "s=ZIP_WIN_CHECKSUM=$zip_win_checksum=g" <<< "$release_description")
release_description=$(sed "s=TAR_LINUX_CHECKSUM=$tar_linux_checksum=g" <<< "$release_description")
release_description=$(sed "s=TAR_MACOS_CHECKSUM=$tar_macos_checksum=g" <<< "$release_description")
release_description=$(sed "s=TAR_WIN_CHECKSUM=$tar_win_checksum=g" <<< "$release_description")
echo "$release_description"
