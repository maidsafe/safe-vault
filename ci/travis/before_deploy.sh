#!/bin/bash

# Print commands, but do not expand them (to not reveal secure tokens).
set -ev

# This works on both linux and osx
mktempd() {
  echo $(mktemp -d 2>/dev/null || mktemp -d -t tmp)
}

if [ -n "${TARGET}" ]; then
  ARG_TARGET=" --target ${TARGET}"
fi

cargo build ${ARG_TARGET} --release

# Create the release archive
NAME="$PROJECT_NAME-v$PROJECT_VERSION-$PLATFORM"

WORK_DIR=$(mktempd)

# Clone the repo with the config files
CONFIG_DIR=$HOME/config
CONFIG_REPO_SLUG="maidsafe/release_config"

mkdir -p $CONFIG_DIR
git clone https://${GH_TOKEN}@github.com/${CONFIG_REPO_SLUG} $CONFIG_DIR

mkdir $WORK_DIR/$NAME
if [ -n "${TARGET}" ]; then
  cp target/$TARGET/release/$PROJECT_NAME $WORK_DIR/$NAME
else
  cp target/release/$PROJECT_NAME $WORK_DIR/$NAME
fi
cp -r ${CONFIG_DIR}/safe_vault/* $WORK_DIR/$NAME

pushd $WORK_DIR
tar czf $TRAVIS_BUILD_DIR/$NAME.tar.gz *
popd

rm -r $WORK_DIR

# Create packages
# case $PLATFORM in
# linux-x64|linux-x86)
#   PACKAGE_SCRIPT=linux/create_packages.sh
#   ;;
# osx-x64)
#   PACKAGE_SCRIPT=osx/create_package.sh
#   ;;
# esac

# if [ -n "$PACKAGE_SCRIPT" ]; then
#   gem install -N fpm
#   ./"installer/$PACKAGE_SCRIPT"
# fi
