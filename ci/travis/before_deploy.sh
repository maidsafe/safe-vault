#!/bin/bash

# Print commands, but do not expand them (to not reveal secure tokens).
set -ev

# This works on both linux and osx
mktempd() {
  echo $(mktemp -d 2>/dev/null || mktemp -d -t tmp)
}

export RUST_BACKTRACE=1
cargo build --target $TARGET --release

# Tag this commit if not already tagged.
git config --global user.email qa@maidsafe.net
git config --global user.name MaidSafe-QA
git fetch --tags

if [ -z $(git tag -l | grep "$VERSION") ]; then
  git tag $VERSION -am "Version $VERSION" $TRAVIS_COMMIT
  git push https://${GH_TOKEN}@github.com/${TRAVIS_REPO_SLUG} tag $VERSION > /dev/null 2>&1
fi

TMP_DIR=$(mktempd)
OUT_DIR=$(pwd)

NAME="$PROJECT_NAME-v$VERSION-$PLATFORM"

mkdir $TMP_DIR/$NAME
cp target/$TARGET/release/$PROJECT_NAME $TMP_DIR/$NAME
cp -r installer/bundle/* $TMP_DIR/$NAME

pushd $TMP_DIR
tar czf $OUT_DIR/$NAME.tar.gz *
popd

rm -r $TMP_DIR
