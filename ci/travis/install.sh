#!/bin/bash

set -ex

# Add a rustup target for cross-compilation
if [ -n "$TARGET" ]; then
  sh ~/rust-installer/rustup.sh --prefix=$HOME/rust --add-target=$TARGET --disable-sudo
fi

# Configure toolchain
case "$TARGET" in
  arm*-gnueabihf)
    GCC_PREFIX=arm-linux-gnueabihf-
    ;;
  *-unknown-linux-musl)
    ./ci/travis/install_musl.sh
    GCC_PREFIX=musl-
    ;;
esac

if [ -n "$GCC_PREFIX" ]; then
  # Information about the cross compiler
  ${GCC_PREFIX}gcc -v

  # Tell cargo which linker to use for cross compilation
  mkdir -p .cargo
  echo "[target.$TARGET]" >> .cargo/config
  echo "linker = \"${GCC_PREFIX}gcc\"" >> .cargo/config
fi
