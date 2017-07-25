#!/bin/bash

set -ex

# Skip test script if $ONLY_DEPLOY is defined.
[ -n "${ONLY_DEPLOY}" ] && exit 0

if [ -n "${TARGET}" ]; then
  ARG_TARGET=" --target ${TARGET}"
fi

if [ "${TRAVIS_RUST_VERSION}" = 1.19.0 ]; then
  cargo fmt -- --write-mode=diff
  # build without features
  cargo check ${ARG_TARGET} --verbose --lib --tests
  cargo check ${ARG_TARGET} --verbose --bin safe_vault --tests

  # unit tests with mock routing
  env RUSTFLAGS="-C opt-level=2 -C codegen-units=8" cargo test ${ARG_TARGET} --release --verbose --features use-mock-routing

  # integration tests with mock crust
  env RUSTFLAGS="-C opt-level=2 -C codegen-units=8" cargo test ${ARG_TARGET} --release --verbose --features use-mock-crust
elif [ "${TRAVIS_OS_NAME}" = linux ]; then
  cargo clippy
  cargo clippy --features use-mock-crust
  cargo clippy --profile test
  cargo clippy --profile test --features use-mock-routing
  cargo clippy --profile test --features use-mock-crust
fi
