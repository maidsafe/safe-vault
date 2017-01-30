#!/bin/bash

set -ex

# Skip test script if $ONLY_DEPLOY is defined.
[ -n "${ONLY_DEPLOY}" ] && exit 0

if [ -n "${TARGET}" ]; then
  ARG_TARGET=" --target ${TARGET}"
fi

if [ "${TRAVIS_RUST_VERSION}" = stable ]; then
  cargo fmt -- --write-mode=diff
  # build without features
  cargo rustc ${ARG_TARGET} --verbose --lib --profile test -- -Zno-trans
  cargo rustc ${ARG_TARGET} --verbose --bin safe_vault --profile test -- -Zno-trans
  cargo rustc ${ARG_TARGET} --verbose --lib -- -Zno-trans
  cargo rustc ${ARG_TARGET} --verbose --bin safe_vault -- -Zno-trans
  # test with mock crust enabled
  env RUSTFLAGS="-C opt-level=2 -C codegen-units=8" cargo test ${ARG_TARGET} --release --verbose --features use-mock-crust
elif [ "${TRAVIS_OS_NAME}" = linux ]; then
  cargo clippy
  cargo clippy --profile test
  cargo clippy --features use-mock-crust
  cargo clippy --profile test --features use-mock-crust
fi
