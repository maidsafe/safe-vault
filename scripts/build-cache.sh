#!/usr/bin/env bash

if [[ -z "$build_type" ]]; then
    echo "build_type must be set to mock or non-mock"
    exit 1
fi

if [[ "$build_type" == "mock" ]]; then
    cargo test --release --features=mock --no-default-features
else
    cargo build --release
fi
