#!/bin/bash
# Copyright (c) 2025 Internet Mastering & Company, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Build release by default
BUILD_TYPE="${1:-release}"

if [ "$BUILD_TYPE" = "debug" ]; then
    echo "Building Arti FFI library (debug)..."
    cargo build
else
    echo "Building Arti FFI library (release)..."
    cargo build --release
fi

echo "Build complete: target/$BUILD_TYPE/libarti_vpp_ffi.so"
