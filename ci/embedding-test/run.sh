#!/bin/bash
# Run the embedding test locally.
#
# Usage:
#   ci/embedding-test/run.sh [picoquic-root] [cmake-args...]
#
# picoquic-root defaults to the repository root (two directories above this
# script). Any additional arguments are passed directly to cmake.
#
# Examples (from the repository root):
#   ci/embedding-test/run.sh
#   ci/embedding-test/run.sh $(pwd)
#   ci/embedding-test/run.sh $(pwd) -DFETCHCONTENT_SOURCE_DIR_PICOTLS=/path/to/picotls

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PICOQUIC_ROOT="${1:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
shift 1 2>/dev/null || true

BUILD_DIR="$(mktemp -d)"
FETCHCONTENT_INSTALL="$(mktemp -d)"
STANDALONE_INSTALL="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR" "$FETCHCONTENT_INSTALL" "$STANDALONE_INSTALL"' EXIT

# --- Standalone install test ---
# Validates that an installed picoquic (as getdeps does it) correctly exports
# INTERFACE_INCLUDE_DIRECTORIES so consumers can #include <picoquic.h>.
echo "==> Building and installing picoquic standalone"
cmake -S "$PICOQUIC_ROOT" -B "$BUILD_DIR/picoquic" \
    -DPICOQUIC_FETCH_PTLS=ON \
    -DCMAKE_INSTALL_PREFIX="$STANDALONE_INSTALL" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    "$@"
cmake --build "$BUILD_DIR/picoquic"
cmake --install "$BUILD_DIR/picoquic"

echo "==> Building and running install_test against standalone install"
cmake -S "$SCRIPT_DIR/install_test" -B "$BUILD_DIR/install_test" \
    -DCMAKE_PREFIX_PATH="$STANDALONE_INSTALL" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR/install_test"
"$BUILD_DIR/install_test/install_test"

# --- FetchContent re-export test ---
# Validates that a library embedding picoquic via FetchContent correctly
# re-exports it to downstream consumers.
echo "==> Building and installing sample_lib (picoquic root: $PICOQUIC_ROOT)"
cmake -S "$SCRIPT_DIR/sample_lib" -B "$BUILD_DIR/sample_lib" \
    -DFETCHCONTENT_SOURCE_DIR_PICOQUIC="$PICOQUIC_ROOT" \
    -DPICOQUIC_FETCH_PTLS=ON \
    -DCMAKE_INSTALL_PREFIX="$FETCHCONTENT_INSTALL" \
    -DCMAKE_BUILD_TYPE=Release \
    "$@"
cmake --build "$BUILD_DIR/sample_lib"
cmake --install "$BUILD_DIR/sample_lib"

echo "==> Building and running sample_app"
cmake -S "$SCRIPT_DIR/sample_app" -B "$BUILD_DIR/sample_app" \
    -DCMAKE_PREFIX_PATH="$FETCHCONTENT_INSTALL" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR/sample_app"
"$BUILD_DIR/sample_app/sample_app"
