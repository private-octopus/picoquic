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
INSTALL_PREFIX="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR" "$INSTALL_PREFIX"' EXIT

echo "==> Building and installing sample_lib (picoquic root: $PICOQUIC_ROOT)"
cmake -S "$SCRIPT_DIR/sample_lib" -B "$BUILD_DIR/sample_lib" \
    -DFETCHCONTENT_SOURCE_DIR_PICOQUIC="$PICOQUIC_ROOT" \
    -DPICOQUIC_FETCH_PTLS=ON \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DCMAKE_BUILD_TYPE=Release \
    "$@"
cmake --build "$BUILD_DIR/sample_lib"
cmake --install "$BUILD_DIR/sample_lib"

echo "==> Building sample_app"
cmake -S "$SCRIPT_DIR/sample_app" -B "$BUILD_DIR/sample_app" \
    -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX" \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR/sample_app"

echo "==> Running sample_app"
"$BUILD_DIR/sample_app/sample_app"
