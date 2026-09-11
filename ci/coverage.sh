#!/bin/bash
# Build picoquic_ct/picohttp_ct with gcov instrumentation, run them, and emit an lcov HTML report.
# Usage: ci/coverage.sh [-o OUTPUT_DIR] [-b BUILD_DIR] [-j JOBS] [-f]

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

BUILD_DIR="$REPO_ROOT/build-coverage"
OUT_DIR="$REPO_ROOT/coverage-report"
JOBS=$(nproc 2>/dev/null || echo 4)
FRESH=0

usage() {
    echo "Usage: $0 [-o OUTPUT_DIR] [-b BUILD_DIR] [-j JOBS] [-f]"
    echo ""
    echo "  -o, --output DIR      HTML report output directory (default: coverage-report)"
    echo "  -b, --build-dir DIR   instrumented CMake build directory (default: build-coverage)"
    echo "  -j, --jobs N          parallel build jobs (default: nproc)"
    echo "  -f, --fresh           remove the build directory first for a clean rebuild"
    echo "  -h, --help            show this help"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output) OUT_DIR=$2; shift 2 ;;
        -b|--build-dir) BUILD_DIR=$2; shift 2 ;;
        -j|--jobs) JOBS=$2; shift 2 ;;
        -f|--fresh) FRESH=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

# dependency check
MISSING=()
for cmd in cmake gcc lcov genhtml; do
    command -v "$cmd" >/dev/null 2>&1 || MISSING+=("$cmd")
done
if [ ${#MISSING[@]} -ne 0 ]; then
    echo "Missing tools: ${MISSING[*]}" >&2
    echo "On Ubuntu/Debian: sudo apt-get install -y build-essential cmake lcov libssl-dev" >&2
    exit 1
fi

if [ "$FRESH" -eq 1 ] && [ -d "$BUILD_DIR" ]; then
    echo "Removing $BUILD_DIR for a clean rebuild"
    rm -rf "$BUILD_DIR"
fi

echo "Configuring instrumented build in $BUILD_DIR"
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" \
    -DPICOQUIC_FETCH_PTLS:BOOL=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="--coverage -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="--coverage" || exit 1

echo "Building (jobs=$JOBS)"
cmake --build "$BUILD_DIR" -j"$JOBS" || exit 1

# reset counters in case $BUILD_DIR was reused from a previous run
lcov --directory "$BUILD_DIR" --zero-counters --quiet

echo "Running picoquic_ct"
(cd "$BUILD_DIR" && ./picoquic_ct -S "$REPO_ROOT" -n -r)
PICOQUIC_STATUS=$?

echo "Running picohttp_ct"
(cd "$BUILD_DIR" && ./picohttp_ct -S "$REPO_ROOT" -n -r -x http_corrupt)
PICOHTTP_STATUS=$?

if [ "$PICOQUIC_STATUS" -ne 0 ] || [ "$PICOHTTP_STATUS" -ne 0 ]; then
    echo "Warning: picoquic_ct exit=$PICOQUIC_STATUS picohttp_ct exit=$PICOHTTP_STATUS -- report below only covers what ran" >&2
fi

echo "Capturing coverage"
lcov --directory "$BUILD_DIR" --capture --rc branch_coverage=1 \
    --ignore-errors mismatch,negative,inconsistent \
    --output-file "$BUILD_DIR/coverage.raw.info" || exit 1

# keep picoquic-core and picohttp-core only: drop test harnesses, fetched deps, system headers
lcov --rc branch_coverage=1 \
    --remove "$BUILD_DIR/coverage.raw.info" \
    '/usr/*' '*/_deps/*' '*/picoquic_t/*' '*/picohttp_t/*' '*/picoquictest/*' \
    --ignore-errors unused \
    --output-file "$BUILD_DIR/coverage.info" || exit 1

echo "Generating HTML report in $OUT_DIR"
genhtml --branch-coverage --rc branch_coverage=1 \
    --output-directory "$OUT_DIR" \
    --title "picoquic coverage $(date +%F)" \
    "$BUILD_DIR/coverage.info" || exit 1

echo ""
lcov --rc branch_coverage=1 --summary "$BUILD_DIR/coverage.info"
echo ""
echo "Report: $OUT_DIR/index.html"
