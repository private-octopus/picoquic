#!/bin/sh
set -eu

pkg-config --exists libbrotlidec libbrotlienc
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${1:?usage: test_picotls_brotli.sh BUILD_DIRECTORY [CMAKE_OPTIONS...]}
shift

cmake -S "$source_dir" -B "$build_dir" -DPICOQUIC_FETCH_PTLS=ON \
    -DBUILD_SHARED_LIBS=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "$@"
cmake --build "$build_dir" --target picoquic_ct -j 2
test -s "$build_dir/compile_commands.json"
readelf -d "$build_dir/_deps/picotls-build/libpicotls-core.so" > "$build_dir/brotli-dynamic.txt"

if grep -Eq 'PICOTLS_USE_BROTLI|certificate_compression\.c' "$build_dir/compile_commands.json"; then
    echo 'Fetched picotls compiled Brotli certificate compression' >&2
    exit 1
fi
if grep -q 'libbrotli' "$build_dir/brotli-dynamic.txt"; then
    echo 'Fetched picotls retains a Brotli shared library dependency' >&2
    exit 1
fi
"$build_dir/picoquic_ct" -S "$source_dir" -n tls_api_certificate_compression_disabled \
    tls_api cert_verify_rsa client_auth
