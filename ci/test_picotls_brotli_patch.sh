#!/bin/sh
set -eu

picotls_source=${1:?usage: test_picotls_brotli_patch.sh PICOTLS_SOURCE TEST_DIRECTORY}
test_dir=${2:?usage: test_picotls_brotli_patch.sh PICOTLS_SOURCE TEST_DIRECTORY}
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# A vendored source snapshot has no .git, but can live in a parent repository.
mkdir -p "$test_dir/vendor/picotls"
git init -q "$test_dir"
git -C "$picotls_source" show HEAD:CMakeLists.txt > "$test_dir/vendor/picotls/CMakeLists.txt"
cmake -DPICOTLS_SOURCE_DIR="$test_dir/vendor/picotls" -P "$source_dir/cmake/PatchPicotlsBrotli.cmake"
grep -q 'OPTION(WITH_BROTLI ' "$test_dir/vendor/picotls/CMakeLists.txt"
cp "$test_dir/vendor/picotls/CMakeLists.txt" "$test_dir/once.txt"
cmake -DPICOTLS_SOURCE_DIR="$test_dir/vendor/picotls" -P "$source_dir/cmake/PatchPicotlsBrotli.cmake"
cmp "$test_dir/once.txt" "$test_dir/vendor/picotls/CMakeLists.txt"
echo 'Vendored picotls patch and repeated application checks passed'
