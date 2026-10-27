#!/bin/sh
# build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=e446233b4100ebcdec60901c05bfb7f4cd369c5d

cd .. || exit
# git clone --branch master --single-branch --shallow-submodules --recurse-submodules \
#     --no-tags https://github.com/h2o/picotls
git clone https://github.com/h2o/picotls
cd picotls || exit
git checkout -q "$COMMIT_ID"
git submodule init
git submodule update
# shellcheck disable=SC2154
echo "Using options:  $PTLS_CMAKE_OPTS"
# shellcheck disable=SC2086
cmake $PTLS_CMAKE_OPTS -DWITH_BROTLI=OFF . || exit
# shellcheck disable=SC2046
make -j$(nproc) all
cd .. || exit
