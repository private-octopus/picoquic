#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=4d9f8a40d7f90abf1794ce141ecde98aba9d0c51

cd ..
# git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
git clone https://github.com/h2o/picotls
cd picotls
git checkout -q "$COMMIT_ID"
git submodule init
git submodule update
echo "Using options:  $PTLS_CMAKE_OPTS"
cmake $PTLS_CMAKE_OPTS .
make -j$(nproc) all
cd ..
