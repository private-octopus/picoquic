#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=03674790ae42c0d3675c5b462c52988f67454e11

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
# git checkout "$COMMIT_ID"
git checkout
# git submodule init
# git submodule update
cmake $CMAKE_OPTS .
make -j$(nproc) all
cd ..
