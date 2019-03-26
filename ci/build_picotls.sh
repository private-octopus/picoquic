#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=7898a8d4feab966d9f32b98a776763a9e7b7fd4b

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout -q "$COMMIT_ID"
# git submodule init
# git submodule update
cmake $CMAKE_OPTS .
make -j$(nproc) all
cd ..
