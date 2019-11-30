#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=3fdf6a54c4c0762226afcbabda3b2016af5a8761

cd ..
# git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
git clone https://github.com/h2o/picotls
cd picotls
git checkout -q "$COMMIT_ID"
git submodule init
git submodule update
cmake $CMAKE_OPTS .
make -j$(nproc) all
cd ..
