#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=8443c09c0f091482679e0b32c4f238928b7f5c1e

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
