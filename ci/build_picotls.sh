#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=86ccc558004c6808d6605d2c0e6f8dd13ebd1376

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
