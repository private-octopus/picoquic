#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=5e0f82e184f1ae79de58837819b13ea7ef89b6f1

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
