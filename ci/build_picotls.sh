#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=4e6080b6a1ede0d3b23c72a8be73b46ecaf1a084

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
git submodule init
git submodule update
cmake $CMAKE_OPTS .
make -j$(nproc) all
cd ..
