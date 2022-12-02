#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=7e97d3e48e237b9a01227cf7f4b116325b356fc6

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
