#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=a834170c3529ace968b6588f1aec793ba4a6e3d6

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake $CMAKE_OPTS .
make -j$(nproc) all
cd ..
