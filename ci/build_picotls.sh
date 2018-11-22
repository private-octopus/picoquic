#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=5d6c78d018655dc65774ea3a41d318a6fe2bcb1d

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
