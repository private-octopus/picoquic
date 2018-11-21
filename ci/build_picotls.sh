#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=c5bbb1cac0f6537b80837c8ba83d1ef892b28c28

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
