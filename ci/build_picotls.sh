#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=241f684346d3be4f5ba8dc46010e9f9486a79991

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
