#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
COMMIT_ID=c91baf9c9971332d9280a7062943c54a4f13a7ec

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
