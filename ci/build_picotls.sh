#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
# Must select a commit date (can copy-paste from git log)
COMMIT_ID=a760bd5812441d3ef44fd34ae3c5aaab2016712d
COMMIT_DATE="Sat Jul 7 12:26:35 2018 +0900"

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags --shallow-since="$COMMIT_DATE" https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
