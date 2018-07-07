#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
# Must select a commit date (can copy-paste from git log)
COMMIT_ID=0e03d538945fbe83c3831b9a3ddc30eabc92d7c2
COMMIT_DATE="Thu Jun 21 21:21:03 2018 -1000"

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags --shallow-since="$COMMIT_DATE" https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
