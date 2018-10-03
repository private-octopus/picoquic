#!/bin/sh
#build last picotls master (for Travis)

# Build at a known-good commit
# Must select a commit date (can copy-paste from git log)
COMMIT_ID=ed9b9fee4ce8484ab86280e017bb5aafbd60adc3
COMMIT_DATE="Wed Oct 3 11:06:54 2018 +0900"

cd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags --shallow-since="$COMMIT_DATE" https://github.com/h2o/picotls
cd picotls
git checkout "$COMMIT_ID"
#git submodule init
#git submodule update
cmake .
make -j$(nproc) all
cd ..
