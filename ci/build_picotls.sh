#!/bin/sh
#build last picotls master (for Travis)

cd ..
git clone --depth 1 https://github.com/h2o/picotls
cd picotls
git submodule init
git submodule update
cmake .
make -j$(nproc) all
cd ..
