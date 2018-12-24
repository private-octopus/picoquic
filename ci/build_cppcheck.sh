#!/bin/sh
#build last cppcheck 1.84 (for Travis)

cd ..
git clone https://github.com/danmar/cppcheck.git
cd cppcheck
git checkout Cppcheck
cmake .
make -j$(nproc) all
sudo make install
cd ..
