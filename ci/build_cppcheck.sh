#!/bin/sh
# build last cppcheck 1.86 (for Travis)

cd .. || exit
git clone -b "2.1" --depth 1 https://github.com/danmar/cppcheck.git
cd cppcheck || exit
cmake .
make -j "$(nproc)" all
sudo make install
cd .. || exit
