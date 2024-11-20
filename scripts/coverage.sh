make clean
mkdir -p covr
find . -name "*.gcda" -exec rm {} \;
find . -name "*.gcno" -exec rm {} \;
find . -name "*.gcov" -exec rm {} \;
COVERAGE="-fprofile-arcs -ftest-coverage"
echo $COVERAGE
cmake "-DCMAKE_C_FLAGS=$COVERAGE" "-DCMAKE_CC_FLAGS=$COVERAGE" .
make
./picoquic_ct -n
./picohttp_ct -n
gcovr -r . --gcov-ignore-parse-errors --html -o cover.html
gcovr -r . --gcov-ignore-parse-errors --html-details -o covr/covr.html
