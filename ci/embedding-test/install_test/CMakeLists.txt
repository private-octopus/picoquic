cmake_minimum_required(VERSION 3.14)
project(install_test LANGUAGES C)

# Validate that an installed picoquic exports INTERFACE_INCLUDE_DIRECTORIES so
# that consumers can #include <picoquic.h> without manually specifying the path.
# Also validates that picohttp-core is exported as picoquic::picohttp-core.
find_package(picoquic REQUIRED)

add_executable(install_test main.c)
target_link_libraries(install_test PRIVATE picoquic::picoquic-core)

if(TARGET picoquic::picohttp-core)
    add_executable(install_test_http main_http.c)
    target_link_libraries(install_test_http PRIVATE picoquic::picohttp-core)
endif()
