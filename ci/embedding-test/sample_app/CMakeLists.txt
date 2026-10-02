cmake_minimum_required(VERSION 3.14)
project(sample_app LANGUAGES C)

find_package(sample_lib REQUIRED)

add_executable(sample_app main.c)
target_link_libraries(sample_app PRIVATE sample_lib::sample_lib)
