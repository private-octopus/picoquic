cmake_minimum_required(VERSION 3.14)
project(sample_lib VERSION 1.0.0 LANGUAGES C)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Embed picoquic. When building locally, override the fetch with:
#   -DFETCHCONTENT_SOURCE_DIR_PICOQUIC=<path-to-picoquic-root>
# ---------------------------------------------------------------------------
FetchContent_Declare(
    picoquic
    GIT_REPOSITORY https://github.com/private-octopus/picoquic.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(picoquic)

# ---------------------------------------------------------------------------
# sample_lib: a thin library that uses picoquic-core
# ---------------------------------------------------------------------------
add_library(sample_lib sample_lib.c)

target_include_directories(sample_lib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# picoquic is a private dependency: picoquic.h appears only in sample_lib.c,
# not in any installed header, so consumers need not know about it.
target_link_libraries(sample_lib PRIVATE picoquic::picoquic-core)

# ---------------------------------------------------------------------------
# Install sample_lib. picoquic's own install rules (included via FetchContent)
# install picoquic-core and its dependencies when cmake --install runs, so
# sample_lib-config.cmake can find them via find_dependency(picoquic).
# ---------------------------------------------------------------------------
install(TARGETS sample_lib
    EXPORT sample_lib-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES sample_lib.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT sample_lib-targets
    FILE sample_lib-targets.cmake
    NAMESPACE sample_lib::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sample_lib
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sample_lib-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sample_lib-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sample_lib
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sample_lib-config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sample_lib
)
