cmake_minimum_required(VERSION 2.8.11)
cmake_policy(SET CMP0003 NEW)

project(picoquic)

set(CMAKE_C_STANDARD 11)

# FIND_PACKAGE(PkgConfig REQUIRED)

set(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

if(DISABLE_DEBUG_PRINTF)
    set(CMAKE_C_FLAGS "-DDISABLE_DEBUG_PRINTF ${CMAKE_C_FLAGS}")
endif()

set(PICOQUIC_LIBRARY_FILES
    picoquic/cubic.c
    picoquic/fnv1a.c
    picoquic/frames.c
    picoquic/h3zero.c
    picoquic/http0dot9.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/newreno.c
    picoquic/packet.c
    picoquic/picohash.c
    picoquic/picosocks.c
    picoquic/picosplay.c
    picoquic/quicctx.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/spinbit.c
    picoquic/ticket_store.c
    picoquic/tls_api.c
    picoquic/transport.c
    picoquic/util.c
)

set(PICOQUIC_TEST_LIBRARY_FILES
    picoquictest/ack_of_ack_test.c
    picoquictest/cleartext_aead_test.c
    picoquictest/cnx_creation_test.c
    picoquictest/float16test.c
    picoquictest/fnv1atest.c
    picoquictest/h3zerotest.c
    picoquictest/hashtest.c
    picoquictest/http0dot9test.c
    picoquictest/intformattest.c
    picoquictest/parseheadertest.c
    picoquictest/pn2pn64test.c
    picoquictest/sacktest.c
    picoquictest/skip_frame_test.c
    picoquictest/sim_link.c
    picoquictest/socket_test.c
    picoquictest/splay_test.c
    picoquictest/stream0_frame_test.c
    picoquictest/stresstest.c
    picoquictest/ticket_store_test.c
    picoquictest/tls_api_test.c
    picoquictest/transport_param_test.c
)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PTLS REQUIRED)
message(STATUS "picotls/include: ${PTLS_INCLUDE_DIRS}" )
message(STATUS "picotls libraries: ${PTLS_LIBRARIES}" )

find_package(OpenSSL )
message(STATUS "root: ${OPENSSL_ROOT_DIR}")
message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")

include_directories(picoquic picoquictest
    ${PTLS_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

add_library(picoquic-core
    ${PICOQUIC_LIBRARY_FILES}
)

add_executable(picoquicdemo picoquicfirst/picoquicdemo.c
                            picoquicfirst/getopt.c )
target_link_libraries(picoquicdemo picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

add_executable(picoquic_ct picoquic_t/picoquic_t.c
 ${PICOQUIC_TEST_LIBRARY_FILES} )
target_link_libraries(picoquic_ct picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

set(TEST_EXES picoquic_ct)

# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)

# Adds clangformat as target that formats all source files
add_custom_target(
    clangformat
    COMMAND clang-format
    -style=Webkit
    -i
    ${CLANG_FORMAT_SOURCE_FILES}
)
