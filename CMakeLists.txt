cmake_minimum_required(VERSION 2.8.11)
cmake_policy(SET CMP0003 NEW)
project(picoquic C CXX)
find_package (Threads REQUIRED)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "-std=c99 -Wall -Werror -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

if(DISABLE_DEBUG_PRINTF)
    set(CMAKE_C_FLAGS "-DDISABLE_DEBUG_PRINTF ${CMAKE_C_FLAGS}")
endif()

set(PICOQUIC_LIBRARY_FILES
    picoquic/bbr.c
    picoquic/bytestream.c
	picoquic/cc_common.c
    picoquic/cubic.c
    picoquic/fastcc.c
    picoquic/frames.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/logwriter.c
    picoquic/newreno.c
    picoquic/packet.c
    picoquic/picohash.c
    picoquic/picosocks.c
    picoquic/picosplay.c
    picoquic/quicctx.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/sim_link.c
    picoquic/spinbit.c
    picoquic/ticket_store.c
    picoquic/token_store.c
    picoquic/tls_api.c
    picoquic/transport.c
    picoquic/util.c
)

set(LOGLIB_LIBRARY_FILES
    loglib/autoqlog.c
    loglib/cidset.c
    loglib/csv.c
    loglib/logconvert.c
    loglib/logreader.c
    loglib/qlog.c
    loglib/svg.c
)

set(PICOQUIC_TEST_LIBRARY_FILES
    picoquictest/ack_of_ack_test.c
    picoquictest/bytestream_test.c
    picoquictest/cleartext_aead_test.c
    picoquictest/cplusplus.cpp
    picoquictest/cnx_creation_test.c
    picoquictest/hashtest.c
    picoquictest/intformattest.c
    picoquictest/multipath_test.c
    picoquictest/parseheadertest.c
    picoquictest/pn2pn64test.c
    picoquictest/sacktest.c
    picoquictest/skip_frame_test.c
    picoquictest/socket_test.c
    picoquictest/splay_test.c
    picoquictest/stream0_frame_test.c
    picoquictest/stresstest.c
    picoquictest/ticket_store_test.c
    picoquictest/tls_api_test.c
    picoquictest/transport_param_test.c
    picoquictest/util_test.c
)

set(PICOHTTP_LIBRARY_FILES
    picohttp/democlient.c
    picohttp/demoserver.c
    picohttp/h3zero.c
	picohttp/siduck.c
)

set(PICOHTTP_TEST_LIBRARY_FILES
    picoquictest/h3zerotest.c
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

add_library(picoquic-log
    ${LOGLIB_LIBRARY_FILES}
)

add_library(picohttp-core
    ${PICOHTTP_LIBRARY_FILES}
)

add_executable(picoquicdemo
    picoquicfirst/picoquicdemo.c
    picoquicfirst/getopt.c
)

target_link_libraries(picoquicdemo
    picoquic-log
    picoquic-core
    picohttp-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(picoquicdemo PRIVATE loglib picohttp)

add_executable(picolog_t
    picolog/picolog.c
)

target_link_libraries(picolog_t
    picoquic-log
    picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(picolog_t PRIVATE loglib)

add_executable(picoquic_ct picoquic_t/picoquic_t.c
    ${PICOQUIC_TEST_LIBRARY_FILES}
)

target_link_libraries(picoquic_ct
    picoquic-log
    picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(picoquic_ct PRIVATE loglib)

add_executable(picohttp_ct picohttp_t/picohttp_t.c
    ${PICOQUIC_TEST_LIBRARY_FILES}
    ${PICOHTTP_TEST_LIBRARY_FILES}
)

target_link_libraries(picohttp_ct
    picoquic-log
    picoquic-core
    picohttp-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(picohttp_ct PRIVATE loglib picohttp)

add_executable(picoquic_sample
    sample/sample.c
    sample/sample_client.c
    sample/sample_server.c
)

target_link_libraries(picoquic_sample
    picoquic-log
    picoquic-core
    ${PTLS_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(picoquic_sample PRIVATE loglib picoquic)

set(TEST_EXES picoquic_ct picohttp_ct)

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
