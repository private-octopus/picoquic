CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(picoquic)

# FIND_PACKAGE(PkgConfig REQUIRED)

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")

INCLUDE_DIRECTORIES(picoquic picoquictest)

SET(PICOQUIC_LIBRARY_FILES
    picoquic/fnv1a.c
    picoquic/frames.c
    picoquic/http0dot9.c
    picoquic/intformat.c
    picoquic/logger.c
    picoquic/newreno.c
    picoquic/packet.c
    picoquic/picohash.c
    picoquic/quicctx.c
    picoquic/sacks.c
    picoquic/sender.c
    picoquic/tls_api.c
    picoquic/transport.c
    picoquic/util.c
)

SET(PICOQUIC_TEST_LIBRARY_FILES
    picoquictest/cnx_creation_test.c
    picoquictest/float16test.c
    picoquictest/fnv1atest.c
    picoquictest/hashtest.c
    picoquictest/http0dot9test.c
    picoquictest/intformattest.c
    picoquictest/parseheadertest.c
    picoquictest/pn2pn64test.c
    picoquictest/sacktest.c
    picoquictest/sim_link.c
    picoquictest/stream0_frame_test.c
    picoquictest/tls_api_test.c
    picoquictest/transport_param_test.c
)

ADD_LIBRARY(picoquic-core ${PICOQUIC_LIBRARY_FILES})

ADD_LIBRARY(picoquic-test ${PICOQUIC_TEST_LIBRARY_FILES})

ADD_EXECUTABLE(picoquicdemo picoquicdemo/picoquicdemo.c ${PICOQUIC_LIBRARY_FILES})

ADD_EXECUTABLE(picoquicclitest picoquicclitest/picoquicclitest.c ${PICOQUIC_TEST_LIBRARY_FILES} ${PICOQUIC_LIBRARY_FILES})

SET(TEST_EXES picoquicclitest)
