# - Try to find Picotls

find_path(PICOTLS_INCLUDE_DIR
    NAMES picotls.h picotls/openssl.h picotls/minicrypto.h
    HINTS ${CMAKE_BINARY_DIR}/../picotls/include )

MESSAGE (STATUS "found picotls.h at ${PICOTLS_INCLUDE_DIR}" )

FIND_LIBRARY(PTLS_CORE picotls-core
     HINTS $(CMAKE_BINARY_DIR)/../picotls)

MESSAGE(STATUS "Found picotls-core at : ${PTLS_CORE}" )

FIND_LIBRARY(PTLS_MINICRYPTO picotls-minicrypto
     HINTS $(CMAKE_LIBRARY_DIR)/../picotls)

MESSAGE(STATUS "Found picotls-crypto at : ${PTLS_MINICRYPTO}" )

FIND_LIBRARY(PTLS_OPENSSL picotls-openssl
     HINTS $(CMAKE_LIBRARY_DIR)/q../picotls)

MESSAGE(STATUS "Found picotls-openssl at : ${PTLS_OPENSSL}" )

