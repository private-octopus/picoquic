message(STATUS "mbedtls/prefix: ${MBEDTLS_PREFIX}")

find_path(MBEDTLS_INCLUDE_DIR
    NAMES mbedtls/build_info.h psa/crypto.h
    HINTS ${MBEDTLS_PREFIX}/include/
        ${CMAKE_SOURCE_DIR}/../mbedtls/include/
        ${CMAKE_BINARY_DIR}/../mbedtls/include/
        ../mbedtls/include/
)

set(MBEDTLS_LIBRARY_HINTS
    ${MBEDTLS_PREFIX}/build/library
    ${CMAKE_BINARY_DIR}/../mbedtls/build/library
    ../mbedtls/build/library
    ../mbedtls/library
)

find_library(MBEDTLS_LIBRARY mbedtls HINTS ${MBEDTLS_LIBRARY_HINTS})
find_library(MBEDTLS_CRYPTO mbedcrypto HINTS ${MBEDTLS_LIBRARY_HINTS})
find_library(MBEDTLS_X509 mbedx509 HINTS ${MBEDTLS_LIBRARY_HINTS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS REQUIRED_VARS
    MBEDTLS_LIBRARY
    MBEDTLS_CRYPTO
    MBEDTLS_X509
    MBEDTLS_INCLUDE_DIR
)

if (MbedTLS_FOUND)
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDTLS_X509} ${MBEDTLS_CRYPTO})
    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
    mark_as_advanced(MBEDTLS_LIBRARIES MBEDTLS_INCLUDE_DIRS)
endif ()
