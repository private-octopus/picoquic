# - Try to find libaegis
#
# Defines:
#   aegis_FOUND
#   AEGIS_INCLUDE_DIR
#   AEGIS_LIBRARY
#   AEGIS_LIBRARIES
#   aegis_LIBRARIES

find_path(AEGIS_INCLUDE_DIR
    NAMES aegis.h
    HINTS
        ${AEGIS_PREFIX}/include/aegis
        ${AEGIS_PREFIX}/include
    PATH_SUFFIXES aegis)

find_library(AEGIS_LIBRARY
    NAMES aegis
    HINTS
        ${AEGIS_PREFIX}/lib)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(aegis REQUIRED_VARS AEGIS_INCLUDE_DIR AEGIS_LIBRARY)

if(aegis_FOUND)
    set(AEGIS_LIBRARIES ${AEGIS_LIBRARY})
    set(aegis_LIBRARIES ${AEGIS_LIBRARY})
endif()

mark_as_advanced(AEGIS_INCLUDE_DIR AEGIS_LIBRARY AEGIS_LIBRARIES aegis_LIBRARIES)
