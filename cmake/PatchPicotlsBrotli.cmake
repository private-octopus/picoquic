# Backport the Brotli opt-in switch until the pinned picotls includes it.
# Upstream: https://github.com/h2o/picotls/pull/663
if(NOT DEFINED PICOTLS_SOURCE_DIR)
    message(FATAL_ERROR "PICOTLS_SOURCE_DIR is required")
endif()
get_filename_component(PICOTLS_SOURCE_DIR "${PICOTLS_SOURCE_DIR}" ABSOLUTE)
file(READ "${PICOTLS_SOURCE_DIR}/CMakeLists.txt" _picotls_cmake)
if(_picotls_cmake MATCHES "OPTION\\(WITH_BROTLI ")
    return()
endif()

find_package(Git REQUIRED)
set(_brotli_patch "${CMAKE_CURRENT_LIST_DIR}/../ci/picotls-brotli.patch")
# Do not let git apply silently scope a vendored snapshot to its parent repo.
get_filename_component(_picotls_parent "${PICOTLS_SOURCE_DIR}" DIRECTORY)
set(_git_apply "${CMAKE_COMMAND}" -E env "GIT_CEILING_DIRECTORIES=${_picotls_parent}" "${GIT_EXECUTABLE}" apply)
execute_process(COMMAND ${_git_apply} --check "${_brotli_patch}"
    WORKING_DIRECTORY "${PICOTLS_SOURCE_DIR}"
    RESULT_VARIABLE _patch_check OUTPUT_VARIABLE _patch_output ERROR_VARIABLE _patch_error)
if(NOT _patch_check EQUAL 0)
    message(FATAL_ERROR "Cannot add the picotls Brotli switch: ${_patch_output}${_patch_error}")
endif()
execute_process(COMMAND ${_git_apply} "${_brotli_patch}"
    WORKING_DIRECTORY "${PICOTLS_SOURCE_DIR}"
    RESULT_VARIABLE _patch_result OUTPUT_VARIABLE _patch_output ERROR_VARIABLE _patch_error)
if(NOT _patch_result EQUAL 0)
    message(FATAL_ERROR "Cannot patch picotls: ${_patch_output}${_patch_error}")
endif()
file(READ "${PICOTLS_SOURCE_DIR}/CMakeLists.txt" _patched_picotls_cmake)
if(NOT _patched_picotls_cmake MATCHES "OPTION\\(WITH_BROTLI ")
    message(FATAL_ERROR "The picotls patch did not add WITH_BROTLI")
endif()
