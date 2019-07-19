cmake_minimum_required(VERSION 3.5)

project(sample-plugin)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(VPP)

add_subdirectory(sample)

set(VPP_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../..")
# scripts/version provides ALSO the build number
execute_process(
  WORKING_DIRECTORY ${VPP_SRC}
  COMMAND scripts/version
  OUTPUT_VARIABLE VPP_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_vpp_packaging(
  NAME "sample-plugin"
  VENDOR "fd.io"
  DESCRIPTION "VPP Sample Plugin"
  VERSION ${VPP_VERSION} #Use scripts/version for internal project only
)
