cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project (vpp C)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

message(STATUS "We are on a ${CMAKE_SYSTEM_NAME} system")
message(STATUS "The host processor is ${CMAKE_HOST_SYSTEM_PROCESSOR}")

# compile options
option(VPP_BUILD_VPPINFRA_TESTS "Build vppinfra tests." OFF)
option(VPP_USE_DLMALLOC "Use dlmalloc memory allocator." ON)

include_directories (
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_definitions (-DHAVE_MEMFD_CREATE -DVPP_API_TEST_BUILTIN=1)

function(VPP_API_GENERATE_H file)
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  add_custom_command (OUTPUT ${output_name}
    COMMAND mkdir -p ${output_dir}
    COMMAND ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen
    ARGS --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} --output ${output_name}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Generating API header ${file}.h"
  )
endfunction()

foreach (DIR vppinfra svm vlib vlibmemory vnet vpp)
  add_subdirectory(${DIR})
endforeach ()

