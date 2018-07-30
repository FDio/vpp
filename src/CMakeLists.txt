cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project (vpp C)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

message(STATUS "We are on a ${CMAKE_SYSTEM_NAME} system")
message(STATUS "The host processor is ${CMAKE_HOST_SYSTEM_PROCESSOR}")

include_directories (
	${CMAKE_SOURCE_DIR}
	${CMAKE_BINARY_DIR}
)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_definitions (-DUSE_DLMALLOC=1 -DHAVE_MEMFD_CREATE -DVPP_API_TEST_BUILTIN=1)

foreach (DIR vppinfra svm vlib vlibmemory vnet vpp)
  add_subdirectory(${DIR})
endforeach ()

