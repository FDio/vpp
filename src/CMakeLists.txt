cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project (vpp C)

execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE VPP_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "VPP version ${VPP_VERSION}")
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

add_definitions (-DHAVE_MEMFD_CREATE -DVPP_API_TEST_BUILTIN=1)

##############################################################################
# functions
##############################################################################
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

# install header files into include subdir
function (install_hdrs path)
  foreach(file ${ARGN})
    get_filename_component(dir ${file} DIRECTORY)
    install(FILES ${file} DESTINATION include/${path}/${dir})
  endforeach()
endfunction()

##############################################################################
# subdirs
##############################################################################
foreach (DIR vppinfra svm vlib vlibmemory vnet vpp vcl)
  add_subdirectory(${DIR})
endforeach ()

