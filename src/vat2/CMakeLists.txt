# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##############################################################################
# vat2
##############################################################################
add_vpp_executable(vat2 ENABLE_EXPORTS
  SOURCES
  main.c
  plugin.c

  DEPENDS api_headers

  LINK_LIBRARIES
  vlibmemoryclient
  svm
  vppinfra
  vppapiclient
  Threads::Threads
  rt m dl crypto
)

#
# Unit test code. Call generator directly to avoid it being installed
#set_source_files_properties(vat2_test.c PROPERTIES
#  COMPILE_FLAGS " -fsanitize=address"
#)

vpp_generate_api_c_header (test/vat2_test.api)
add_vpp_executable(test_vat2 ENABLE_EXPORTS NO_INSTALL
  SOURCES
  test/vat2_test.c

  DEPENDS api_headers

  LINK_LIBRARIES
  vlibmemoryclient
  svm
  vppinfra
  vppapiclient
  Threads::Threads
  rt m dl crypto
)
#target_link_options(test_vat2 PUBLIC "LINKER:-fsanitize=address")

if("${CMAKE_VERSION}" VERSION_GREATER_EQUAL "3.13" AND "${CMAKE_C_COMPILER_ID}" MATCHES "(Apple)?[Cc]lang")
  set(TARGET_NAME test_vat2)

  message("Building with llvm Code Coverage Tools ${TARGET_NAME}")
  target_compile_options(${TARGET_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_link_options(${TARGET_NAME} PRIVATE -fprofile-instr-generate -fcoverage-mapping)
  target_compile_options(${TARGET_NAME} PRIVATE -fsanitize=address)
  target_link_options(${TARGET_NAME} PRIVATE -fsanitize=address)

  # llvm-cov
  add_custom_target(${TARGET_NAME}-ccov-preprocessing
    COMMAND LLVM_PROFILE_FILE=${TARGET_NAME}.profraw $<TARGET_FILE:${TARGET_NAME}>
    COMMAND llvm-profdata merge -sparse ${TARGET_NAME}.profraw -o ${TARGET_NAME}.profdata
    DEPENDS ${TARGET_NAME})

  add_custom_target(${TARGET_NAME}-ccov-show
    COMMAND llvm-cov show $<TARGET_FILE:${TARGET_NAME}> -instr-profile=${TARGET_NAME}.profdata -show-line-counts-or-regions ${COV_SOURCES}
    DEPENDS ${TARGET_NAME}-ccov-preprocessing)

  add_custom_target(${TARGET_NAME}-ccov-report
    COMMAND llvm-cov report -show-functions $<TARGET_FILE:${TARGET_NAME}> -instr-profile=${TARGET_NAME}.profdata ${COV_SOURCES}
    DEPENDS ${TARGET_NAME}-ccov-preprocessing)

  add_custom_target(${TARGET_NAME}-ccov
    COMMAND llvm-cov show $<TARGET_FILE:${TARGET_NAME}> -instr-profile=${TARGET_NAME}.profdata -show-line-counts-or-regions -output-dir=${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TARGET_NAME}-llvm-cov -format="html" ${COV_SOURCES}
    DEPENDS ${TARGET_NAME}-ccov-preprocessing)

  add_custom_command(TARGET ${TARGET_NAME}-ccov POST_BUILD
    COMMAND ;
    COMMENT "Open ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TARGET_NAME}-llvm-cov/index.html in your browser to view the coverage report."
)
endif()



##############################################################################
# vat2 headers
##############################################################################
install(
  FILES
  vat2_helpers.h
  DESTINATION include/vat2
  COMPONENT vpp-dev
)
