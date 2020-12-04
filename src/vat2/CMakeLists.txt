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
add_vpp_executable(vat2 ENABLE_EXPORTS NO_INSTALL
  SOURCES
  main.c
  plugin.c
  jsonconvert.c

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
  jsonconvert.c

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
##############################################################################
# vat2 headers
##############################################################################
install(
  FILES
  jsonconvert.h
  vat2_helpers.h
  DESTINATION include/vat2
  COMPONENT vpp-dev
)
