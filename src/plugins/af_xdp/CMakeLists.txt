# Copyright (c) 2018 Cisco and/or its affiliates.
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

vpp_find_path(XDP_INCLUDE_DIR NAMES xdp/xsk.h)
if (NOT XDP_INCLUDE_DIR)
  message(WARNING "libxdp headers not found - af_xdp plugin disabled")
  return()
endif()

set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
vpp_plugin_find_library(af_xdp XDP_LIB libxdp.a)
vpp_plugin_find_library(af_xdp BPF_LIB libbpf.a)
vpp_plugin_find_library(af_xdp ELF_LIB elf)
vpp_plugin_find_library(af_xdp Z_LIB z)
if (NOT XDP_LIB OR NOT BPF_LIB OR NOT ELF_LIB OR NOT Z_LIB)
  message(WARNING "af_xdp plugin - missing libraries - af_xdp plugin disabled")
  return()
endif()

set(CMAKE_REQUIRED_FLAGS "-fPIC")
set(CMAKE_REQUIRED_INCLUDES "${XDP_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "${XDP_LIB}" "${BPF_LIB}" "${ELF_LIB}" "${Z_LIB}")
CHECK_C_SOURCE_COMPILES("
#include <xdp/xsk.h>
int main(void)
{
    return xsk_socket__create (0, 0, 0, 0, 0, 0, 0);
}" XDP_COMPILES_CHECK)
if (NOT XDP_COMPILES_CHECK)
message(WARNING "af_xdp plugins - no working libxdp found - af_xdp plugin disabled")
  return()
endif()

include_directories(${XDP_INCLUDE_DIR})

add_vpp_plugin(af_xdp
  SOURCES
  api.c
  cli.c
  device.c
  format.c
  unformat.c
  plugin.c
  input.c
  output.c

  MULTIARCH_SOURCES
  input.c
  output.c

  API_FILES
  af_xdp.api

  API_TEST_SOURCES
  unformat.c
  test_api.c

  LINK_LIBRARIES
  ${XDP_LIB}
  ${BPF_LIB}
  ${ELF_LIB}
  ${Z_LIB}

  SUPPORTED_OS_LIST Linux
)
