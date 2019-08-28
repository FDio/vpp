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

execute_process(
  COMMAND uname -r
  OUTPUT_VARIABLE KERNEL_RELEASE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

string (REGEX MATCH "[5-9]\\.[2-9]" KERNEL_RELEASE_MATCH ${KERNEL_RELEASE})

if (NOT KERNEL_RELEASE_MATCH)
  message(STATUS "kernel release: ${KERNEL_RELEASE}")
  message(WARNING "-- kernel & libbpf version 5.2 or newer required \
- af_xdp plugin disabled")
  return()
endif()

# Requires kernel headers to be installed.
# This keeps if_xdp.h in sync with current kernel headers.
# This solution is temporary, while if_xdp.h isn't stabilized enough to occur
# in standard location as: /usr/include.
# For more details take a look at: https://kernelnewbies.org/KernelHeaders
find_path(IF_XDP_INCLUDE_DIR NAMES linux/if_xdp.h
         PATHS /usr/src/linux-headers-${KERNEL_RELEASE}/include/uapi/)

if (NOT IF_XDP_INCLUDE_DIR)
  message(WARNING "-- af_xdp header if_xdp.h not found \
- af_xdp plugin disabled")
  return()
endif()

configure_file(
  ${IF_XDP_INCLUDE_DIR}/linux/if_xdp.h
  .
  COPYONLY
)

find_path(BPF_INCLUDE_DIR NAMES bpf/bpf.h)
find_path(LIBBPF_INCLUDE_DIR NAMES bpf/libbpf.h)
find_path(XSK_INCLUDE_DIR NAMES bpf/xsk.h)

if (NOT BPF_INCLUDE_DIR OR NOT LIBBPF_INCLUDE_DIR OR NOT XSK_INCLUDE_DIR)
  message(WARNING "-- af_xdp headers not found - af_xdp plugin disabled")
  return()
endif()

vpp_plugin_find_library(af_xdp LIBELF_SHLIB "libelf.so")
vpp_plugin_find_library(af_xdp LIBBPF_SHLIB "libbpf.so")

add_vpp_plugin(af_xdp
  SOURCES
  cli.c
  device.c
  format.c
  plugin.c
  input.c

  MULTIARCH_SOURCES
  input.c

  LINK_LIBRARIES
  bpf
  elf
)
