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

find_path(IF_XDP_INCLUDE_DIR NAMES linux/if_xdp.h)
find_path(BPF_INCLUDE_DIR NAMES bpf/bpf.h)
find_path(LIBBPF_INCLUDE_DIR NAMES bpf/libbpf.h)

if (NOT IF_XDP_INCLUDE_DIR OR NOT BPF_INCLUDE_DIR OR NOT LIBBPF_INCLUDE_DIR)
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
