# Copyright (c) 2023 Cisco and/or its affiliates.
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

vpp_find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
if (NOT PCAP_INCLUDE_DIR)
  message(WARNING "libpcap headers not found - bpf_trace_filter plugin disabled")
  return()
endif()

vpp_plugin_find_library(bpf_trace_filter PCAP_LIB libpcap.so)

if (NOT PCAP_LIB)
  message(WARNING "bpf_trace_filter plugin - missing libraries - bpf_trace_filter plugin disabled")
  return()
endif()

set(CMAKE_REQUIRED_FLAGS "-fPIC")
set(CMAKE_REQUIRED_INCLUDES "${PCAP_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "${PCAP_LIB}")

include_directories(${PCAP_INCLUDE_DIR})

add_vpp_plugin(bpf_trace_filter
  SOURCES
  cli.c
  plugin.c
  bpf_trace_filter.c
  api.c

  API_FILES
  bpf_trace_filter.api

  LINK_LIBRARIES
  ${PCAP_LIB}
)
