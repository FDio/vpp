# Copyright (c) 2024 Cisco and/or its affiliates.
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

set(CMAKE_VERBOSE_MAKEFILE ON)

add_vpp_plugin(gpcapng
  SOURCES
  capture/main.c
  capture/gpcapng_node.c
  capture/gpcapng_nodemain.c
  capture/destination.c
  capture/destination_file.c
  capture/destination_http.c
  capture/gpcapng_filter_api.c

  MULTIARCH_SOURCES
  capture/gpcapng_node.c

  INSTALL_HEADERS
  capture/gpcapng_node.h
  capture/destination.h
  capture/write_pcapng.h
  lib/gpcapng_filter_api.h
  lib/public_inlines.h
  lib/exports.h
  lib/gpcapng.h
)

add_vpp_plugin(gpcapng_simple_filter
  SOURCES
  simple-filter/filter_main.c
  simple-filter/simple_filter.c
  simple-filter/filter.c
  simple-filter/output.c

  INSTALL_HEADERS
  simple-filter/simple_filter.h
  simple-filter/filter.h
)

add_vpp_plugin(gpcapng_trivial_filter
  SOURCES
  trivial-filter/filter_main.c
  trivial-filter/trivial_filter.c
  trivial-filter/trivial_cli.c

  INSTALL_HEADERS
  trivial-filter/trivial_filter.h
)

add_vpp_plugin(gpcapng_show_packets
  SOURCES
  show-packets/show_packets.c
)