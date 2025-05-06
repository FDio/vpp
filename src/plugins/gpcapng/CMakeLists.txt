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

add_vpp_plugin(gpcapng
  SOURCES
  main.c
  show_packets.c
  destination.c
  destination.h
  destination_igzip.c
  destination_http.c
  destination_gzip.c
  destination_file.c
  write_pcapng.c
  filter.c
  filter.h
  gpcapng_node.c
  gpcapng_node.h
  gpcapng_nodemain.c
  output.c

  MULTIARCH_SOURCES
  gpcapng_node.c

  # API_FILES

  # API_TEST_SOURCES
  # LINK_LIBRARIES z
  # LINK_LIBRARIES isal
  # isal requires "sudo apt-get install libisal-dev"
  LINK_LIBRARIES isal z
)
