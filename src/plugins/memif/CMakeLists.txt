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

add_vpp_plugin(memif
  SOURCES
  memif.c
  memif_api.c
  cli.c
  node.c
  device.c
  socket.c

  API_FILES
  memif.api

  API_TEST_SOURCES
  memif_test.c

  MULTIARCH_SOURCES
  device.c
  node.c

  INSTALL_HEADERS
  memif.h
)

add_compile_definitions(MEMIF_CACHELINE_SIZE=${VPP_CACHE_LINE_SIZE})
