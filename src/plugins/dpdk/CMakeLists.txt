# Copyright (c) 2016 Cisco and/or its affiliates.
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

include_directories (
  /usr/include/dpdk
)

add_vpp_plugin(dpdk_plugin
  buffer.c
  main.c
  thread.c
  api/dpdk_api.c
  api/dpdk_test.c
  device/cli.c
  device/common.c
  device/device.c
  device/flow.c
  device/format.c
  device/init.c
  device/node.c
  hqos/hqos.c
  ipsec/cli.c
  ipsec/crypto_node.c
  ipsec/esp_decrypt.c
  ipsec/esp_encrypt.c
  ipsec/ipsec.c
  api/dpdk.api
)

vpp_library_set_multiarch_sources(dpdk_plugin
  buffer.c
  device/device.c
  device/node.c
)

set(DPDK_LINK_FLAGS "-Wl,--whole-archive,-l:libdpdk.a,--no-whole-archive")
set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lnuma")

message(STATUS "DPDK_LINK_FLAGS: ${DPDK_LINK_FLAGS}")

set_target_properties(dpdk_plugin PROPERTIES LINK_FLAGS "${DPDK_LINK_FLAGS}")

