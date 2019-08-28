#
# May 18 2019, Christian E. Hopps <chopps@labn.net>
#
# Copyright (c) 2019, LabN Consulting, L.L.C.
# Copyright (c) 2015 Cisco and/or its affiliates.
#
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

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

add_vpp_plugin(iptfs
  SOURCES
  # iptfs_build.c
  deferred.c
  iptfs_api.c
  iptfs_decap.c
  iptfs_decap_reorder.c
  iptfs_encap.c
  iptfs_format.c
  ipsec_iptfs.c
  iptfs_output.c
  iptfs_pacer.c
  iptfs_zpool.c

  MULTIARCH_SOURCES
  iptfs_decap.c
  iptfs_decap_reorder.c
  iptfs_encap.c
  iptfs_output.c
  iptfs_pacer.c
  iptfs_zpool.c

  API_FILES
  iptfs.api

  # API_TEST_SOURCES
  # iptfs_api_test.c

  # This would be used if we encrypted prior to output.
  # iptfs_output_enq.c

  # MULTIARCH_SOURCES
  INSTALL_HEADERS
  deferred.h
  ipsec_iptfs.h
  iptfs_sring.h
  iptfs_all_api_h.h
)
