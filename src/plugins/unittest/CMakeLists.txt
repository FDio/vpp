# Copyright (c) 2018-2019 Cisco and/or its affiliates.
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

set(chacha20_poly1305)
if (OPENSSL_VERSION VERSION_GREATER_EQUAL 1.1.0)
    set(chacha20_poly1305 crypto/chacha20_poly1305.c)
endif()
include_directories(${CMAKE_SOURCE_DIR}/vpp-api ${CMAKE_CURRENT_BINARY_DIR}/../../vpp-api)
add_vpp_plugin(unittest
  SOURCES
  api_test.c
  api_fuzz_test.c
  bier_test.c
  bihash_test.c
  bitmap_test.c
  crypto/aes_cbc.c
  crypto/aes_ctr.c
  crypto/aes_gcm.c
  crypto/aes_gmac.c
  ${chacha20_poly1305}
  crypto/rfc2202_hmac_md5.c
  crypto/rfc2202_hmac_sha1.c
  crypto/rfc4231.c
  crypto/sha.c
  crypto_test.c
  fib_test.c
  gso_test.c
  hash_test.c
  interface_test.c
  ipsec_test.c
  ip_psh_cksum_test.c
  llist_test.c
  mactime_test.c
  mem_bulk_test.c
  mfib_test.c
  mpcap_node.c
  policer_test.c
  pool_test.c
  punt_test.c
  rbtree_test.c
  session_test.c
  sparse_vec_test.c
  string_test.c
  svm_fifo_test.c
  segment_manager_test.c
  tcp_test.c
  test_buffer.c
  time_test.c
  unittest.c
  udp_test.c
  util_test.c
  vlib_test.c
  counter_test.c
  ring_buffer_test.c
  histogram_test.c

  COMPONENT
  vpp-plugin-devtools
  LINK_LIBRARIES vapiclient
)
