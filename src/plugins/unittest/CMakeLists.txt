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

add_vpp_plugin(unittest
  SOURCES
  bier_test.c
  bihash_test.c
  crypto_test.c
  crypto/aes_cbc.c
  crypto/aes_gcm.c
  crypto/aes_ctr.c
  crypto/rfc2202_hmac_sha1.c
  crypto/rfc2202_hmac_md5.c
  crypto/rfc4231.c
  fib_test.c
  ipsec_test.c
  interface_test.c
  mfib_test.c
  punt_test.c
  rbtree_test.c
  session_test.c
  string_test.c
  tcp_test.c
  sparse_vec_test.c
  svm_fifo_test.c
  unittest.c
  util_test.c
)
