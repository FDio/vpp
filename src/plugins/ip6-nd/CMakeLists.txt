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

add_vpp_plugin(ip6_nd
  SOURCES
  ip6_mld.c
  ip6_nd.c
  ip6_nd_api.c
  ip6_nd_proxy.c
  ip6_ra.c
  rd_cp.c
  rd_cp_api.c

  API_FILES
  ip6_nd.api
  rd_cp.api

  INSTALL_HEADERS
  ip6_nd.h

 API_TEST_SOURCES
 ip6_nd_test.c
)
