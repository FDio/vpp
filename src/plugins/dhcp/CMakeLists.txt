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

add_vpp_plugin(dhcp
  SOURCES
  client.c
  dhcp_api.c
  dhcp_client_detect.c
  dhcp_proxy.c
  dhcp4_packet.c
  dhcp4_proxy_node.c
  dhcp6_client_common_dp.c
  dhcp6_ia_na_client_dp.c
  dhcp6_ia_na_client_cp.c
  dhcp6_ia_na_client_cp_api.c
  dhcp6_pd_client_cp.c
  dhcp6_pd_client_cp_api.c
  dhcp6_pd_client_dp.c
  dhcp6_proxy_node.c

  MULTIARCH_SOURCES
  dhcp_client_detect.c

  API_FILES
  dhcp.api
  dhcp6_pd_client_cp.api
  dhcp6_ia_na_client_cp.api

  INSTALL_HEADERS
  client.h
  dhcp4_packet.h
  dhcp6_packet.h
  dhcp_proxy.h
  dhcp6_proxy_error.def
  dhcp4_proxy_error.def
  dhcp6_client_common_dp.h
  dhcp6_pd_client_dp.h
  dhcp6_ia_na_client_dp.h

  API_TEST_SOURCES
  dhcp_test.c
)
