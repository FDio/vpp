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

add_vpp_plugin(gbp
  SOURCES
  gbp_api.c
  gbp_bridge_domain.c
  gbp_classify.c
  gbp_contract.c
  gbp_endpoint.c
  gbp_endpoint_group.c
  gbp_fwd.c
  gbp_fwd_dpo.c
  gbp_itf.c
  gbp_learn.c
  gbp_policy.c
  gbp_policy_dpo.c
  gbp_recirc.c
  gbp_route_domain.c
  gbp_scanner.c
  gbp_subnet.c
  gbp_vxlan.c

  API_FILES
  gbp.api

  INSTALL_HEADERS
  gbp.h
  gbp_all_api_h.h
  gbp_msg_enum.h
)
