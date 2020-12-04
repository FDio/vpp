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

add_vpp_plugin(cnat
  SOURCES
  cnat_api.c
  cnat_client.c
  cnat_node_snat.c
  cnat_node_vip.c
  cnat_scanner.c
  cnat_session.c
  cnat_translation.c
  cnat_types.c
  cnat_snat.c
  cnat_src_policy.c
  cnat_feature.c

  API_FILES
  cnat.api
)
