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

add_vpp_plugin(map
  SOURCES
  ip4_map.c
  ip4_map_t.c
  ip6_map.c
  ip6_map_t.c
  map_api.c
  map.c
  lpm.c

  API_FILES
  map.api

  INSTALL_HEADERS
  map_all_api_h.h
  map_msg_enum.h
  map.h
  lpm.h
)
