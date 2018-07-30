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

vpp_generate_api_header(memclnt.api)
add_custom_target(vlibmemory_api_headers DEPENDS memclnt.api.h)

add_library (vlibmemory SHARED
  memory_api.c
  memory_shared.c
  memory_client.c
  socket_api.c
  vlib_api.c
  vlib_api_cli.c
  ../vlibapi/api_shared.c
  ../vlibapi/node_serialize.c
)
target_link_libraries (vlibmemory vppinfra svm vlib)
add_dependencies(vlibmemory vlibmemory_api_headers)
install (TARGETS vlibmemory DESTINATION lib)

add_library (vlibmemoryclient SHARED
  memory_shared.c
  memory_client.c
  socket_client.c
  ../vlibapi/api_shared.c
  ../vlibapi/node_serialize.c
)

target_link_libraries (vlibmemoryclient vppinfra svm vlib)
add_dependencies(vlibmemoryclient vlibmemory_api_headers)
install (TARGETS vlibmemoryclient DESTINATION lib)
