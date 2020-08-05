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

add_vpp_library (vlibmemory
  SOURCES
  memory_api.c
  memory_shared.c
  memory_client.c
  socket_client.c
  socket_api.c
  vlib_api.c
  vlib_api_cli.c
  vlib_api_api.c
  ../vlibapi/api_shared.c
  ../vlibapi/node_serialize.c

  INSTALL_HEADERS
  vl_memory_msg_enum.h
  memory_shared.h
  vl_memory_api_h.h
  socket_client.h
  memory_api.h
  api.h
  memory_client.h
  socket_api.h

  API_FILES
  memclnt.api
  vlib_api.api

  LINK_LIBRARIES vppinfra svm vlib
)
add_dependencies(vlibmemory vlibmemory_api_headers)

add_vpp_library (vlibmemoryclient
  SOURCES
  memory_shared.c
  memory_client.c
  socket_client.c
  ../vlibapi/api_shared.c
  ../vlibapi/node_serialize.c

  LINK_LIBRARIES vppinfra svm
)
add_dependencies(vlibmemoryclient vlibmemory_api_headers)
