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

add_vpp_plugin(vppdb
  SOURCES
  vppdb.c

  API_FILES
  vppdb.api
)

add_vpp_executable(test_vppdb
  SOURCES
  vppdb.c
  vppdb_shm.c
  test_vppdb.c
  LINK_LIBRARIES vppinfra pthread
)

add_vpp_executable(test_vppdb_server
  SOURCES
  vppdb.c
  vppdb_shm.c
  test_vppdb_server.c

  LINK_LIBRARIES vppinfra
)
add_vpp_executable(test_vppdb_client
  SOURCES
  vppdb.c
  vppdb_client.c
  vppdb_hash.c
  test_vppdb_client.c
  LINK_LIBRARIES vppinfra
)
