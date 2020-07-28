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

add_vpp_plugin(acl
  SOURCES
  acl.c
  hash_lookup.c
  lookup_context.c
  sess_mgmt_node.c
  dataplane_node.c
  dataplane_node_nonip.c

  acl_caiop.c

  MULTIARCH_SOURCES
  dataplane_node.c
  dataplane_node_nonip.c

  API_FILES
  acl.api
  acl_types.api

  API_TEST_SOURCES
  acl_test.c
)
