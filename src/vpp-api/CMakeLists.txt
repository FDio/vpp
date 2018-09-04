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

##############################################################################
# vpp api client library
##############################################################################

add_vpp_library (vppapiclient
  SOURCES
  client/client.c
  client/stat_client.c
  client/libvppapiclient.map
  LINK_LIBRARIES vppinfra vlibmemoryclient pthread
)
add_dependencies(vppapiclient vpp_version_h api_headers)

add_vpp_headers(vpp-api
  client/vppapiclient.h
  client/stat_client.h
)

add_subdirectory(vapi)
add_subdirectory(python)
