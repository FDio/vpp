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

add_vpp_plugin(perfmon
  SOURCES
  perfmon.c
  perfmon_periodic.c
  parse_util.c

  API_FILES
  perfmon.api

  API_TEST_SOURCES
  perfmon_test.c

  INSTALL_HEADERS
  perfmon_all_api_h.h
  perfmon_msg_enum.h
)

set (PERFMON_JSON_FILES
  haswell_core_v28.json
  haswellx_core_v20.json
  ivybridge_core_v21.json
  ivytown_core_v20.json
  jaketown_core_v20.json
  sandybridge_core_v16.json
  skylake_core_v42.json
  skylakex_core_v1.12.json
)

install(
  FILES ${PERFMON_JSON_FILES}
  DESTINATION usr/share/vpp/plugins/perfmon
  COMPONENT vpp-dev
)
