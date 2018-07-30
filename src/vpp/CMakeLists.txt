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
# Generate vpp/app/version.h
##############################################################################
add_custom_command(
  OUTPUT ${CMAKE_BINARY_DIR}/include/vpp/app/version.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMAND mkdir
  ARGS -p ${CMAKE_BINARY_DIR}/include/vpp/app
  COMMAND scripts/generate_version_h
  ARGS ${CMAKE_BINARY_DIR}/include/vpp/app/version.h
  COMMENT "Generating VPP version.h"
)

add_custom_target(vpp_version_h
  DEPENDS ${CMAKE_BINARY_DIR}/include/vpp/app/version.h
)

##############################################################################
# vpp binary
##############################################################################

vpp_add_api_files(vpp_api_headers
  api/vpe.api
  stats/stats.api
  oam/oam.api
)

add_executable (vpp
  vnet/main.c
  app/vpe_cli.c
  app/version.c
  oam/oam.c
  oam/oam_api.c
  stats/stats.c
  stats/stat_segment.c
  api/api.c
  api/api_main.c
  api/api_format.c
  api/json_format.c
  api/custom_dump.c
  api/plugin.c
)
target_link_libraries(vpp svm vlib vppinfra vlibmemory vnet Threads::Threads
		      ${CMAKE_DL_LIBS})
add_dependencies(vpp vpp_version_h api_headers)
set_target_properties(vpp PROPERTIES ENABLE_EXPORTS 1)
install(TARGETS vpp DESTINATION bin)

##############################################################################
# vppctl binary
##############################################################################
add_executable(vppctl app/vppctl.c)
target_link_libraries(vppctl vppinfra)
install(TARGETS vppctl DESTINATION bin)

##############################################################################
# vpp_get_metrics binary
##############################################################################
add_executable (vpp_get_metrics api/vpp_get_metrics.c ${VPP_API_HDRS})
target_link_libraries (vpp_get_metrics vppinfra svm svmdb)
install(TARGETS vpp_get_metrics DESTINATION bin)

##############################################################################
# stats binaries
##############################################################################
add_executable(summary_stats_client api/summary_stats_client.c)
add_executable(stat_client app/stat_client.c)
target_link_libraries(summary_stats_client vppinfra svm vlibmemoryclient)
target_link_libraries(stat_client vppinfra svm vlibmemoryclient)

##############################################################################
# install
##############################################################################

