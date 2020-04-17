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
option(VPP_API_TEST_BUILTIN "Use builtin VPP API test." ON)

configure_file(
  ${CMAKE_SOURCE_DIR}/vpp/vnet/config.h.in
  ${CMAKE_BINARY_DIR}/vpp/vnet/config.h
)

set(VPP_API_FILES
  api/vpe_types.api
  api/vpe.api
)

vpp_add_api_files(vpp core vpp ${VPP_API_FILES})

foreach(file ${VPP_API_FILES})
  get_filename_component(dir ${file} DIRECTORY)
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${file}.h
    ${CMAKE_CURRENT_BINARY_DIR}/${file}_enum.h
    ${CMAKE_CURRENT_BINARY_DIR}/${file}_types.h
    DESTINATION include/vpp/${dir}
    COMPONENT vpp-dev
  )
endforeach()

set(VPP_SOURCES
  vnet/main.c
  app/vpe_cli.c
  app/version.c
  stats/stat_segment.c
  api/api.c
  api/json_format.c
  api/custom_dump.c
  api/types.c
)

if(VPP_API_TEST_BUILTIN)
  list(APPEND VPP_SOURCES
    api/api_format.c
    api/api_main.c
    api/plugin.c
    api/types.c
    ../vnet/arp/arp_test.c
  )
  add_definitions(-DVPP_API_TEST_BUILTIN=1)
endif()

add_vpp_executable(vpp
  ENABLE_EXPORTS
  SOURCES ${VPP_SOURCES}
  LINK_LIBRARIES svm vlib vppinfra vlibmemory vnet Threads::Threads ${CMAKE_DL_LIBS}
  DEPENDS vpp_version_h api_headers
)

add_vpp_headers(vpp
  api/vpe_msg_enum.h
  api/vpe_all_api_h.h
  stats/stat_segment.h
  stats/stat_segment_shared.h
)

##############################################################################
# vppctl binary
##############################################################################
add_vpp_executable(vppctl
  SOURCES app/vppctl.c
  LINK_LIBRARIES vppinfra
)

if (DEFINED ENV{BUILD_STATIC_VPPCTL})
add_vpp_executable(vppctl_static
  SOURCES app/vppctl.c
  STATIC_LINK 1
  NO_INSTALL
  LINK_LIBRARIES vppinfra_static
)
endif()

##############################################################################
# vpp_get_metrics binary
##############################################################################
add_vpp_executable(vpp_get_metrics
  SOURCES api/vpp_get_metrics.c
  LINK_LIBRARIES vppinfra svm svmdb
  DEPENDS api_headers
)

##############################################################################
# stats binaries
##############################################################################
add_vpp_executable(vpp_get_stats
  SOURCES app/vpp_get_stats.c
  LINK_LIBRARIES vppapiclient vppinfra
  DEPENDS api_headers
)

add_vpp_executable(vpp_prometheus_export
  SOURCES app/vpp_prometheus_export.c
  LINK_LIBRARIES vppapiclient vppinfra svm vlibmemoryclient
  DEPENDS api_headers
)

##############################################################################
# vppmem_preload library
##############################################################################
add_vpp_library(vppmem_preload
  SOURCES mem/mem.c
  LINK_LIBRARIES vppinfra
)

install(FILES conf/startup.conf DESTINATION etc/vpp COMPONENT vpp)
install(FILES conf/80-vpp.conf DESTINATION etc/sysctl.d COMPONENT vpp)

##############################################################################
# VAT2 plugins
##############################################################################
add_vpp_test_library(vpp
  ${VPP_API_FILES}
)
