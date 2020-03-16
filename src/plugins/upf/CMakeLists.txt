#
# Copyright (c) 2016 Cisco and/or its affiliates.
# Copyright (c) 2018 Travelping GmbH
#
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
# UPF plugin
##############################################################################

message(STATUS "Looking for hyperscan")
pkg_check_modules(HS libhs)

if(HS_FOUND)
  include_directories (${HS_INCLUDE_DIRS})

  add_vpp_plugin(upf
    SOURCES
    upf.c
    upf_api.c
    upf_cli.c
    upf_gtpu_encap.c
    upf_gtpu_decap.c
    upf_flow_node.c
    upf_classify.c
    upf_adf.c
    upf_tdf.c
    upf_input.c
    upf_forward.c
    upf_session_dpo.c
    pfcp.c
    upf_pfcp.c
    upf_pfcp_api.c
    upf_pfcp_server.c
    upf_pfcp_session_server.c
    upf_proxy_accept.c
    upf_proxy_input.c
    upf_proxy_output.c
    upf_proxy.c
    upf_app_db.c
    flowtable_init.c
    flowtable.c

    MULTIARCH_SOURCES
    upf_gtpu_encap.c
    upf_gtpu_decap.c
    upf_flow_node.c
    upf_classify.c
    upf_tdf.c
    upf_proxy_accept.c
    upf_proxy_input.c
    upf_proxy_output.c
    upf_input.c
    upf_forward.c
    upf_session_dpo.c

    API_FILES
    upf.api

    INSTALL_HEADERS
    upf.h
    pfcp.h
    upf_pfcp.h
    upf_pfcp_api.h
    upf_pfcp_server.h
    upf_proxy.h
    upf_app_db.h
    flowtable.h
    flowtable_tcp.h

    LINK_LIBRARIES
    ${HS_LIBRARIES}

    LINK_FLAGS
    ${HS_LDFLAGS}

    API_TEST_SOURCES
    upf_test.c
  )
else()
  message(WARNING "Hyperscan not found - GTP UPF disabled")
endif()
