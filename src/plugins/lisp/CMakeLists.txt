# Copyright (c) 2020 Cisco and/or its affiliates.
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
# LISP control plane: lisp-cp
##############################################################################

##############################################################################
# Tunnel protocol: lisp-gpe
##############################################################################

add_vpp_plugin(lisp
  SOURCES
  lisp-cp/lisp_types.c
  lisp-cp/lisp_cp_dpo.c
  lisp-cp/control.c
  lisp-cp/control_main.c
  lisp-cp/gid_dictionary.c
  lisp-cp/lisp_msg_serdes.c
  lisp-cp/packets.c
  lisp-cp/one_cli.c
  lisp-cp/lisp_cli.c
  lisp-cp/one_api.c
  lisp-cp/lisp_api.c
  lisp-cp/lisp_types_api.c
  lisp-gpe/lisp_gpe.c
  lisp-gpe/lisp_gpe_sub_interface.c
  lisp-gpe/lisp_gpe_adjacency.c
  lisp-gpe/lisp_gpe_tunnel.c
  lisp-gpe/lisp_gpe_fwd_entry.c
  lisp-gpe/lisp_gpe_tenant.c
  lisp-gpe/interface.c
  lisp-gpe/decap.c
  lisp-gpe/lisp_gpe_api.c

  API_FILES
  lisp-cp/lisp_types.api
  lisp-cp/lisp.api
  lisp-cp/one.api
  lisp-gpe/lisp_gpe.api

  INSTALL_HEADERS
  lisp-cp/lisp_types.h
  lisp-cp/packets.h
  lisp-cp/gid_dictionary.h
  lisp-cp/lisp_cp_messages.h
  lisp-cp/lisp_msg_serdes.h
  lisp-cp/control.h
  lisp-cp/lisp_types_api.h
  lisp-gpe/lisp_gpe.h
  lisp-gpe/lisp_gpe_fwd_entry.h
  lisp-gpe/lisp_gpe_tenant.h
  lisp-gpe/lisp_gpe_packet.h
  lisp-gpe/lisp_gpe_error.def

  API_TEST_SOURCES
  lisp-cp/lisp_test.c
  lisp-cp/lisp_cp_test.c
  lisp-cp/one_test.c
  lisp-gpe/lisp_gpe_test.c
)

add_vpp_plugin(lisp_unittest
  SOURCES
  lisp-cp/lisp_types.c
  lisp-cp/control.c
  lisp-cp/control_main.c
  lisp-cp/gid_dictionary.c
  lisp-cp/lisp_cp_dpo.c
  lisp-cp/lisp_msg_serdes.c
  lisp-cp/packets.c
  lisp-gpe/lisp_gpe.c
  lisp-gpe/decap.c
  lisp-gpe/interface.c
  lisp-gpe/lisp_gpe_adjacency.c
  lisp-gpe/lisp_gpe_fwd_entry.c
  lisp-gpe/lisp_gpe_tenant.c
  lisp-gpe/lisp_gpe_tunnel.c
  lisp-gpe/lisp_gpe_sub_interface.c
  test/lisp_cp_test.c
)
