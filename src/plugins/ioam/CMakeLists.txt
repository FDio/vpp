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

add_vpp_plugin(ioam
  SOURCES
  # iOAM Proof of Transit
  lib-pot/pot_util.c
  encap/ip6_ioam_pot.c
  lib-pot/pot_api.c

  # iOAM trace export for IPv6
  export/ioam_export.c
  export/node.c
  export/ioam_export_thread.c

  # iOAM Trace
  lib-trace/trace_util.c
  encap/ip6_ioam_trace.c
  lib-trace/trace_api.c

  # VxLAN-GPE
  lib-vxlan-gpe/ioam_encap.c
  lib-vxlan-gpe/ioam_decap.c
  lib-vxlan-gpe/ioam_transit.c
  lib-vxlan-gpe/ioam_pop.c
  lib-vxlan-gpe/vxlan_gpe_api.c
  lib-vxlan-gpe/vxlan_gpe_ioam_trace.c
  lib-vxlan-gpe/vxlan_gpe_ioam.c
  export-vxlan-gpe/vxlan_gpe_ioam_export.c
  export-vxlan-gpe/vxlan_gpe_node.c
  export-vxlan-gpe/vxlan_gpe_ioam_export_thread.c

  # iOAM E2E
  encap/ip6_ioam_e2e.c
  encap/ip6_ioam_seqno.c
  lib-e2e/ioam_seqno_lib.c

  # ipfix collector
  ipfixcollector/ipfixcollector.c
  ipfixcollector/node.c

  # iOAM Analyse
  analyse/ip6/ip6_ioam_analyse.c
  analyse/ip6/node.c
  analyse/ioam_summary_export.c

  # iOAM record cache and rewrite
  ip6/ioam_cache.c
  ip6/ioam_cache_node.c
  ip6/ioam_cache_tunnel_select_node.c

  # udp ping
  udp-ping/udp_ping_node.c
  udp-ping/udp_ping_util.c
  udp-ping/udp_ping_export.c
  udp-ping/udp_ping_api.c

  MULTIARCH_SOURCES
  ip6/ioam_cache_node.c
  ip6/ioam_cache_tunnel_select_node.c

  API_FILES
  lib-pot/pot.api
  export/ioam_export.api
  lib-trace/trace.api
  lib-vxlan-gpe/ioam_vxlan_gpe.api
  export-vxlan-gpe/vxlan_gpe_ioam_export.api
  ip6/ioam_cache.api
  udp-ping/udp_ping.api

  INSTALL_HEADERS
  lib-pot/pot_util.h
  lib-pot/math64.h
  lib-trace/trace_util.h
  encap/ip6_ioam_trace.h
  lib-trace/trace_config.h
  export-common/ioam_export.h
  lib-vxlan-gpe/vxlan_gpe_ioam_util.h
  lib-vxlan-gpe/vxlan_gpe_ioam_packet.h
  lib-vxlan-gpe/vxlan_gpe_ioam.h
  encap/ip6_ioam_e2e.h
  encap/ip6_ioam_seqno.h
  lib-e2e/ioam_seqno_lib.h
  udp-ping/udp_ping_packet.h
  udp-ping/udp_ping.h
  udp-ping/udp_ping_util.h

  API_TEST_SOURCES
  ioam_test.c
  lib-pot/pot_test.c
  export/ioam_export_test.c
  export-vxlan-gpe/vxlan_gpe_ioam_export_test.c
  lib-trace/trace_test.c
  lib-vxlan-gpe/vxlan_gpe_test.c
  udp-ping/udp_ping_test.c
)

