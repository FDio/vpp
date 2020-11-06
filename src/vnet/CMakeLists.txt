# Copyright (c) 2018-2020 Cisco and/or its affiliates.
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

add_definitions (-DWITH_LIBSSL=1)
include_directories(${OPENSSL_INCLUDE_DIR})

unset(VNET_SOURCES)
unset(VNET_HEADERS)
unset(VNET_API_FILES)
unset(VNET_MULTIARCH_SOURCES)

##############################################################################
# Generic stuff
##############################################################################
list(APPEND VNET_SOURCES
  buffer.c
  config.c
  devices/devices.c
  devices/netlink.c
  flow/flow.c
  flow/flow_cli.c
  flow/flow_api.c
  handoff.c
  interface.c
  interface_api.c
  interface_cli.c
  interface_format.c
  interface_output.c
  interface/rx_queue.c
  interface/runtime.c
  interface_stats.c
  misc.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  interface_output.c
  interface_stats.c
  handoff.c
)

list(APPEND VNET_HEADERS
  api_errno.h
  buffer.h
  config.h
  devices/devices.h
  devices/netlink.h
  flow/flow.h
  global_funcs.h
  handoff.h
  interface/rx_queue_funcs.h
  interface.h
  interface_funcs.h
  interface_output.h
  ip/ip4_to_ip6.h
  ip/ip6_to_ip4.h
  ip/ip_types_api.h
  l3_types.h
  plugin/plugin.h
  pipeline.h
  vnet.h
  vnet_all_api_h.h
  vnet_msg_enum.h
  util/radix.h
  util/refcount.h
  format_fns.h
  ip/ip_format_fns.h
  ethernet/ethernet_format_fns.h
)

list(APPEND VNET_API_FILES
  interface.api
  interface_types.api
  ip/ip_types.api
  flow/flow_types.api
  flow/flow.api
)

##############################################################################
# Policer infra
##############################################################################
list(APPEND VNET_SOURCES
  policer/node_funcs.c
  policer/policer.c
  policer/xlate.c
  policer/policer_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  policer/node_funcs.c
)

list(APPEND VNET_HEADERS
  policer/police.h
  policer/policer.h
  policer/xlate.h
)

list(APPEND VNET_API_FILES
  policer/policer.api
  policer/policer_types.api
)

##############################################################################
# Binary API compatibility until vpp 20.12, see the ADL plugin...
##############################################################################

list(APPEND VNET_SOURCES
  cop/cop_api.c
)

list(APPEND VNET_API_FILES cop/cop.api)

##############################################################################
# Layer 2 protocols go here
##############################################################################

##############################################################################
# Layer 2 protocol: Ethernet
##############################################################################
list(APPEND VNET_SOURCES
  ethernet/arp_packet.c
  ethernet/ethernet_types_api.c
  ethernet/format.c
  ethernet/init.c
  ethernet/interface.c
  ethernet/mac_address.c
  ethernet/node.c
  ethernet/pg.c
  ethernet/sfp.c
  ethernet/p2p_ethernet.c
  ethernet/p2p_ethernet_input.c
  ethernet/p2p_ethernet_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  ethernet/node.c
  ethernet/p2p_ethernet_input.c
)

list(APPEND VNET_HEADERS
  ethernet/error.def
  ethernet/ethernet.h
  ethernet/mac_address.h
  ethernet/packet.h
  ethernet/types.def
  ethernet/sfp.h
  ethernet/p2p_ethernet.h
  ethernet/arp_packet.h
)

list(APPEND VNET_API_FILES
  ethernet/p2p_ethernet.api
  ethernet/ethernet_types.api)

##############################################################################
# Layer 2 protocol: Ethernet bridging
##############################################################################
list(APPEND VNET_SOURCES
  l2/feat_bitmap.c
  l2/l2_api.c
  l2/l2_arp_term.c
  l2/l2_bd.c
  l2/l2_bvi.c
  l2/l2_bvi_node.c
  l2/l2_input_classify.c
  l2/l2_output_classify.c
  l2/l2_efp_filter.c
  l2/l2_fib.c
  l2/l2_flood.c
  l2/l2_fwd.c
  l2/l2_input.c
  l2/l2_input_node.c
  l2/l2_input_vtr.c
  l2/l2_learn.c
  l2/l2_output.c
  l2/l2_in_out_acl.c
  l2/l2_in_out_feat_arc.c
  l2/l2_patch.c
  l2/l2_rw.c
  l2/l2_uu_fwd.c
  l2/l2_vtr.c
  l2/l2_xcrw.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  l2/l2_bvi_node.c
  l2/l2_fwd.c
  l2/l2_learn.c
  l2/l2_output.c
  l2/l2_patch.c
  l2/l2_in_out_feat_arc.c
  l2/l2_input_classify.c
  l2/l2_input_node.c
  l2/l2_output_classify.c
  l2/l2_flood.c
  l2/l2_uu_fwd.c
  l2/l2_efp_filter.c
  l2/l2_rw.c
  l2/l2_xcrw.c
  l2/l2_in_out_acl.c
  l2/l2_input_vtr.c
)

list(APPEND VNET_HEADERS
  l2/feat_bitmap.h
  l2/l2_input.h
  l2/l2_output.h
  l2/l2_vtr.h
  l2/l2_input_vtr.h
  l2/l2_efp_filter.h
  l2/l2_fwd.h
  l2/l2_bd.h
  l2/l2_bvi.h
  l2/l2_flood.h
  l2/l2_fib.h
  l2/l2_rw.h
  l2/l2_xcrw.h
  l2/l2_classify.h
)

list(APPEND VNET_API_FILES l2/l2.api)

##############################################################################
# Layer 2 protocol: SRP
##############################################################################
list(APPEND VNET_SOURCES
  srp/format.c
  srp/interface.c
  srp/node.c
  srp/pg.c
)

list(APPEND VNET_HEADERS
  srp/packet.h
  srp/srp.h
)

##############################################################################
# Layer 2 protocol: PPP
##############################################################################
list(APPEND VNET_SOURCES
  ppp/node.c
  ppp/pg.c
  ppp/ppp.c
)

list(APPEND VNET_HEADERS
  ppp/error.def
  ppp/ppp.h
  ppp/packet.h
)

##############################################################################
# Layer 2 protocol: HDLC
##############################################################################
list(APPEND VNET_SOURCES
  hdlc/node.c
  hdlc/pg.c
  hdlc/hdlc.c
)

list(APPEND VNET_HEADERS
  hdlc/error.def
  hdlc/hdlc.h
  hdlc/packet.h
)

##############################################################################
# Layer 2 protocol: LLC
##############################################################################
list(APPEND VNET_SOURCES
  llc/llc.c
  llc/node.c
  llc/pg.c
)

list(APPEND VNET_HEADERS
  llc/llc.h
)

##############################################################################
# Layer 2 protocol: SNAP
##############################################################################
list(APPEND VNET_SOURCES
  snap/snap.c
  snap/node.c
  snap/pg.c
)

list(APPEND VNET_HEADERS
  snap/snap.h
)

##############################################################################
# Layer 2 / vxlan
##############################################################################
list(APPEND VNET_SOURCES
  vxlan/vxlan.c
  vxlan/encap.c
  vxlan/decap.c
  vxlan/vxlan_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  vxlan/encap.c
)

list(APPEND VNET_HEADERS
  vxlan/vxlan.h
  vxlan/vxlan_packet.h
  vxlan/vxlan_error.def
)

list(APPEND VNET_MULTIARCH_SOURCES vxlan/decap.c)

list(APPEND VNET_API_FILES vxlan/vxlan.api)

##############################################################################
# Layer 2 / Bonding
##############################################################################
list(APPEND VNET_SOURCES
  bonding/cli.c
  bonding/node.c
  bonding/device.c
  bonding/bond_api.c
)

list(APPEND VNET_HEADERS
  bonding/node.h
)

list(APPEND VNET_MULTIARCH_SOURCES bonding/node.c bonding/device.c)
list(APPEND VNET_API_FILES bonding/bond.api)

##############################################################################
# Layer 2/3 "classify"
##############################################################################
list(APPEND VNET_SOURCES
  classify/vnet_classify.c
  classify/trace_classify.h
  classify/ip_classify.c
  classify/in_out_acl.c
  classify/policer_classify.c
  classify/flow_classify.c
  classify/flow_classify_node.c
  classify/vnet_classify.h
  classify/classify_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  classify/ip_classify.c
  classify/flow_classify_node.c
)

list(APPEND VNET_HEADERS
  classify/vnet_classify.h
  classify/trace_classify.h
  classify/in_out_acl.h
  classify/policer_classify.h
  classify/flow_classify.h
)

list(APPEND VNET_API_FILES classify/classify.api)

##############################################################################
# Layer 3 protocols go here
##############################################################################

##############################################################################
# Layer 3 protocol: IP v4/v6
##############################################################################
list(APPEND VNET_SOURCES
  ip/format.c
  ip/icmp4.c
  ip/icmp6.c
  ip/ip46_cli.c
  ip/ip_types_api.c
  ip/ip46_address.c
  ip/ip4_format.c
  ip/ip4_forward.c
  ip/ip4_punt_drop.c
  ip/ip4_input.c
  ip/ip4_options.c
  ip/ip4_mtrie.c
  ip/ip4_pg.c
  ip/ip4_source_and_port_range_check.c
  ip/reass/ip4_full_reass.c
  ip/reass/ip4_sv_reass.c
  ip/ip6_format.c
  ip/ip6_forward.c
  ip/ip6_ll_table.c
  ip/ip6_ll_types.c
  ip/ip6_punt_drop.c
  ip/ip6_hop_by_hop.c
  ip/ip6_input.c
  ip/ip6_link.c
  ip/ip6_pg.c
  ip/reass/ip6_full_reass.c
  ip/reass/ip6_sv_reass.c
  ip/ip_api.c
  ip/ip_checksum.c
  ip/ip_container_proxy.c
  ip/ip_frag.c
  ip/ip.c
  ip/ip_interface.c
  ip/ip_init.c
  ip/ip_in_out_acl.c
  ip/ip_punt_drop.c
  ip/ip_types.c
  ip/lookup.c
  ip/punt_api.c
  ip/punt.c
  ip/punt_node.c
  ip/vtep.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  ip/ip4_punt_drop.c
  ip/reass/ip4_full_reass.c
  ip/ip6_hop_by_hop.c
  ip/reass/ip6_full_reass.c
  ip/reass/ip4_sv_reass.c
  ip/ip6_hop_by_hop.c
  ip/reass/ip6_full_reass.c
  ip/reass/ip6_sv_reass.c
  ip/ip6_input.c
  ip/ip6_punt_drop.c
  ip/punt_node.c
  ip/ip_in_out_acl.c
)

list(APPEND VNET_HEADERS
  ip/format.h
  ip/icmp46_packet.h
  ip/icmp4.h
  ip/icmp6.h
  ip/igmp_packet.h
  ip/ip4_error.h
  ip/ip4.h
  ip/ip4_mtrie.h
  ip/ip4_inlines.h
  ip/ip4_packet.h
  ip/ip46_address.h
  ip/ip6_error.h
  ip/ip6.h
  ip/ip6_hop_by_hop.h
  ip/ip6_hop_by_hop_packet.h
  ip/ip6_inlines.h
  ip/ip6_packet.h
  ip/ip.h
  ip/ip_container_proxy.h
  ip/ip_flow_hash.h
  ip/ip_table.h
  ip/ip_interface.h
  ip/ip_packet.h
  ip/ip_source_and_port_range_check.h
  ip/ip_types.h
  ip/lookup.h
  ip/ports.def
  ip/protocols.def
  ip/punt_error.def
  ip/punt.h
)

list(APPEND VNET_API_FILES
  ip/ip.api
  ip/punt.api
)

list(APPEND VNET_MULTIARCH_SOURCES
  ip/ip4_forward.c
  ip/ip6_forward.c
  ip/ip4_input.c
)

##############################################################################
# Layer 3 neighbours
##############################################################################
list(APPEND VNET_SOURCES
  ip-neighbor/ip_neighbor.c
  ip-neighbor/ip_neighbor_api.c
  ip-neighbor/ip_neighbor_dp.c
  ip-neighbor/ip_neighbor_types.c
  ip-neighbor/ip_neighbor_watch.c
  ip-neighbor/ip4_neighbor.c
  ip-neighbor/ip6_neighbor.c
)

list(APPEND VNET_HEADERS
  ip-neighbor/ip_neighbor.h
  ip-neighbor/ip_neighbor_types.h
)

list(APPEND VNET_API_FILES
  ip-neighbor/ip_neighbor.api
)

##############################################################################
# Bidirectional Forwarding Detection
##############################################################################

list(APPEND VNET_HEADERS
  bfd/bfd_protocol.h
  bfd/bfd_main.h
  bfd/bfd_api.h
  bfd/bfd_udp.h
)

list(APPEND VNET_SOURCES
  bfd/bfd_api.h
  bfd/bfd_udp.c
  bfd/bfd_main.c
  bfd/bfd_protocol.c
  bfd/bfd_cli.c
  bfd/bfd_api.c
)

list(APPEND VNET_API_FILES bfd/bfd.api)

##############################################################################
# Crypto
##############################################################################

list(APPEND VNET_SOURCES
  crypto/cli.c
  crypto/crypto.c
  crypto/format.c
  crypto/node.c
  crypto/crypto_api.c
)

list(APPEND VNET_HEADERS
  crypto/crypto.h
)

list(APPEND VNET_MULTIARCH_SOURCES crypto/node.c)

list(APPEND VNET_API_FILES crypto/crypto.api)

##############################################################################
# Layer 3 protocol: IPSec
##############################################################################
list(APPEND VNET_SOURCES
  ipsec/ipsec.c
  ipsec/ipsec_cli.c
  ipsec/ipsec_format.c
  ipsec/ipsec_handoff.c
  ipsec/ipsec_input.c
  ipsec/ipsec_itf.c
  ipsec/ipsec_punt.c
  ipsec/ipsec_sa.c
  ipsec/ipsec_spd.c
  ipsec/ipsec_spd_policy.c
  ipsec/ipsec_tun.c
  ipsec/ipsec_tun_in.c
  ipsec/esp_format.c
  ipsec/esp_encrypt.c
  ipsec/esp_decrypt.c
  ipsec/ah_decrypt.c
  ipsec/ah_encrypt.c
  ipsec/ipsec_api.c
  ipsec/ipsec_types_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  ipsec/esp_encrypt.c
  ipsec/esp_decrypt.c
  ipsec/ah_decrypt.c
  ipsec/ah_encrypt.c
  ipsec/ipsec_handoff.c
  ipsec/ipsec_output.c
  ipsec/ipsec_input.c
  ipsec/ipsec_tun_in.c
)

list(APPEND VNET_API_FILES ipsec/ipsec_types.api)
list(APPEND VNET_API_FILES ipsec/ipsec.api)

list(APPEND VNET_SOURCES
  ipsec/ipsec_output.c
)

list(APPEND VNET_HEADERS
  ipsec/ipsec.h
  ipsec/ipsec_spd.h
  ipsec/ipsec_spd_policy.h
  ipsec/ipsec_sa.h
  ipsec/ipsec_tun.h
  ipsec/ipsec_types_api.h
  ipsec/ipsec_punt.h
  ipsec/esp.h
  ipsec/ah.h
)

##############################################################################
# Layer 3 protocol: osi
##############################################################################
list(APPEND VNET_SOURCES
  osi/node.c
  osi/osi.c
  osi/pg.c
)

list(APPEND VNET_HEADERS
  osi/osi.h
)

##############################################################################
# Layer 4 protocol: tcp
##############################################################################
list(APPEND VNET_SOURCES
  tcp/tcp_api.c
  tcp/tcp_format.c
  tcp/tcp_pg.c
  tcp/tcp_syn_filter4.c
  tcp/tcp_output.c
  tcp/tcp_input.c
  tcp/tcp_newreno.c
  tcp/tcp_bt.c
  tcp/tcp_cli.c
  tcp/tcp_cubic.c
  tcp/tcp_debug.c
  tcp/tcp_sack.c
  tcp/tcp_timer.c
  tcp/tcp.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  tcp/tcp_input.c
  tcp/tcp_output.c
  tcp/tcp_syn_filter4.c
)

list(APPEND VNET_HEADERS
  tcp/tcp_packet.h
  tcp/tcp_timer.h
  tcp/tcp_bt.h
  tcp/tcp_cc.h
  tcp/tcp_debug.h
  tcp/tcp_inlines.h
  tcp/tcp_sack.h
  tcp/tcp_types.h
  tcp/tcp.h
  tcp/tcp_error.def
)

list(APPEND VNET_API_FILES tcp/tcp.api)

##############################################################################
# Layer 4 protocol: udp
##############################################################################
list(APPEND VNET_SOURCES
  udp/udp.c
  udp/udp_cli.c
  udp/udp_input.c
  udp/udp_format.c
  udp/udp_local.c
  udp/udp_pg.c
  udp/udp_encap_node.c
  udp/udp_encap.c
  udp/udp_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  udp/udp_local.c
  udp/udp_encap_node.c
)

list(APPEND VNET_HEADERS
  udp/udp_error.def
  udp/udp.h
  udp/udp_packet.h
  udp/udp_inlines.h
  udp/udp_local.h
)

list(APPEND VNET_API_FILES udp/udp.api)

##############################################################################
# Tunnel protocol: gre
##############################################################################
list(APPEND VNET_SOURCES
  gre/gre.c
  gre/node.c
  gre/interface.c
  gre/pg.c
  gre/gre_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  gre/node.c
  gre/gre.c
)

list(APPEND VNET_HEADERS
  gre/gre.h
  gre/packet.h
  gre/error.def
)

list(APPEND VNET_API_FILES gre/gre.api)

##############################################################################
# Tunnel protocol: ipip
##############################################################################
list(APPEND VNET_SOURCES
  ipip/ipip.c
  ipip/node.c
  ipip/sixrd.c
  ipip/ipip_api.c
  ipip/ipip_cli.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  ipip/node.c
)

list(APPEND VNET_HEADERS
  ipip/ipip.h
)

list(APPEND VNET_API_FILES
  ipip/ipip.api
)

##############################################################################
# Tunnel infra
##############################################################################
list(APPEND VNET_SOURCES
  tunnel/tunnel.c
  tunnel/tunnel_types_api.c
)

list(APPEND VNET_API_FILES
  tunnel/tunnel_types.api
)

list(APPEND VNET_HEADERS
  tunnel/tunnel.h
  tunnel/tunnel_dp.h
)

##############################################################################
# Tunnel protocol: gre+mpls
##############################################################################
list(APPEND VNET_SOURCES
  mpls/mpls.c
  mpls/mpls_lookup.c
  mpls/mpls_output.c
  mpls/mpls_features.c
  mpls/mpls_input.c
  mpls/interface.c
  mpls/mpls_tunnel.c
  mpls/pg.c
  mpls/mpls_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  mpls/mpls_output.c
  mpls/mpls_input.c
  mpls/mpls_lookup.c
  mpls/mpls_features.c
)

list(APPEND VNET_HEADERS
  mpls/mpls.h
  mpls/mpls_types.h
  mpls/mpls_tunnel.h
  mpls/packet.h
  mpls/error.def
)

list(APPEND VNET_API_FILES mpls/mpls.api)

##############################################################################
# Tunnel protocol: vxlan-gbp
##############################################################################
list(APPEND VNET_SOURCES
  vxlan-gbp/decap.c
  vxlan-gbp/encap.c
  vxlan-gbp/vxlan_gbp_api.c
  vxlan-gbp/vxlan_gbp.c
  vxlan-gbp/vxlan_gbp_packet.c
)

list (APPEND VNET_MULTIARCH_SOURCES
  vxlan-gbp/decap.c
  vxlan-gbp/encap.c
)

list(APPEND VNET_HEADERS
  vxlan-gbp/vxlan_gbp.h
  vxlan-gbp/vxlan_gbp_packet.h
  vxlan-gbp/vxlan_gbp_error.def
)

list(APPEND VNET_API_FILES vxlan-gbp/vxlan_gbp.api)

##############################################################################
# Tunnel protocol: vxlan-gpe
##############################################################################

list(APPEND VNET_SOURCES
  vxlan-gpe/vxlan_gpe.c
  vxlan-gpe/encap.c
  vxlan-gpe/decap.c
  vxlan-gpe/vxlan_gpe_api.c
)

list (APPEND VNET_MULTIARCH_SOURCES
  vxlan-gpe/decap.c
)

list(APPEND VNET_HEADERS
  vxlan-gpe/vxlan_gpe.h
  vxlan-gpe/vxlan_gpe_packet.h
  vxlan-gpe/vxlan_gpe_error.def
)

list(APPEND VNET_API_FILES vxlan-gpe/vxlan_gpe.api)

##############################################################################
# ipv6 segment routing
##############################################################################

list(APPEND VNET_SOURCES
  srv6/sr.c
  srv6/sr_localsid.c
  srv6/sr_policy_rewrite.c
  srv6/sr_steering.c
  srv6/sr_api.c
)

list(APPEND VNET_HEADERS
  srv6/sr_packet.h
  srv6/sr.h
)

list(APPEND VNET_API_FILES
  srv6/sr.api
  srv6/sr_types.api
)

##############################################################################
# mpls segment routing
##############################################################################

list(APPEND VNET_SOURCES
  srmpls/sr_mpls_policy.c
  srmpls/sr_mpls_steering.c
  srmpls/sr_mpls_api.c
)

list(APPEND VNET_HEADERS
  srmpls/sr_mpls.h
)

list(APPEND VNET_API_FILES
  srmpls/sr_mpls.api
)

##############################################################################
# IPFIX / netflow v10
##############################################################################
list(APPEND VNET_SOURCES
  ipfix-export/flow_report.c
  ipfix-export/flow_api.c
)

list(APPEND VNET_HEADERS
  ipfix-export/flow_report.h
  ipfix-export/ipfix_info_elements.h
  ipfix-export/ipfix_packet.h
)

list(APPEND VNET_API_FILES ipfix-export/ipfix_export.api)

##############################################################################
# GSO
##############################################################################
list(APPEND VNET_SOURCES
  gso/cli.c
  gso/gso.c
  gso/gso_api.c
  gso/node.c
)

list(APPEND VNET_HEADERS
  gso/gro.h
  gso/gro_func.h
  gso/hdr_offset_parser.h
  gso/gso.h
)

list(APPEND VNET_API_FILES
  gso/gso.api
)

##############################################################################
# IPFIX classify code
##############################################################################

list(APPEND VNET_SOURCES
  ipfix-export/flow_report_classify.c
)

list(APPEND VNET_HEADERS
  ipfix-export/flow_report_classify.h
)

##############################################################################
# lawful intercept
##############################################################################

list(APPEND VNET_SOURCES
  lawful-intercept/lawful_intercept.c
  lawful-intercept/node.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  lawful-intercept/node.c
)

list(APPEND VNET_HEADERS
  lawful-intercept/lawful_intercept.h
)

##############################################################################
# SPAN (port mirroring)
##############################################################################

list(APPEND VNET_SOURCES
  span/span_api.c
  span/span.c
  span/node.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  span/node.c
)

list(APPEND VNET_HEADERS
  span/span.h
)

list(APPEND VNET_API_FILES span/span.api)

##############################################################################
# Packet generator
##############################################################################

list(APPEND VNET_SOURCES
  pg/cli.c
  pg/edit.c
  pg/init.c
  pg/input.c
  pg/output.c
  pg/stream.c
  pg/pg_api.c
)

list(APPEND VNET_HEADERS
  pg/pg.h
  pg/edit.h
)

list(APPEND VNET_API_FILES pg/pg.api)

##############################################################################
# virtio
##############################################################################

list(APPEND VNET_SOURCES
  devices/virtio/cli.c
  devices/virtio/device.c
  devices/virtio/format.c
  devices/virtio/node.c
  devices/virtio/pci.c
  devices/virtio/vhost_user.c
  devices/virtio/vhost_user_input.c
  devices/virtio/vhost_user_output.c
  devices/virtio/vhost_user_api.c
  devices/virtio/virtio.c
  devices/virtio/virtio_api.c
  devices/virtio/virtio_pci_legacy.c
  devices/virtio/virtio_pci_modern.c
  devices/virtio/virtio_process.c
  devices/virtio/virtio_types_api.c
)

list(APPEND VNET_HEADERS
  devices/virtio/pci.h
  devices/virtio/virtio.h
  devices/virtio/virtio_buffering.h
  devices/virtio/virtio_std.h
  devices/virtio/virtio_pci_legacy.h
  devices/virtio/virtio_pci_modern.h
  devices/virtio/vhost_std.h
  devices/virtio/vhost_user.h
  devices/virtio/virtio_types_api.h
)

list(APPEND VNET_MULTIARCH_SOURCES
  devices/virtio/vhost_user_input.c
  devices/virtio/vhost_user_output.c
  devices/virtio/node.c
  devices/af_packet/node.c
  devices/virtio/device.c
)

list(APPEND VNET_API_FILES
  devices/virtio/vhost_user.api
  devices/virtio/virtio.api
  devices/virtio/virtio_types.api
)

##############################################################################
# tap interface (with virtio backend)
##############################################################################

list(APPEND VNET_SOURCES
  devices/tap/cli.c
  devices/tap/tap.c
  devices/tap/tapv2_api.c
)

list(APPEND VNET_HEADERS
  devices/tap/tap.h
)

list(APPEND VNET_API_FILES
  devices/tap/tapv2.api
)

##############################################################################
# tap interface (with virtio backend)
##############################################################################

list(APPEND VNET_SOURCES
  devices/pipe/pipe_api.c
  devices/pipe/pipe.c
)

list(APPEND VNET_HEADERS
  devices/pipe/pipe.h
)

list(APPEND VNET_API_FILES devices/pipe/pipe.api)

##############################################################################
# session managmeent
##############################################################################

list(APPEND VNET_SOURCES
  session/session.c
  session/session_debug.c
  session/session_table.c
  session/session_rules_table.c
  session/session_lookup.c
  session/session_node.c
  session/transport.c
  session/application.c
  session/application_worker.c
  session/session_cli.c
  session/application_interface.c
  session/application_local.c
  session/application_namespace.c
  session/segment_manager.c
  session/session_api.c
)

list(APPEND VNET_HEADERS
  session/session.h
  session/session_table.h
  session/session_rules_table.h
  session/session_types.h
  session/session_lookup.h
  session/application.h
  session/transport.h
  session/transport_types.h
  session/application_interface.h
  session/application_local.h
  session/application_namespace.h
  session/session_debug.h
  session/segment_manager.h
  session/mma_template.h
  session/mma_template.c
  session/mma_16.h
  session/mma_40.h
)

list(APPEND VNET_API_FILES session/session.api)

##############################################################################
# TLS protocol
##############################################################################

list(APPEND VNET_SOURCES
  tls/tls.c
)

list(APPEND VNET_HEADERS
  tls/tls.h
  tls/tls_test.h
)

##############################################################################
# Linux packet interface
##############################################################################

list(APPEND VNET_SOURCES
  devices/af_packet/af_packet.c
  devices/af_packet/device.c
  devices/af_packet/node.c
  devices/af_packet/cli.c
  devices/af_packet/af_packet_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  devices/af_packet/device.c
)

list(APPEND VNET_HEADERS
  devices/af_packet/af_packet.h
)

list(APPEND VNET_API_FILES devices/af_packet/af_packet.api)

##############################################################################
# Driver feature graph arc support
##############################################################################

list(APPEND VNET_SOURCES
  feature/feature.c
  feature/feature_api.c
  feature/registration.c
)

list(APPEND VNET_HEADERS
  feature/feature.h
)

list(APPEND VNET_API_FILES feature/feature.api)

##############################################################################
# Unix kernel related
##############################################################################

# FIXME: unix/hgshm.c

list(APPEND VNET_SOURCES
  unix/gdb_funcs.c
  unix/tuntap.c
)

list(APPEND VNET_HEADERS
  unix/tuntap.h
)

##############################################################################
# FIB
##############################################################################

list(APPEND VNET_SOURCES
  fib/fib.c
  fib/ip4_fib.c
  fib/ip6_fib.c
  fib/mpls_fib.c
  fib/fib_table.c
  fib/fib_walk.c
  fib/fib_types.c
  fib/fib_node.c
  fib/fib_node_list.c
  fib/fib_entry.c
  fib/fib_entry_src.c
  fib/fib_entry_src_adj.c
  fib/fib_entry_src_api.c
  fib/fib_entry_src_drop.c
  fib/fib_entry_src_interface.c
  fib/fib_entry_src_interpose.c
  fib/fib_entry_src_lisp.c
  fib/fib_entry_src_mpls.c
  fib/fib_entry_src_simple.c
  fib/fib_entry_src_rr.c
  fib/fib_entry_cover.c
  fib/fib_entry_delegate.c
  fib/fib_entry_track.c
  fib/fib_path_list.c
  fib/fib_path.c
  fib/fib_path_ext.c
  fib/fib_source.c
  fib/fib_urpf_list.c
  fib/fib_attached_export.c
  fib/fib_api.c
  fib/fib_bfd.c
)

list(APPEND VNET_HEADERS
  fib/fib.h
  fib/fib_api.h
  fib/ip4_fib.h
  fib/ip6_fib.h
  fib/fib_types.h
  fib/fib_table.h
  fib/fib_node.h
  fib/fib_node_list.h
  fib/fib_entry.h
  fib/fib_entry_delegate.h
  fib/fib_source.h
)

list(APPEND VNET_API_FILES fib/fib_types.api)

##############################################################################
# ADJ
##############################################################################

list(APPEND VNET_SOURCES
  adj/adj_nbr.c
  adj/adj_glean.c
  adj/adj_midchain.c
  adj/adj_midchain_delegate.c
  adj/adj_mcast.c
  adj/adj_l2.c
  adj/adj_nsh.c
  adj/adj.c
  adj/rewrite.c
  adj/adj_bfd.c
  adj/adj_delegate.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  adj/adj_nsh.c
  adj/adj_l2.c
  adj/adj_midchain.c
)

list(APPEND VNET_HEADERS
  adj/adj.h
  adj/adj_types.h
  adj/adj_glean.h
  adj/adj_nsh.h
  adj/adj_nbr.h
  adj/adj_midchain.h
  adj/rewrite.h
)

##############################################################################
# Data-Plane Objects
##############################################################################

list(APPEND VNET_SOURCES
  dpo/dpo.c
  dpo/drop_dpo.c
  dpo/ip_null_dpo.c
  dpo/ip6_ll_dpo.c
  dpo/punt_dpo.c
  dpo/receive_dpo.c
  dpo/load_balance.c
  dpo/load_balance_map.c
  dpo/lookup_dpo.c
  dpo/classify_dpo.c
  dpo/replicate_dpo.c
  dpo/interface_rx_dpo.c
  dpo/interface_tx_dpo.c
  dpo/mpls_disposition.c
  dpo/mpls_label_dpo.c
  dpo/l3_proxy_dpo.c
  dpo/dvr_dpo.c
  dpo/pw_cw.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  dpo/lookup_dpo.h
  dpo/mpls_disposition.c
  dpo/dvr_dpo.c
  dpo/mpls_label_dpo.c
  dpo/interface_rx_dpo.c
)

list(APPEND VNET_HEADERS
  dpo/load_balance.h
  dpo/drop_dpo.h
  dpo/lookup_dpo.h
  dpo/punt_dpo.h
  dpo/classify_dpo.h
  dpo/receive_dpo.h
  dpo/ip_null_dpo.h
  dpo/replicate_dpo.h
  dpo/dpo.h
)

##############################################################################
# Multicast FIB
##############################################################################

list(APPEND VNET_SOURCES
  mfib/mfib_forward.c
  mfib/ip4_mfib.c
  mfib/ip6_mfib.c
  mfib/mfib_api.c
  mfib/mfib_types.c
  mfib/mfib_signal.c
  mfib/mfib_itf.c
  mfib/mfib_entry.c
  mfib/mfib_entry.c
  mfib/mfib_entry_cover.c
  mfib/mfib_entry_delegate.c
  mfib/mfib_entry_src.c
  mfib/mfib_entry_src_rr.c
  mfib/mfib_table.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  mfib/mfib_forward.c
)

list(APPEND VNET_HEADERS
  mfib/ip4_mfib.h
  mfib/mfib_types.h
  mfib/mfib_table.h
)

list(APPEND VNET_API_FILES mfib/mfib_types.api)

##############################################################################
# Utilities
##############################################################################

list(APPEND VNET_SOURCES
  util/radix.c
  util/refcount.c
  util/throttle.c
  util/trajectory.c
)

list(APPEND VNET_HEADERS
  util/throttle.h
)

##############################################################################
# QoS
##############################################################################

list(APPEND VNET_SOURCES
  qos/qos_types.c
  qos/qos_api.c
  qos/qos_egress_map.c
  qos/qos_record.c
  qos/qos_record_node.c
  qos/qos_store.c
  qos/qos_store_node.c
  qos/qos_mark.c
  qos/qos_mark_node.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  qos/qos_record_node.c
  qos/qos_mark_node.c
)

list(APPEND VNET_API_FILES qos/qos.api)

##############################################################################
# BIER
##############################################################################

list(APPEND VNET_SOURCES
  bier/bier_bit_string.c
  bier/bier_entry.c
  bier/bier_fmask.c
  bier/bier_fmask_db.c
  bier/bier_input.c
  bier/bier_lookup.c
  bier/bier_output.c
  bier/bier_table.c
  bier/bier_types.c
  bier/bier_api.c
  bier/bier_drop.c
  bier/bier_update.c
  bier/bier_imp_node.c
  bier/bier_imp.c
  bier/bier_disp_entry.c
  bier/bier_disp_lookup_node.c
  bier/bier_disp_dispatch_node.c
  bier/bier_disp_table.c
  bier/bier_bift_table.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  bier/bier_disp_dispatch_node.c
  bier/bier_disp_lookup_node.c
  bier/bier_imp_node.c
)

list(APPEND VNET_HEADERS
  bier/bier_types.h
  bier/bier_entry.h
  bier/bier_update.h
  bier/bier_table.h
)

list(APPEND VNET_API_FILES bier/bier.api)

##############################################################################
# SYSLOG
##############################################################################

list (APPEND VNET_SOURCES
  syslog/syslog_api.c
  syslog/syslog_udp.c
  syslog/syslog.c
)

list(APPEND VNET_HEADERS
  syslog/syslog_udp.h
  syslog/syslog.h
)

list(APPEND VNET_API_FILES syslog/syslog.api)

##############################################################################
# Tunnel Endpoint Information Base
##############################################################################

list (APPEND VNET_SOURCES
  teib/teib_api.c
  teib/teib_cli.c
  teib/teib.c
)

list(APPEND VNET_HEADERS
  teib/teib.h
)

list(APPEND VNET_API_FILES teib/teib.api)

##############################################################################
# ARP/ND
##############################################################################

list (APPEND VNET_SOURCES
  arp/arp_api.c
  arp/arp.c
  arp/arp_proxy.c
)

list(APPEND VNET_HEADERS
  arp/arp.h
)

list(APPEND VNET_API_FILES arp/arp.api)

list (APPEND VNET_SOURCES
  ip6-nd/ip6_mld.c
  ip6-nd/ip6_nd.c
  ip6-nd/ip6_nd_api.c
  ip6-nd/ip6_nd_proxy.c
  ip6-nd/ip6_ra.c
  ip6-nd/rd_cp.c
  ip6-nd/rd_cp_api.c
)

list(APPEND VNET_HEADERS
  ip6-nd/ip6_nd.h
)

list(APPEND VNET_API_FILES
  ip6-nd/ip6_nd.api
  ip6-nd/rd_cp.api
)

##############################################################################
# VNET Library
##############################################################################

add_vpp_library(vnet
  SOURCES ${VNET_SOURCES}
  MULTIARCH_SOURCES ${VNET_MULTIARCH_SOURCES}
  INSTALL_HEADERS ${VNET_HEADERS}
  API_FILES ${VNET_API_FILES}
  LINK_LIBRARIES vppinfra svm vlib ${OPENSSL_LIBRARIES}
  DEPENDS vpp_version_h api_headers
)

##############################################################################
# vpp api test client library
##############################################################################

add_vpp_library (vatclient
  SOURCES ip/ip_types_api.c
  DEPENDS api_headers
)

##############################################################################
# VAT2 plugins
##############################################################################
add_vpp_test_library(vnet
  ${VNET_API_FILES}
)

##############################################################################
