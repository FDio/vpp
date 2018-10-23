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
  handoff.c
  interface.c
  interface_api.c
  interface_cli.c
  interface_format.c
  interface_output.c
  interface_stats.c
  misc.c
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
  interface.h
  interface_funcs.h
  ip/ip4_to_ip6.h
  ip/ip6_to_ip4.h
  l3_types.h
  plugin/plugin.h
  pipeline.h
  vnet.h
  vnet_all_api_h.h
  vnet_msg_enum.h
  util/radix.h
  util/refcount.h
)

list(APPEND VNET_API_FILES interface.api)

##############################################################################
# Policer infra
##############################################################################
list(APPEND VNET_SOURCES
  policer/node_funcs.c
  policer/policer.c
  policer/xlate.c
  policer/policer_api.c
)

list(APPEND VNET_HEADERS
  policer/police.h
  policer/policer.h
  policer/xlate.h
)

list(APPEND VNET_API_FILES policer/policer.api)

##############################################################################
# Cop - junk filter
##############################################################################
list(APPEND VNET_SOURCES
  cop/cop.c
  cop/node1.c
  cop/ip4_whitelist.c
  cop/ip6_whitelist.c
  cop/cop_api.c
)

list(APPEND VNET_HEADERS
  cop/cop.h
)

list(APPEND VNET_API_FILES cop/cop.api)

##############################################################################
# Layer 2 protocols go here
##############################################################################

##############################################################################
# Layer 2 protocol: Ethernet
##############################################################################
list(APPEND VNET_SOURCES
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

list(APPEND VNET_MULTIARCH_SOURCES ethernet/node.c)

list(APPEND VNET_HEADERS
  ethernet/error.def
  ethernet/ethernet.h
  ethernet/mac_address.h
  ethernet/packet.h
  ethernet/types.def
  ethernet/sfp.h
  ethernet/p2p_ethernet.h
)

list(APPEND VNET_API_FILES ethernet/p2p_ethernet.api)

##############################################################################
# Layer 2 protocol: Ethernet bridging
##############################################################################
list(APPEND VNET_SOURCES
  l2/feat_bitmap.c
  l2/l2_api.c
  l2/l2_bd.c
  l2/l2_bvi.c
  l2/l2_input_classify.c
  l2/l2_output_classify.c
  l2/l2_efp_filter.c
  l2/l2_fib.c
  l2/l2_flood.c
  l2/l2_fwd.c
  l2/l2_input.c
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
  l2/l2_fwd.c
  l2/l2_learn.c
  l2/l2_output.c
  l2/l2_patch.c
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

list(APPEND VNET_HEADERS
  vxlan/vxlan.h
  vxlan/vxlan_packet.h
  vxlan/vxlan_error.def
)

list(APPEND VNET_MULTIARCH_SOURCES vxlan/decap.c)

list(APPEND VNET_API_FILES vxlan/vxlan.api)

##############################################################################
# Layer 2 / Geneve
##############################################################################
list(APPEND VNET_SOURCES
  geneve/geneve.c
  geneve/encap.c
  geneve/decap.c
  geneve/geneve_api.c
)

list(APPEND VNET_HEADERS
  geneve/geneve.h
  geneve/geneve_packet.h
  geneve/geneve_error.def
)

list(APPEND VNET_API_FILES geneve/geneve.api)

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
# Layer 2 / LLDP
##############################################################################
list(APPEND VNET_SOURCES
  lldp/lldp_input.c
  lldp/lldp_node.c
  lldp/lldp_output.c
  lldp/lldp_cli.c
  lldp/lldp_api.c
)

list(APPEND VNET_HEADERS
  lldp/lldp_protocol.h
  lldp/lldp.h
)

list(APPEND VNET_API_FILES lldp/lldp.api)

##############################################################################
# Layer 2/3 "classify"
##############################################################################
list(APPEND VNET_SOURCES
  classify/vnet_classify.c
  classify/ip_classify.c
  classify/in_out_acl.c
  classify/policer_classify.c
  classify/flow_classify.c
  classify/flow_classify_node.c
  classify/vnet_classify.h
  classify/classify_api.c
)

list(APPEND VNET_HEADERS
  classify/vnet_classify.h
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
  ip/ip4_format.c
  ip/ip4_forward.c
  ip/ip4_punt_drop.c
  ip/ip4_input.c
  ip/ip4_options.c
  ip/ip4_mtrie.c
  ip/ip4_pg.c
  ip/ip4_source_and_port_range_check.c
  ip/ip4_source_check.c
  ip/ip4_reassembly.c
  ip/ip6_format.c
  ip/ip6_forward.c
  ip/ip6_ll_table.c
  ip/ip6_ll_types.c
  ip/ip6_punt_drop.c
  ip/ip6_hop_by_hop.c
  ip/ip6_input.c
  ip/ip6_neighbor.c
  ip/ip6_pg.c
  ip/ip6_reassembly.c
  ip/rd_cp.c
  ip/ip_neighbor.c
  ip/ip_api.c
  ip/ip_checksum.c
  ip/ip_frag.c
  ip/ip.c
  ip/ip_init.c
  ip/ip_in_out_acl.c
  ip/lookup.c
  ip/ping.c
  ip/punt_api.c
  ip/punt.c
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
  ip/ip4_packet.h
  ip/ip6_error.h
  ip/ip6.h
  ip/ip6_hop_by_hop.h
  ip/ip6_hop_by_hop_packet.h
  ip/ip6_packet.h
  ip/ip6_neighbor.h
  ip/ip.h
  ip/ip_packet.h
  ip/ip_source_and_port_range_check.h
  ip/ip_neighbor.h
  ip/lookup.h
  ip/ports.def
  ip/protocols.def
  ip/punt_error.def
  ip/punt.h
)

list(APPEND VNET_API_FILES
  ip/ip.api
  ip/rd_cp.api
  ip/punt.api
)

list(APPEND VNET_MULTIARCH_SOURCES ip/ip4_forward.c ip/ip4_input.c)

##############################################################################
# Layer 2/3 ARP
##############################################################################
list(APPEND VNET_SOURCES
  ethernet/arp.c
)

list(APPEND VNET_HEADERS
  ethernet/arp_packet.h
  ethernet/arp.h
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
# Layer 3 protocol: IPSec
##############################################################################
list(APPEND VNET_SOURCES
  ipsec/ipsec.c
  ipsec/ipsec_cli.c
  ipsec/ipsec_format.c
  ipsec/ipsec_input.c
  ipsec/ipsec_if.c
  ipsec/ipsec_if_in.c
  ipsec/esp_format.c
  ipsec/esp_encrypt.c
  ipsec/esp_decrypt.c
  ipsec/ah_decrypt.c
  ipsec/ah_encrypt.c
  ipsec/ikev2.c
  ipsec/ikev2_crypto.c
  ipsec/ikev2_cli.c
  ipsec/ikev2_payload.c
  ipsec/ikev2_format.c
  ipsec/ipsec_api.c
)

list(APPEND VNET_MULTIARCH_SOURCES
  ipsec/esp_encrypt.c
  ipsec/esp_decrypt.c
  ipsec/ah_decrypt.c
  ipsec/ah_encrypt.c
)

list(APPEND VNET_API_FILES ipsec/ipsec.api)

list(APPEND VNET_SOURCES
  ipsec/ipsec_output.c
)

list(APPEND VNET_HEADERS
  ipsec/ipsec.h
  ipsec/esp.h
  ipsec/ah.h
  ipsec/ikev2.h
  ipsec/ikev2_priv.h
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
  tcp/tcp_cubic.c
  tcp/tcp.c
)

list(APPEND VNET_HEADERS
  tcp/tcp_packet.h
  tcp/tcp_timer.h
  tcp/tcp_debug.h
  tcp/tcp.h
  tcp/tcp_error.def
)

list(APPEND VNET_API_FILES tcp/tcp.api)

##############################################################################
# Layer 4 protocol: udp
##############################################################################
list(APPEND VNET_SOURCES
  udp/udp.c
  udp/udp_input.c
  udp/udp_format.c
  udp/udp_local.c
  udp/udp_pg.c
  udp/udp_encap_node.c
  udp/udp_encap.c
  udp/udp_api.c
)

list(APPEND VNET_HEADERS
  udp/udp_error.def
  udp/udp.h
  udp/udp_packet.h
)

list(APPEND VNET_API_FILES udp/udp.api)

##############################################################################
# Layer 4 protocol: sctp
##############################################################################
list(APPEND VNET_SOURCES
  sctp/sctp_api.c
  sctp/sctp.c
  sctp/sctp_pg.c
  sctp/sctp_input.c
  sctp/sctp_output.c
  sctp/sctp_format.c
)

list(APPEND VNET_HEADERS
  sctp/sctp_error.def
  sctp/sctp_packet.h
  sctp/sctp_timer.h
  sctp/sctp.h
)

list(APPEND VNET_API_FILES sctp/sctp.api)

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

list(APPEND VNET_HEADERS
  ipip/ipip.h
)

list(APPEND VNET_API_FILES ipip/ipip.api)

##############################################################################
# Tunnel protocol: l2tpv3
##############################################################################
list(APPEND VNET_SOURCES
  l2tp/l2tp.c
  l2tp/encap.c
  l2tp/decap.c
  l2tp/pg.c
  l2tp/l2tp_api.c
)

list(APPEND VNET_HEADERS
  l2tp/l2tp.h
  l2tp/packet.h
)

list(APPEND VNET_API_FILES l2tp/l2tp.api)

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

list(APPEND VNET_HEADERS
  vxlan-gpe/vxlan_gpe.h
  vxlan-gpe/vxlan_gpe_packet.h
  vxlan-gpe/vxlan_gpe_error.def
)

list(APPEND VNET_API_FILES vxlan-gpe/vxlan_gpe.api)

##############################################################################
# Tunnel protocol: ipsec+gre
##############################################################################
list(APPEND VNET_SOURCES
  ipsec-gre/ipsec_gre.c
  ipsec-gre/node.c
  ipsec-gre/interface.c
  ipsec-gre/ipsec_gre_api.c
)

list(APPEND VNET_HEADERS
  ipsec-gre/ipsec_gre.h
  ipsec-gre/error.def
)

list(APPEND VNET_API_FILES ipsec-gre/ipsec_gre.api)

##############################################################################
# LISP control plane: lisp-cp
##############################################################################

list(APPEND VNET_SOURCES
  lisp-cp/lisp_types.c
  lisp-cp/lisp_cp_dpo.c
  lisp-cp/control.c
  lisp-cp/gid_dictionary.c
  lisp-cp/lisp_msg_serdes.c
  lisp-cp/packets.c
  lisp-cp/one_cli.c
  lisp-cp/lisp_cli.c
  lisp-cp/one_api.c
  lisp-cp/lisp_api.c
)

list(APPEND VNET_HEADERS
  lisp-cp/lisp_types.h
  lisp-cp/packets.h
  lisp-cp/gid_dictionary.h
  lisp-cp/lisp_cp_messages.h
  lisp-cp/lisp_msg_serdes.h
  lisp-cp/control.h
)

list(APPEND VNET_API_FILES lisp-cp/lisp.api)
list(APPEND VNET_API_FILES lisp-cp/one.api)

##############################################################################
# Tunnel protocol: lisp-gpe
##############################################################################

list(APPEND VNET_SOURCES
  lisp-gpe/lisp_gpe.c
  lisp-gpe/lisp_gpe_sub_interface.c
  lisp-gpe/lisp_gpe_adjacency.c
  lisp-gpe/lisp_gpe_tunnel.c
  lisp-gpe/lisp_gpe_fwd_entry.c
  lisp-gpe/lisp_gpe_tenant.c
  lisp-gpe/interface.c
  lisp-gpe/decap.c
  lisp-gpe/lisp_gpe_api.c
)

list(APPEND VNET_HEADERS
  lisp-gpe/lisp_gpe.h
  lisp-gpe/lisp_gpe_fwd_entry.h
  lisp-gpe/lisp_gpe_tenant.h
  lisp-gpe/lisp_gpe_packet.h
  lisp-gpe/lisp_gpe_error.def
)

list(APPEND VNET_API_FILES lisp-gpe/lisp_gpe.api)

##############################################################################
# DHCP client
##############################################################################
list(APPEND VNET_SOURCES
  dhcp/client.c
  dhcp/dhcp_client_detect.c
  dhcp/dhcp6_client_common_dp.c
  dhcp/dhcp6_pd_client_dp.c
  dhcp/dhcp6_pd_client_cp.c
  dhcp/dhcp6_ia_na_client_dp.c
  dhcp/dhcp6_ia_na_client_cp.c
  dhcp/dhcp_api.c
)

list(APPEND VNET_HEADERS
  dhcp/client.h
  dhcp/dhcp6_client_common_dp.h
  dhcp/dhcp6_pd_client_dp.h
  dhcp/dhcp6_ia_na_client_dp.h
)

list(APPEND VNET_API_FILES
  dhcp/dhcp.api
  dhcp/dhcp6_pd_client_cp.api
  dhcp/dhcp6_ia_na_client_cp.api
)

##############################################################################
# DHCP proxy
##############################################################################
list(APPEND VNET_SOURCES
  dhcp/dhcp6_proxy_node.c
  dhcp/dhcp4_proxy_node.c
  dhcp/dhcp_proxy.c
)

list(APPEND VNET_HEADERS
  dhcp/dhcp4_packet.h
  dhcp/dhcp6_packet.h
  dhcp/dhcp_proxy.h
  dhcp/dhcp6_proxy_error.def
  dhcp/dhcp4_proxy_error.def
)

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

list(APPEND VNET_API_FILES srv6/sr.api)

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

list(APPEND VNET_API_FILES srmpls/sr_mpls.api)

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

list(APPEND VNET_HEADERS
  span/span.h
)

list(APPEND VNET_API_FILES span/span.api)

##############################################################################
# DNS proxy, API
##############################################################################
list(APPEND VNET_SOURCES
  dns/dns.c
  dns/dns.h
  dns/dns_packet.h
  dns/reply_node.c
  dns/request_node.c
  dns/resolver_process.c
)

list(APPEND VNET_HEADERS
  dns/dns.h
)

list(APPEND VNET_API_FILES dns/dns.api)

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
  devices/virtio/device.c
  devices/virtio/node.c
  devices/virtio/vhost_user.c
  devices/virtio/vhost_user_input.c
  devices/virtio/vhost_user_output.c
  devices/virtio/vhost_user_api.c
  devices/virtio/virtio.c
  devices/virtio/virtio_api.c
  devices/virtio/cli.c
  devices/virtio/pci.c
)

list(APPEND VNET_HEADERS
  devices/virtio/pci.h
  devices/virtio/virtio.h
  devices/virtio/vhost_user.h
)

list(APPEND VNET_MULTIARCH_SOURCES
  devices/virtio/vhost_user_input.c
  devices/virtio/vhost_user_output.c
)

list(APPEND VNET_API_FILES
  devices/virtio/vhost_user.api
  devices/virtio/virtio.api
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

list(APPEND VNET_API_FILES devices/tap/tapv2.api)

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
  session/session_table.c
  session/session_rules_table.c
  session/session_lookup.c
  session/session_node.c
  session/transport.c
  session/application.c
  session/session_cli.c
  session/application_interface.c
  session/application_namespace.c
  session/segment_manager.c
  session/session_api.c
)

list(APPEND VNET_HEADERS
  session/session.h
  session/session_table.h
  session/session_rules_table.h
  session/stream_session.h
  session/session_lookup.h
  session/application.h
  session/transport.h
  session/transport_interface.h
  session/application_interface.h
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
# session layer applications
##############################################################################

list(APPEND VNET_SOURCES
  session-apps/echo_client.c
  session-apps/echo_server.c
  session-apps/http_server.c
  session-apps/proxy.c
)

list(APPEND VNET_HEADERS
  session-apps/echo_client.h
  session-apps/proxy.h
)

##############################################################################
# TLS protocol
##############################################################################

list(APPEND VNET_SOURCES
  tls/tls.c
)

list(APPEND VNET_HEADERS
  tls/tls.h
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

list(APPEND VNET_HEADERS
  devices/af_packet/af_packet.h
)

list(APPEND VNET_API_FILES devices/af_packet/af_packet.api)

##############################################################################
# NETMAP interface
##############################################################################

list(APPEND VNET_SOURCES
  devices/netmap/netmap.c
  devices/netmap/device.c
  devices/netmap/node.c
  devices/netmap/cli.c
  devices/netmap/netmap_api.c
)

list(APPEND VNET_HEADERS
  devices/netmap/netmap.h
)

list(APPEND VNET_API_FILES devices/netmap/netmap.api)

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
  unix/tap_api.c
  unix/tapcli.c
  unix/tuntap.c
)

list(APPEND VNET_HEADERS
  unix/tuntap.h
  unix/tapcli.h
)

list(APPEND VNET_API_FILES unix/tap.api)

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
  fib/fib_entry_src_rr.c
  fib/fib_entry_src_interface.c
  fib/fib_entry_src_interpose.c
  fib/fib_entry_src_default_route.c
  fib/fib_entry_src_special.c
  fib/fib_entry_src_api.c
  fib/fib_entry_src_adj.c
  fib/fib_entry_src_mpls.c
  fib/fib_entry_src_lisp.c
  fib/fib_entry_cover.c
  fib/fib_entry_delegate.c
  fib/fib_path_list.c
  fib/fib_path.c
  fib/fib_path_ext.c
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
)

##############################################################################
# ADJ
##############################################################################

list(APPEND VNET_SOURCES
  adj/adj_nbr.c
  adj/adj_glean.c
  adj/adj_midchain.c
  adj/adj_mcast.c
  adj/adj_l2.c
  adj/adj_nsh.c
  adj/adj.c
  adj/rewrite.c
  adj/adj_bfd.c
  adj/adj_delegate.c
)

list(APPEND VNET_HEADERS
  adj/adj.h
  adj/adj_types.h
  adj/adj_glean.h
  adj/adj_nsh.h
  adj/adj_nbr.h
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

list(APPEND VNET_HEADERS
  mfib/ip4_mfib.h
  mfib/mfib_types.h
  mfib/mfib_table.h
)

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
  qos/qos_mark.c
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
# VNET Library
##############################################################################

add_vpp_library(vnet
  SOURCES ${VNET_SOURCES}
  MULTIARCH_SOURCES ${VNET_MULTIARCH_SOURCES}
  INSTALL_HEADERS ${VNET_HEADERS}
  API_FILES ${VNET_API_FILES}
  LINK_LIBRARIES vppinfra svm vlib ${OPENSSL_LIBRARIES}
  DEPENDS api_headers
)

##############################################################################
# Session echo apps
##############################################################################

option(VPP_BUILD_SESSION_ECHO_APPS "Build session echo apps." ON)
if(VPP_BUILD_SESSION_ECHO_APPS)
  add_vpp_executable(tcp_echo
    SOURCES ../tests/vnet/session/tcp_echo.c
    LINK_LIBRARIES vlibmemoryclient svm vppinfra pthread m rt
    DEPENDS api_headers
    NO_INSTALL
    )
  add_vpp_executable(udp_echo
    SOURCES ../tests/vnet/session/udp_echo.c
    LINK_LIBRARIES vlibmemoryclient svm vppinfra pthread m rt
    DEPENDS api_headers
    NO_INSTALL
    )
endif(VPP_BUILD_SESSION_ECHO_APPS)

##############################################################################
