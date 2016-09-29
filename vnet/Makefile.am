# Copyright (c) 2015 Cisco and/or its affiliates.
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

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall -Werror @DPDK@ @DPDK_CRYPTO@ @IPSEC@ @IPV6SR@

BUILT_SOURCES = 				\
 vnet/interface.api.h				\
 vnet/interface.api.json			\
 vnet/ip/ip.api.h				\
 vnet/ip/ip.api.json				\
 vnet/l2/l2.api.h				\
 vnet/l2/l2.api.json				\
 vnet/map/map.api.h				\
 vnet/map/map.api.json				\
 vnet/span/span.api.h				\
 vnet/span/span.api.json			\
 vnet/unix/tap.api.h				\
 vnet/unix/tap.api.json

libvnet_la_SOURCES =
libvnetplugin_la_SOURCES =
nobase_include_HEADERS =
noinst_PROGRAMS =
TESTS =

dpdk_libs =
if WITH_DPDK
dpdk_libs += -l:libdpdk.a
endif

########################################
# Generic stuff
########################################
libvnet_la_SOURCES +=					\
  vnet/config.c						\
  vnet/devices/devices.c				\
  vnet/handoff.c					\
  vnet/interface.c					\
  vnet/interface_api.c					\
  vnet/interface_cli.c					\
  vnet/interface_format.c				\
  vnet/interface_output.c				\
  vnet/misc.c						\
  vnet/replication.c                                    \
  vnet/rewrite.c				

nobase_include_HEADERS +=			\
  vnet/api_errno.h				\
  vnet/buffer.h					\
  vnet/config.h					\
  vnet/devices/devices.h			\
  vnet/global_funcs.h				\
  vnet/handoff.h				\
  vnet/interface.h				\
  vnet/interface.api.h				\
  vnet/interface_funcs.h			\
  vnet/l3_types.h				\
  vnet/pipeline.h				\
  vnet/replication.h				\
  vnet/rewrite.h				\
  vnet/vnet.h					\
  vnet/vnet_all_api_h.h				\
  vnet/vnet_msg_enum.h

########################################
# Policer infra
########################################

libvnet_la_SOURCES +=				\
  vnet/policer/node_funcs.c			\
  vnet/policer/policer.c			\
  vnet/policer/xlate.c

nobase_include_HEADERS +=			\
  vnet/policer/police.h				\
  vnet/policer/policer.h			\
  vnet/policer/xlate.h

########################################
# Cop - junk filter
########################################

libvnet_la_SOURCES +=				\
  vnet/cop/cop.c				\
  vnet/cop/node1.c				\
  vnet/cop/ip4_whitelist.c			\
  vnet/cop/ip6_whitelist.c	

nobase_include_HEADERS +=			\
  vnet/cop/cop.h

########################################
# Layer 2 protocols go here
########################################

########################################
# Layer 2 protocol: Ethernet
########################################
libvnet_la_SOURCES +=				\
 vnet/ethernet/arp.c				\
 vnet/ethernet/format.c				\
 vnet/ethernet/init.c				\
 vnet/ethernet/interface.c			\
 vnet/ethernet/node.c				\
 vnet/ethernet/pg.c

nobase_include_HEADERS +=			\
 vnet/ethernet/arp_packet.h			\
 vnet/ethernet/error.def			\
 vnet/ethernet/ethernet.h			\
 vnet/ethernet/packet.h				\
 vnet/ethernet/types.def

########################################
# Layer 2 protocol: Ethernet bridging
########################################
libvnet_la_SOURCES +=				\
 vnet/l2/feat_bitmap.c				\
 vnet/l2/l2_api.c      				\
 vnet/l2/l2_bd.c				\
 vnet/l2/l2_bvi.c				\
 vnet/l2/l2_input_classify.c			\
 vnet/l2/l2_output_classify.c			\
 vnet/l2/l2_efp_filter.c			\
 vnet/l2/l2_fib.c				\
 vnet/l2/l2_flood.c				\
 vnet/l2/l2_fwd.c				\
 vnet/l2/l2_input_acl.c				\
 vnet/l2/l2_input.c				\
 vnet/l2/l2_input_vtr.c				\
 vnet/l2/l2_learn.c				\
 vnet/l2/l2_output_acl.c			\
 vnet/l2/l2_output.c				\
 vnet/l2/l2_patch.c				\
 vnet/l2/l2_rw.c                                \
 vnet/l2/l2_vtr.c				\
 vnet/l2/l2_xcrw.c

nobase_include_HEADERS +=			\
 vnet/l2/feat_bitmap.h				\
 vnet/l2/l2_input.h				\
 vnet/l2/l2_output.h				\
 vnet/l2/l2_vtr.h				\
 vnet/l2/l2_input_vtr.h				\
 vnet/l2/l2_efp_filter.h			\
 vnet/l2/l2_fwd.h				\
 vnet/l2/l2_bd.h				\
 vnet/l2/l2_bvi.h				\
 vnet/l2/l2_flood.h				\
 vnet/l2/l2_fib.h				\
 vnet/l2/l2_rw.h                                \
 vnet/l2/l2_xcrw.h				\
 vnet/l2/l2_classify.h				\
 vnet/l2/l2.api.h

########################################
# Layer 2 protocol: SRP
########################################
libvnet_la_SOURCES +=				\
 vnet/srp/format.c				\
 vnet/srp/interface.c				\
 vnet/srp/node.c				\
 vnet/srp/pg.c

nobase_include_HEADERS +=			\
 vnet/srp/packet.h				\
 vnet/srp/srp.h

########################################
# Layer 2 protocol: PPP
########################################
libvnet_la_SOURCES +=				\
  vnet/ppp/node.c				\
  vnet/ppp/pg.c					\
  vnet/ppp/ppp.c

nobase_include_HEADERS +=			\
 vnet/ppp/error.def				\
 vnet/ppp/ppp.h					\
 vnet/ppp/packet.h

########################################
# Layer 2 protocol: HDLC
########################################
libvnet_la_SOURCES +=				\
  vnet/hdlc/node.c				\
  vnet/hdlc/pg.c				\
  vnet/hdlc/hdlc.c

nobase_include_HEADERS +=			\
 vnet/hdlc/error.def				\
 vnet/hdlc/hdlc.h				\
 vnet/hdlc/packet.h

########################################
# Layer 2 protocol: LLC
########################################
libvnet_la_SOURCES +=				\
  vnet/llc/llc.c				\
  vnet/llc/node.c				\
  vnet/llc/pg.c

nobase_include_HEADERS +=			\
 vnet/llc/llc.h

########################################
# Layer 2 protocol: SNAP
########################################
libvnet_la_SOURCES +=				\
  vnet/snap/snap.c				\
  vnet/snap/node.c				\
  vnet/snap/pg.c

nobase_include_HEADERS +=			\
 vnet/snap/snap.h

########################################
# Layer 2 / vxlan
########################################
libvnet_la_SOURCES +=				\
  vnet/vxlan/vxlan.c				\
  vnet/vxlan/encap.c				\
  vnet/vxlan/decap.c	

nobase_include_HEADERS +=			\
  vnet/vxlan/vxlan.h				\
  vnet/vxlan/vxlan_packet.h         		\
  vnet/vxlan/vxlan_error.def

########################################
# Layer 2 / CDP
########################################
libvnet_la_SOURCES +=				\
  vnet/cdp/cdp_input.c				\
  vnet/cdp/cdp_node.c				\
  vnet/cdp/cdp_periodic.c	

nobase_include_HEADERS +=			\
  vnet/cdp/cdp_protocol.h

########################################
# Layer 2 / LLDP
########################################
libvnet_la_SOURCES +=				\
  vnet/lldp/lldp_input.c				\
  vnet/lldp/lldp_node.c				\
  vnet/lldp/lldp_output.c	\
  vnet/lldp/lldp_cli.c

nobase_include_HEADERS +=			\
  vnet/lldp/lldp_protocol.h

########################################
# Layer 2/3 "classify"
########################################
libvnet_la_SOURCES +=				\
  vnet/classify/vnet_classify.c			\
  vnet/classify/ip_classify.c			\
  vnet/classify/input_acl.c			\
  vnet/classify/policer_classify.c		\
  vnet/classify/flow_classify.c                 \
  vnet/classify/flow_classify_node.c            \
  vnet/classify/vnet_classify.h

nobase_include_HEADERS +=			\
  vnet/classify/vnet_classify.h	                \
  vnet/classify/input_acl.h                     \
  vnet/classify/policer_classify.h              \
  vnet/classify/flow_classify.h

########################################
# Layer 3 protocols go here
########################################

########################################
# Layer 3 protocol: IP v4/v6
########################################
libvnet_la_SOURCES +=				\
 vnet/ip/format.c				\
 vnet/ip/icmp4.c				\
 vnet/ip/icmp6.c				\
 vnet/ip/ip46_cli.c				\
 vnet/ip/ip4_format.c				\
 vnet/ip/ip4_forward.c				\
 vnet/ip/ip4_input.c				\
 vnet/ip/ip4_mtrie.c				\
 vnet/ip/ip4_pg.c				\
 vnet/ip/ip4_source_and_port_range_check.c	\
 vnet/ip/ip4_source_check.c			\
 vnet/ip/ip6_format.c				\
 vnet/ip/ip6_forward.c				\
 vnet/ip/ip6_hop_by_hop.c			\
 vnet/ip/ip6_input.c				\
 vnet/ip/ip6_neighbor.c				\
 vnet/ip/ip6_pg.c				\
 vnet/ip/ip_api.c				\
 vnet/ip/ip_checksum.c				\
 vnet/ip/ip_frag.c				\
 vnet/ip/ip.h					\
 vnet/ip/ip_init.c				\
 vnet/ip/ip_input_acl.c				\
 vnet/ip/lookup.c				\
 vnet/ip/ping.c					\
 vnet/ip/punt.c					\
 vnet/ip/udp_format.c				\
 vnet/ip/udp_init.c				\
 vnet/ip/udp_local.c				\
 vnet/ip/udp_pg.c

nobase_include_HEADERS +=			\
 vnet/ip/format.h				\
 vnet/ip/icmp46_packet.h			\
 vnet/ip/icmp4.h				\
 vnet/ip/icmp6.h				\
 vnet/ip/igmp_packet.h				\
 vnet/ip/ip.api.h				\
 vnet/ip/ip4_error.h				\
 vnet/ip/ip4.h					\
 vnet/ip/ip4_mtrie.h				\
 vnet/ip/ip4_packet.h				\
 vnet/ip/ip6_error.h				\
 vnet/ip/ip6.h					\
 vnet/ip/ip6_hop_by_hop.h			\
 vnet/ip/ip6_hop_by_hop_packet.h		\
 vnet/ip/ip6_packet.h				\
 vnet/ip/ip6_neighbor.h				\
 vnet/ip/ip.h					\
 vnet/ip/ip_packet.h				\
 vnet/ip/ip_source_and_port_range_check.h	\
 vnet/ip/lookup.h				\
 vnet/ip/ports.def				\
 vnet/ip/protocols.def				\
 vnet/ip/punt_error.def				\
 vnet/ip/punt.h					\
 vnet/ip/tcp_packet.h				\
 vnet/ip/udp_error.def				\
 vnet/ip/udp.h					\
 vnet/ip/udp_packet.h

########################################
# Bidirectional Forwarding Detection
########################################

nobase_include_HEADERS +=                       \
 vnet/bfd/bfd_protocol.h			\
 vnet/bfd/bfd_main.h                            \
 vnet/bfd/bfd_api.h                            \
 vnet/bfd/bfd_udp.h

libvnet_la_SOURCES +=				\
 vnet/bfd/bfd_api.h                            \
 vnet/bfd/bfd_udp.c                             \
 vnet/bfd/bfd_main.c                            \
 vnet/bfd/bfd_protocol.c

########################################
# Layer 3 protocol: IPSec
########################################
if WITH_IPSEC
libvnet_la_SOURCES +=       			\
 vnet/ipsec/ipsec.c				\
 vnet/ipsec/ipsec_cli.c  			\
 vnet/ipsec/ipsec_format.c			\
 vnet/ipsec/ipsec_input.c			\
 vnet/ipsec/ipsec_if.c				\
 vnet/ipsec/ipsec_if_in.c			\
 vnet/ipsec/ipsec_if_out.c			\
 vnet/ipsec/esp_encrypt.c			\
 vnet/ipsec/esp_decrypt.c			\
 vnet/ipsec/ikev2.c				\
 vnet/ipsec/ikev2_crypto.c			\
 vnet/ipsec/ikev2_cli.c				\
 vnet/ipsec/ikev2_payload.c			\
 vnet/ipsec/ikev2_format.c
if WITH_DPDK_CRYPTO
libvnet_la_SOURCES +=       			\
 vnet/devices/dpdk/ipsec/esp_encrypt.c		\
 vnet/devices/dpdk/ipsec/esp_decrypt.c		\
 vnet/devices/dpdk/ipsec/crypto_node.c		\
 vnet/devices/dpdk/ipsec/cli.c			\
 vnet/devices/dpdk/ipsec/ipsec.c
endif
endif

libvnet_la_SOURCES +=       			\
 vnet/ipsec/ipsec_output.c

nobase_include_HEADERS +=     		        \
 vnet/ipsec/ipsec.h                             \
 vnet/ipsec/esp.h				\
 vnet/ipsec/ikev2.h                             \
 vnet/ipsec/ikev2_priv.h
if WITH_DPDK_CRYPTO
nobase_include_HEADERS +=     		        \
 vnet/devices/dpdk/ipsec/ipsec.h		\
 vnet/devices/dpdk/ipsec/esp.h
endif

########################################
# Layer 3 protocol: osi
########################################
libvnet_la_SOURCES +=				\
 vnet/osi/node.c				\
 vnet/osi/osi.c					\
 vnet/osi/pg.c

nobase_include_HEADERS +=			\
 vnet/osi/osi.h

########################################
# Layer 3 protocol: MAP
########################################
libvnet_la_SOURCES +=				\
 vnet/map/map.c					\
 vnet/map/map_dpo.c				\
 vnet/map/ip4_map.c				\
 vnet/map/ip6_map.c				\
 vnet/map/ip4_map_t.c				\
 vnet/map/ip6_map_t.c				\
 vnet/map/map_api.c

nobase_include_HEADERS +=			\
 vnet/map/map.h					\
 vnet/map/map_dpo.h				\
 vnet/map/map.api.h

if ENABLE_TESTS
TESTS += test_map
test_map_SOURCES =                             \
 vnet/map/test.c
test_map_CPPFLAGS = $(AM_CPPFLAGS) -DCLIB_DEBUG

test_map_LDADD = libvnet.la -lvppinfra -lvlib	\
  -lpthread -lvlibmemory -lvlibapi -lvlib_unix	\
  -ldl -lsvm -lrt

test_map_LDFLAGS = -static
endif


########################################
# Tunnel protocol: gre
########################################
libvnet_la_SOURCES +=				\
 vnet/gre/gre.c					\
 vnet/gre/node.c				\
 vnet/gre/interface.c				\
 vnet/gre/pg.c
 
nobase_include_HEADERS +=			\
 vnet/gre/gre.h					\
 vnet/gre/packet.h				\
 vnet/gre/error.def

########################################
# Tunnel protocol: l2tpv3
########################################
libvnet_la_SOURCES +=				\
 vnet/l2tp/l2tp.c				\
 vnet/l2tp/encap.c 				\
 vnet/l2tp/decap.c  				\
 vnet/l2tp/pg.c
 
nobase_include_HEADERS +=			\
 vnet/l2tp/l2tp.h				\
 vnet/l2tp/packet.h				

########################################
# Tunnel protocol: gre+mpls
########################################
libvnet_la_SOURCES +=				\
 vnet/mpls/mpls.c				\
 vnet/mpls/mpls_lookup.c			\
 vnet/mpls/mpls_output.c			\
 vnet/mpls/mpls_features.c			\
 vnet/mpls/node.c				\
 vnet/mpls/interface.c			        \
 vnet/mpls/mpls_tunnel.c		        \
 vnet/mpls/pg.c
 
nobase_include_HEADERS +=			\
 vnet/mpls/mpls.h				\
 vnet/mpls/mpls_types.h			        \
 vnet/mpls/mpls_tunnel.h		        \
 vnet/mpls/packet.h				\
 vnet/mpls/error.def


########################################
# Tunnel protocol: vxlan-gpe
########################################

libvnet_la_SOURCES +=				\
 vnet/vxlan-gpe/vxlan_gpe.c			\
 vnet/vxlan-gpe/encap.c	        		\
 vnet/vxlan-gpe/decap.c

nobase_include_HEADERS +=			\
 vnet/vxlan-gpe/vxlan_gpe.h			\
 vnet/vxlan-gpe/vxlan_gpe_packet.h		\
 vnet/vxlan-gpe/vxlan_gpe_error.def

########################################
# Tunnel protocol: ipsec+gre
########################################
libvnet_la_SOURCES +=				\
 vnet/ipsec-gre/ipsec_gre.c			\
 vnet/ipsec-gre/node.c				\
 vnet/ipsec-gre/interface.c

nobase_include_HEADERS +=			\
 vnet/ipsec-gre/ipsec_gre.h		        \
 vnet/ipsec-gre/error.def

########################################
# LISP control plane: lisp-cp
########################################

libvnet_la_SOURCES +=				\
 vnet/lisp-cp/lisp_types.c			\
 vnet/lisp-cp/lisp_cp_dpo.c			\
 vnet/lisp-cp/control.c				\
 vnet/lisp-cp/gid_dictionary.c			\
 vnet/lisp-cp/lisp_msg_serdes.c			\
 vnet/lisp-cp/packets.c			

nobase_include_HEADERS +=			\
 vnet/lisp-cp/lisp_types.h			\
 vnet/lisp-cp/packets.h				\
 vnet/lisp-cp/gid_dictionary.h			\
 vnet/lisp-cp/lisp_cp_messages.h		\
 vnet/lisp-cp/lisp_msg_serdes.h			\
 vnet/lisp-cp/control.h				


if ENABLE_TESTS
LDS = -lvppinfra -l:libvlib.a $(dpdk_libs) -l:libvlibmemory.a \
	-l:libvlibapi.a -l:libsvm.a -lpthread -ldl -lrt -lm -l:libvlib_unix.a

TESTS += test_cp_serdes test_lisp_types

test_cp_serdes_SOURCES =			\
 test/lisp-cp/test_cp_serdes.c		\
 vnet/lisp-cp/lisp_msg_serdes.c			\
 vnet/lisp-cp/lisp_types.c			\
 vnet/lisp-cp/packets.c				\
 vnet/ip/ip_checksum.c

test_lisp_types_SOURCES =			\
 test/lisp-cp/test_lisp_types.c		\
 vnet/lisp-cp/lisp_types.c

test_cp_serdes_CPPFLAGS = $(AM_CPPFLAGS) -DCLIB_DEBUG
test_lisp_types_CPPFLAGS = $(AM_CPPFLAGS) -DCLIB_DEBUG

test_cp_serdes_LDADD = libvnet.la $(LDS)
test_lisp_types_LDADD = libvnet.la $(LDS)

test_cp_serdes_LDFLAGS = -static
test_lisp_types_LDFLAGS = -static
endif

########################################
# Tunnel protocol: lisp-gpe
########################################

libvnet_la_SOURCES +=				\
 vnet/lisp-gpe/lisp_gpe.c			\
 vnet/lisp-gpe/lisp_gpe_sub_interface.c         \
 vnet/lisp-gpe/lisp_gpe_adjacency.c             \
 vnet/lisp-gpe/lisp_gpe_tunnel.c                \
 vnet/lisp-gpe/lisp_gpe_fwd_entry.c		\
 vnet/lisp-gpe/lisp_gpe_tenant.c		\
 vnet/lisp-gpe/interface.c			\
 vnet/lisp-gpe/decap.c				

nobase_include_HEADERS +=			\
 vnet/lisp-gpe/lisp_gpe.h			\
 vnet/lisp-gpe/lisp_gpe_fwd_entry.h		\
 vnet/lisp-gpe/lisp_gpe_tenant.h		\
 vnet/lisp-gpe/lisp_gpe_packet.h		\
 vnet/lisp-gpe/lisp_gpe_error.def		

if ENABLE_TESTS
TESTS += test_test

test_test_SOURCES = test/lisp-gpe/test.c

test_test_CPPFLAGS = $(AM_CPPFLAGS) -DCLIB_DEBUG

test_test_LDADD = $(LIBOBJS)

noinst_PROGRAMS += $(TESTS)
check_PROGRAMS = $(TESTS)
endif

########################################
# DHCP client
########################################
libvnet_la_SOURCES +=				\
 vnet/dhcp/client.c				\
 vnet/dhcp/client.h	

nobase_include_HEADERS +=			\
 vnet/dhcp/client.h	

########################################
# DHCP proxy
########################################
libvnet_la_SOURCES +=				\
 vnet/dhcp/proxy_node.c				\
 vnet/dhcp/proxy.h
 
nobase_include_HEADERS +=			\
 vnet/dhcp/packet.h				\
 vnet/dhcp/proxy.h				\
 vnet/dhcp/proxy_error.def

########################################
# ipv6 segment routing
########################################

if WITH_IPV6SR
libvnet_la_SOURCES +=				\
 vnet/sr/sr.c					\
 vnet/sr/sr_replicate.c
endif
 
nobase_include_HEADERS +=			\
 vnet/sr/sr_packet.h				\
 vnet/sr/sr_error.def				\
 vnet/sr/sr.h

########################################
# DHCPv6 proxy
########################################
libvnet_la_SOURCES +=				\
 vnet/dhcpv6/proxy_node.c
 
nobase_include_HEADERS +=			\
 vnet/dhcpv6/packet.h				\
 vnet/dhcpv6/proxy.h				\
 vnet/dhcpv6/proxy_error.def

########################################
# IPFIX / netflow v10 
########################################
libvnet_la_SOURCES +=				\
 vnet/flow/flow_report.c

nobase_include_HEADERS +=			\
 vnet/flow/flow_report.h			\
 vnet/flow/ipfix_info_elements.h		\
 vnet/flow/ipfix_packet.h

########################################
# IPFIX classify code
########################################

libvnet_la_SOURCES +=				\
  vnet/flow/flow_report_classify.c

nobase_include_HEADERS +=			\
  vnet/flow/flow_report_classify.h

########################################
# lawful intercept
########################################

libvnet_la_SOURCES +=				\
  vnet/lawful-intercept/lawful_intercept.c	\
  vnet/lawful-intercept/node.c

nobase_include_HEADERS += 			\
  vnet/lawful-intercept/lawful_intercept.h

########################################
# SPAN (port mirroring)
########################################

libvnet_la_SOURCES +=				\
  vnet/span/span_api.c  \
  vnet/span/span.c	    \
  vnet/span/node.c

nobase_include_HEADERS += 			\
  vnet/span/span.api.h  \
  vnet/span/span.h

########################################
# Packet generator
########################################

libvnet_la_SOURCES +=				\
  vnet/pg/cli.c					\
  vnet/pg/edit.c				\
  vnet/pg/init.c				\
  vnet/pg/input.c				\
  vnet/pg/output.c				\
  vnet/pg/stream.c

nobase_include_HEADERS +=			\
  vnet/pg/pg.h					\
  vnet/pg/edit.h

########################################
# DPDK
########################################
if WITH_DPDK
libvnet_la_SOURCES +=				\
  vnet/devices/dpdk/dpdk_priv.h		\
  vnet/devices/dpdk/device.c		\
  vnet/devices/dpdk/format.c		\
  vnet/devices/dpdk/init.c			\
  vnet/devices/dpdk/node.c			\
  vnet/devices/dpdk/hqos.c			\
  vnet/devices/dpdk/cli.c

nobase_include_HEADERS +=			\
  vnet/devices/dpdk/dpdk.h
else
libvnet_la_SOURCES +=				\
  vnet/devices/nic/ixge.c                       \
  vnet/devices/nic/ixge.h                       \
  vnet/devices/nic/sfp.c                        \
  vnet/devices/nic/sfp.h
endif

########################################
# virtio
########################################

libvnet_la_SOURCES +=       \
  vnet/devices/virtio/vhost-user.c

nobase_include_HEADERS +=     \
  vnet/devices/virtio/vhost-user.h

########################################
# ssvm ethernet
########################################
libvnet_la_SOURCES +=				\
  vnet/devices/ssvm/ssvm_eth.c			\
  vnet/devices/ssvm/node.c

nobase_include_HEADERS +=			\
  vnet/devices/ssvm/ssvm_eth.h

########################################
# Linux packet interface
########################################

libvnet_la_SOURCES +=				\
  vnet/devices/af_packet/af_packet.c		\
  vnet/devices/af_packet/device.c		\
  vnet/devices/af_packet/node.c			\
  vnet/devices/af_packet/cli.c

nobase_include_HEADERS +=			\
  vnet/devices/af_packet/af_packet.h

########################################
# NETMAP interface
########################################

libvnet_la_SOURCES +=				\
  vnet/devices/netmap/netmap.c			\
  vnet/devices/netmap/device.c			\
  vnet/devices/netmap/node.c			\
  vnet/devices/netmap/cli.c

nobase_include_HEADERS +=			\
  vnet/devices/netmap/netmap.h


########################################
# Driver feature graph arc support
########################################

libvnet_la_SOURCES +=				\
  vnet/feature/feature.c			\
  vnet/feature/registration.c

nobase_include_HEADERS +=			\
  vnet/feature/feature.h

########################################
# Unix kernel related
########################################

# FIXME: vnet/unix/hgshm.c 

libvnet_la_SOURCES +=				\
  vnet/unix/gdb_funcs.c				\
  vnet/unix/pcap.c				\
  vnet/unix/tap_api.c				\
  vnet/unix/tapcli.c				\
  vnet/unix/tuntap.c

nobase_include_HEADERS +=			\
  vnet/unix/pcap.h				\
  vnet/unix/tuntap.h				\
  vnet/unix/tap.api.h				\
  vnet/unix/tapcli.h

########################################
# FIB
########################################

libvnet_la_SOURCES +=				\
  vnet/fib/fib.c                                \
  vnet/fib/fib_test.c                           \
  vnet/fib/ip4_fib.c                            \
  vnet/fib/ip6_fib.c                            \
  vnet/fib/mpls_fib.c                           \
  vnet/fib/fib_table.c                          \
  vnet/fib/fib_walk.c                           \
  vnet/fib/fib_types.c                          \
  vnet/fib/fib_node.c                           \
  vnet/fib/fib_node_list.c                      \
  vnet/fib/fib_entry.c                          \
  vnet/fib/fib_entry_src.c                      \
  vnet/fib/fib_entry_src_rr.c                   \
  vnet/fib/fib_entry_src_interface.c            \
  vnet/fib/fib_entry_src_default_route.c        \
  vnet/fib/fib_entry_src_special.c              \
  vnet/fib/fib_entry_src_api.c                  \
  vnet/fib/fib_entry_src_adj.c                  \
  vnet/fib/fib_entry_src_mpls.c                 \
  vnet/fib/fib_entry_src_lisp.c                 \
  vnet/fib/fib_entry_cover.c                    \
  vnet/fib/fib_entry_delegate.c                 \
  vnet/fib/fib_path_list.c                      \
  vnet/fib/fib_path.c				\
  vnet/fib/fib_path_ext.c			\
  vnet/fib/fib_urpf_list.c			\
  vnet/fib/fib_attached_export.c

nobase_include_HEADERS +=			\
  vnet/fib/fib.h				\
  vnet/fib/fib_api.h				\
  vnet/fib/ip4_fib.h				\
  vnet/fib/ip6_fib.h				\
  vnet/fib/fib_types.h				\
  vnet/fib/fib_table.h				\
  vnet/fib/fib_node.h				\
  vnet/fib/fib_node_list.h			\
  vnet/fib/fib_entry.h				\
  vnet/fib/fib_entry_delegate.h

########################################
# ADJ
########################################

libvnet_la_SOURCES +=				\
  vnet/adj/adj_nbr.c				\
  vnet/adj/adj_rewrite.c			\
  vnet/adj/adj_glean.c   			\
  vnet/adj/adj_midchain.c   			\
  vnet/adj/adj_l2.c      			\
  vnet/adj/adj.c                            

nobase_include_HEADERS +=			\
  vnet/adj/adj.h				\
  vnet/adj/adj_types.h				\
  vnet/adj/adj_rewrite.h			\
  vnet/adj/adj_glean.h  			\
  vnet/adj/adj_nbr.h				

########################################
# Data-Plane Objects
########################################

libvnet_la_SOURCES +=				\
  vnet/dpo/dpo.c                                \
  vnet/dpo/drop_dpo.c                           \
  vnet/dpo/ip_null_dpo.c                        \
  vnet/dpo/punt_dpo.c                           \
  vnet/dpo/receive_dpo.c                        \
  vnet/dpo/load_balance.c			\
  vnet/dpo/load_balance_map.c			\
  vnet/dpo/lookup_dpo.c   			\
  vnet/dpo/classify_dpo.c   			\
  vnet/dpo/mpls_label_dpo.c

nobase_include_HEADERS +=			\
  vnet/dpo/load_balance.h                       \
  vnet/dpo/drop_dpo.h                           \
  vnet/dpo/lookup_dpo.h                         \
  vnet/dpo/punt_dpo.h                           \
  vnet/dpo/classify_dpo.h                       \
  vnet/dpo/receive_dpo.h                        \
  vnet/dpo/ip_null_dpo.h                        \
  vnet/dpo/dpo.h

########################################
# Plugin client library
########################################

libvnetplugin_la_SOURCES +=                    \
  vnet/plugin/p1.c

nobase_include_HEADERS +=                      \
  vnet/plugin/plugin.h

lib_LTLIBRARIES = libvnet.la libvnetplugin.la

pcap2pg_SOURCES = 				\
  vnet/unix/pcap2pg.c				\
  vnet/unix/pcap.h

pcap2pg_LDFLAGS = -static
pcap2pg_LDADD = libvnet.la -l:libvppinfra.a -lpthread -lm -ldl

noinst_PROGRAMS += pcap2pg

# Set the suffix list
SUFFIXES = .api.h .api .api.json

# install the API definition, so we can produce java bindings, etc.

apidir = $(prefix)/vnet

api_DATA =					\
 vnet/interface.api.json			\
 vnet/ip/ip.api.json				\
 vnet/l2/l2.api.json				\
 vnet/map/map.api.json				\
 vnet/span/span.api.json			\
 vnet/unix/tap.api.json

# The actual %.api.h rule is in .../build-data/packages/suffix-rules.mk
# and requires a symbolic link at the top of the vnet source tree

include $(top_srcdir)/suffix-rules.mk
