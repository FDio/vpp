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

AM_CFLAGS = -Wall @DPDK@ @VIRL@ @IPSEC@ @VCGN@ @IPV6SR@

libvnet_la_SOURCES =
libvnetplugin_la_SOURCES =
nobase_include_HEADERS =
noinst_PROGRAMS =
TESTS =

########################################
# Generic stuff
########################################
libvnet_la_SOURCES +=					\
  vnet/config.c						\
  vnet/interface.c					\
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
  vnet/global_funcs.h				\
  vnet/interface.h				\
  vnet/interface_funcs.h			\
  vnet/l3_types.h				\
  vnet/pipeline.h				\
  vnet/replication.h				\
  vnet/rewrite.h				\
  vnet/vnet.h

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
  vnet/policer/fix_types.h			\
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
 vnet/l2/l2_bd.c				\
 vnet/l2/l2_bvi.c				\
 vnet/l2/l2_classify.c				\
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
 vnet/l2/l2_classify.h

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
# Layer 2/3 "classify"
########################################
libvnet_la_SOURCES +=				\
  vnet/classify/vnet_classify.c			\
  vnet/classify/ip_classify.c			\
  vnet/classify/input_acl.c			\
  vnet/classify/vnet_classify.h

nobase_include_HEADERS +=			\
  vnet/classify/vnet_classify.h	                \
  vnet/classify/input_acl.h

########################################
# Layer 3 protocols go here
########################################

########################################
# Layer 3 protocol: IP v4/v6
########################################
libvnet_la_SOURCES +=				\
 vnet/ip/adj_alloc.c				\
 vnet/ip/format.c				\
 vnet/ip/icmp4.c				\
 vnet/ip/icmp6.c				\
 vnet/ip/ip46_cli.c				\
 vnet/ip/ip4_format.c				\
 vnet/ip/ip4_forward.c				\
 vnet/ip/ip4_hop_by_hop.c			\
 vnet/ip/ip6_ioam_flow_report.c                 \
 vnet/ip/ip4_input.c				\
 vnet/ip/ip4_mtrie.c				\
 vnet/ip/ip4_pg.c				\
 vnet/ip/ip4_source_check.c			\
 vnet/ip/ip6_format.c				\
 vnet/ip/ip6_forward.c				\
 vnet/ip/ip6_hop_by_hop.c			\
 vnet/ip/ip6_input.c				\
 vnet/ip/ip6_neighbor.c				\
 vnet/ip/ip6_pg.c				\
 vnet/ip/ip_checksum.c				\
 vnet/ip/ip.h					\
 vnet/ip/ip_init.c				\
 vnet/ip/lookup.c				\
 vnet/ip/udp_format.c				\
 vnet/ip/udp_init.c				\
 vnet/ip/udp_local.c				\
 vnet/ip/udp_pg.c                               \
 vnet/ip/ip_input_acl.c                         \
 vnet/ip/ip_frag.c

nobase_include_HEADERS +=			\
 vnet/ip/adj_alloc.h				\
 vnet/ip/format.h				\
 vnet/ip/icmp46_packet.h			\
 vnet/ip/icmp4.h				\
 vnet/ip/icmp6.h				\
 vnet/ip/igmp_packet.h				\
 vnet/ip/ip.h					\
 vnet/ip/ip4.h					\
 vnet/ip/ip4_mtrie.h				\
 vnet/ip/ip4_error.h				\
 vnet/ip/ip4_packet.h				\
 vnet/ip/ip6.h					\
 vnet/ip/ip6_error.h				\
 vnet/ip/ip6_hop_by_hop.h			\
 vnet/ip/ip6_hop_by_hop_packet.h		\
 vnet/ip/ip6_ioam_flow_report.h                 \
 vnet/ip/ip6_packet.h				\
 vnet/ip/lookup.h				\
 vnet/ip/ip_packet.h				\
 vnet/ip/ports.def				\
 vnet/ip/protocols.def				\
 vnet/ip/tcp_packet.h				\
 vnet/ip/udp.h					\
 vnet/ip/udp_error.def				\
 vnet/ip/udp_packet.h

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
endif 

libvnet_la_SOURCES +=       			\
 vnet/ipsec/ipsec_output.c

nobase_include_HEADERS +=     		        \
 vnet/ipsec/ipsec.h                             \
 vnet/ipsec/esp.h				\
 vnet/ipsec/ikev2.h                             \
 vnet/ipsec/ikev2_priv.h

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
libvnet_la_SOURCES +=                           \
 vnet/map/map.c                                 \
 vnet/map/ip4_map.c                             \
 vnet/map/ip6_map.c                             \
 vnet/map/sixrd.c                               \
 vnet/map/ip4_sixrd.c                           \
 vnet/map/ip6_sixrd.c                           \
 vnet/map/ip4_map_t.c                           \
 vnet/map/ip6_map_t.c

nobase_include_HEADERS +=                       \
 vnet/map/map.h                                 \
 vnet/map/sixrd.h

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
 vnet/mpls-gre/mpls.c				\
 vnet/mpls-gre/node.c				\
 vnet/mpls-gre/interface.c			\
 vnet/mpls-gre/policy_encap.c			\
 vnet/mpls-gre/pg.c
 
nobase_include_HEADERS +=			\
 vnet/mpls-gre/mpls.h				\
 vnet/mpls-gre/packet.h				\
 vnet/mpls-gre/error.def


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
# LISP control plane: lisp-cp
########################################

libvnet_la_SOURCES +=				\
 vnet/lisp-cp/lisp_types.c			\
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
LDS = -lvppinfra -l:libvlib.a -l:libdpdk.a -l:libvlibmemory.a \
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
 vnet/lisp-gpe/interface.c			\
 vnet/lisp-gpe/ip_forward.c			\
 vnet/lisp-gpe/decap.c				

nobase_include_HEADERS +=			\
 vnet/lisp-gpe/lisp_gpe.h			\
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
# CGN
#########################################

if WITH_VCGN
libvnet_la_SOURCES +=						\
 vnet/vcgn/cnat_bulk_port.c					\
 vnet/vcgn/cnat_config.c					\
 vnet/vcgn/cnat_db_scanner.c					\
 vnet/vcgn/cnat_db_v2.c						\
 vnet/vcgn/cnat_debug_msg_handler.c				\
 vnet/vcgn/cnat_cli_handler.c					\
 vnet/vcgn/cnat_global.c					\
 vnet/vcgn/cnat_ipv4_udp_inside_input.c				\
 vnet/vcgn/cnat_ipv4_udp_inside_input_exceptions.c		\
 vnet/vcgn/cnat_ipv4_udp_outside_input.c			\
 vnet/vcgn/cnat_ipv4_tcp_inside_input.c				\
 vnet/vcgn/cnat_ipv4_tcp_inside_input_exceptions.c		\
 vnet/vcgn/cnat_ipv4_tcp_outside_input.c			\
 vnet/vcgn/cnat_ipv4_icmp_query_inside_input.c			\
 vnet/vcgn/cnat_ipv4_icmp_query_inside_input_exception.c	\
 vnet/vcgn/cnat_ipv4_icmp_query_outside_input.c			\
 vnet/vcgn/cnat_ipv4_icmp_error_inside_input.c			\
 vnet/vcgn/cnat_ipv4_icmp_error_outside_input.c			\
 vnet/vcgn/cnat_logging.c					\
 vnet/vcgn/cnat_ports.c						\
 vnet/vcgn/cnat_util.c						\
 vnet/vcgn/cnat_show.c						\
 vnet/vcgn/cnat_syslog.c					\
 vnet/vcgn/cnat_v4_functions.c					\
 vnet/vcgn/index_list.c						\
 vnet/vcgn/spp_platform_trace_log.c				\
 vnet/vcgn/vcgn_classify.c
endif

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
# IPFIX sample code
########################################

libvnet_la_SOURCES +=				\
  vnet/flow/flow_report_sample.c

nobase_include_HEADERS +=			\
  vnet/flow/flow_report_sample.h

########################################
# lawful intercept
########################################

libvnet_la_SOURCES +=				\
  vnet/lawful-intercept/lawful_intercept.c	\
  vnet/lawful-intercept/node.c

nobase_include_HEADERS += 			\
  vnet/dpdk_replication.h			\
  vnet/lawful-intercept/lawful_intercept.h

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
# Intel DPDK
########################################
if WITH_DPDK
libvnet_la_SOURCES +=				\
  vnet/devices/dpdk/dpdk_priv.h		\
  vnet/devices/dpdk/device.c		\
  vnet/devices/dpdk/format.c		\
  vnet/devices/dpdk/init.c			\
  vnet/devices/dpdk/node.c			\
  vnet/devices/dpdk/threads.c       \
  vnet/devices/dpdk/vhost_user.c    \
  vnet/devices/dpdk/cli.c

nobase_include_HEADERS +=			\
  vnet/devices/dpdk/dpdk.h			\
  vnet/devices/dpdk/threads.h
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

if WITH_DPDK
libvnet_la_SOURCES +=       \
  vnet/devices/virtio/vhost-user.c

nobase_include_HEADERS +=     \
  vnet/devices/virtio/vhost-user.h
endif WITH_DPDK

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
# Unix kernel related
########################################

# FIXME: vnet/unix/hgshm.c 

libvnet_la_SOURCES +=				\
  vnet/unix/gdb_funcs.c				\
  vnet/unix/pcap.c				\
  vnet/unix/tapcli.c				\
  vnet/unix/tuntap.c

nobase_include_HEADERS +=			\
  vnet/unix/pcap.h				\
  vnet/unix/tuntap.h				\
  vnet/unix/tapcli.h

########################################
# Plugin client library
########################################

libvnetplugin_la_SOURCES +=                    \
  vnet/plugin/p1.c

nobase_include_HEADERS +=                      \
  vnet/plugin/plugin.h

########################################
# Service Chain verification util
########################################
libvnet_la_SOURCES +=       \
 vnet/lib-scv/scv_util.c

nobase_include_HEADERS +=                       \
 vnet/lib-scv/scv_util.h                        \
 vnet/lib-scv/math64.h

lib_LTLIBRARIES = libvnet.la libvnetplugin.la

dpdk_libs = 

if WITH_DPDK
dpdk_libs += -l:libdpdk.a
endif

pcap2pg_SOURCES = 				\
  vnet/unix/pcap2pg.c				\
  vnet/unix/pcap.h

pcap2pg_LDFLAGS = -static
pcap2pg_LDADD = libvnet.la -l:libvppinfra.a -lpthread -lm -ldl

noinst_PROGRAMS += pcap2pg


