# Copyright (c) 2017 Cisco and/or its affiliates.
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

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_LIBTOOLFLAGS = --quiet

AM_CXXFLAGS = -Wall -std=gnu++11 -I${top_srcdir} -I${top_builddir}/vpp-api/vapi/ -I$(top_srcdir)/vpp-api/ -I${libdir}/../include
AM_LDFLAGS = -shared -no-undefined

bin_PROGRAMS =
noinst_LTLIBRARIES =
CLEANDIRS =

lib_LTLIBRARIES = libvom.la

libvom_la_DEPENDENCIES =
libvom_la_LIBADD = 					\
	$(top_builddir)/vpp-api/vapi/libvapiclient.la	\
	-lpthread					\
	-lboost_thread					\
	$(BOOST_SYSTEM_LIB) 				\
	$(BOOST_FILESYSTEM_LIB) 			\
	$(BOOST_ASIO_LIB) 				\
	-lm -lrt

libvom_la_SOURCES = 			\
	types.cpp			\
	acl_binding_cmds.cpp		\
	acl_binding.cpp			\
	acl_l2_rule.cpp			\
	acl_l3_rule.cpp			\
	acl_list_cmds.cpp		\
	acl_list.cpp			\
	acl_types.cpp			\
	arp_proxy_binding_cmds.cpp 	\
	arp_proxy_binding.cpp		\
	arp_proxy_config_cmds.cpp	\
	arp_proxy_config.cpp		\
	bridge_domain_cmds.cpp		\
	bridge_domain.cpp		\
	bridge_domain_arp_entry.cpp	\
	bridge_domain_arp_entry_cmds.cpp \
	bridge_domain_entry_cmds.cpp	\
	bridge_domain_entry.cpp		\
	client_db.cpp			\
	cmd.cpp				\
	connection.cpp			\
	dhcp_config_cmds.cpp		\
	dhcp_config.cpp			\
	hw_cmds.cpp			\
	hw.cpp				\
	inspect.cpp			\
	interface_cmds.cpp		\
	interface.cpp			\
	interface_factory.cpp		\
	interface_ip6_nd_cmds.cpp	\
	interface_span_cmds.cpp		\
	interface_span.cpp		\
	interface_types.cpp		\
	ip_unnumbered_cmds.cpp		\
	ip_unnumbered.cpp		\
	l2_binding_cmds.cpp		\
	l2_binding.cpp			\
	l3_binding_cmds.cpp		\
	l3_binding.cpp			\
	lldp_binding_cmds.cpp		\
	lldp_binding.cpp		\
	lldp_global_cmds.cpp		\
	lldp_global.cpp			\
	logger.cpp			\
	nat_static.cpp			\
	nat_static_cmds.cpp		\
	nat_binding.cpp			\
	nat_binding_cmds.cpp		\
	neighbour.cpp			\
	neighbour_cmds.cpp		\
	object_base.cpp			\
	om.cpp				\
	prefix.cpp			\
	ra_config.cpp			\
	ra_prefix.cpp			\
	route.cpp			\
	route_cmds.cpp			\
	route_domain.cpp		\
	route_domain_cmds.cpp		\
	sub_interface_cmds.cpp		\
	sub_interface.cpp		\
	tap_interface.cpp		\
	tap_interface_cmds.cpp		\
	vxlan_tunnel_cmds.cpp 		\
	vxlan_tunnel.cpp

vomincludedir = $(includedir)/vom

vominclude_HEADERS =			\
	acl_binding.hpp			\
	acl_l2_rule.hpp			\
	acl_l3_rule.hpp			\
	acl_list.hpp			\
	acl_types.hpp			\
	arp_proxy_binding.hpp		\
	arp_proxy_config.hpp		\
	bridge_domain.hpp		\
	bridge_domain_arp_entry.hpp	\
	bridge_domain_entry.hpp		\
	client_db.hpp			\
	cmd.hpp				\
	connection.hpp			\
	dhcp_config.hpp			\
	dhcp_config_cmds.hpp		\
	dump_cmd.hpp			\
	enum_base.hpp			\
	event_cmd.hpp			\
	hw.hpp				\
	inspect.hpp			\
	interface.hpp			\
	interface_cmds.hpp		\
	interface_ip6_nd.hpp		\
	interface_span.hpp		\
	ip_unnumbered.hpp		\
	l2_binding.hpp			\
	l3_binding.hpp			\
	lldp_binding.hpp		\
	lldp_global.hpp			\
	logger.hpp			\
	nat_static.hpp			\
	nat_binding.hpp			\
	neighbour.hpp			\
	object_base.hpp			\
	om.hpp				\
	prefix.hpp			\
	ra_config.hpp			\
	ra_prefix.hpp			\
	route.hpp			\
	route_domain.hpp		\
	rpc_cmd.hpp			\
	singular_db.hpp			\
	sub_interface.hpp		\
	tap_interface.hpp		\
	types.hpp			\
	vxlan_tunnel.hpp

# vi:syntax=automake
