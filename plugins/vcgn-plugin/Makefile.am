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

AM_CFLAGS = -Wall

########################################
# Virtual Carrier Grade NAT
########################################

libvcgn_plugin_la_SOURCES =					\
	vcgn/cnat_bulk_port.c					\
	vcgn/cnat_config.c					\
	vcgn/cnat_db_scanner.c					\
	vcgn/cnat_db_v2.c					\
	vcgn/cnat_debug_msg_handler.c				\
	vcgn/cnat_cli_handler.c					\
	vcgn/cnat_global.c					\
	vcgn/cnat_ipv4_udp_inside_input.c			\
	vcgn/cnat_ipv4_udp_inside_input_exceptions.c		\
	vcgn/cnat_ipv4_udp_outside_input.c			\
	vcgn/cnat_ipv4_tcp_inside_input.c			\
	vcgn/cnat_ipv4_tcp_inside_input_exceptions.c		\
	vcgn/cnat_ipv4_tcp_outside_input.c			\
	vcgn/cnat_ipv4_icmp_query_inside_input.c		\
	vcgn/cnat_ipv4_icmp_query_inside_input_exception.c	\
	vcgn/cnat_ipv4_icmp_query_outside_input.c		\
	vcgn/cnat_ipv4_icmp_error_inside_input.c		\
	vcgn/cnat_ipv4_icmp_error_outside_input.c		\
	vcgn/cnat_logging.c					\
	vcgn/cnat_ports.c					\
	vcgn/cnat_util.c					\
	vcgn/cnat_show.c					\
	vcgn/cnat_syslog.c					\
	vcgn/cnat_v4_functions.c				\
	vcgn/index_list.c					\
	vcgn/spp_platform_trace_log.c				\
	vcgn/vcgn_classify.c

nobase_include_HEADERS =			\
	vcgn/cgn_bitmap.h			\
	vcgn/cgse_defs.h			\
	vcgn/cnat_bulk_port_defs.h		\
	vcgn/cnat_bulk_port.h			\
	vcgn/cnat_cli.h				\
	vcgn/cnat_common_api.h			\
	vcgn/cnat_config_api.h			\
	vcgn/cnat_config.h			\
	vcgn/cnat_db.h				\
	vcgn/cnat_global.h			\
	vcgn/cnat_ipv4_icmp.h			\
	vcgn/cnat_ipv4_udp.h			\
	vcgn/cnat_log_api.h			\
	vcgn/cnat_log_common.h			\
	vcgn/cnat_logging.h			\
	vcgn/cnat_pcp_server.h			\
	vcgn/cnat_ports.h			\
	vcgn/cnat_show_api.h			\
	vcgn/cnat_show_response.h		\
	vcgn/cnat_syslog.h			\
	vcgn/cnat_v4_ftp_alg.h			\
	vcgn/cnat_v4_functions.h		\
	vcgn/cnat_v4_pptp_alg.h			\
	vcgn/cnat_va_db.h			\
	vcgn/dslite_db.h			\
	vcgn/dslite_defs.h			\
	vcgn/index_list.h			\
	vcgn/nat64_db.h				\
	vcgn/nat64_defs.h			\
	vcgn/nat64_tcp_sm.h			\
	vcgn/platform_common.h			\
	vcgn/platform_common_override.h		\
	vcgn/spp_ctx.h				\
	vcgn/spp_platform_trace_log.h		\
	vcgn/spp_timers.h			\
	vcgn/tcp_header_definitions.h		\
	vcgn/vcgn_db.h

libvcgn_plugin_la_LDFLAGS = -module

vpppluginsdir = ${libdir}/vpp_plugins

vppplugins_LTLIBRARIES = libvcgn_plugin.la
