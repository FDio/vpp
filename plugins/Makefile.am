# Copyright (c) 2016 Cisco and/or its affiliates.
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

AM_CFLAGS = -Wall -I@TOOLKIT_INCLUDE@


########################################
# SIXRD (RFC5969)
########################################
libsixrd_plugin_la_SOURCES = plugins/sixrd/sixrd.c plugins/sixrd/ip4_sixrd.c plugins/sixrd/ip6_sixrd.c
nobase_include_HEADERS = plugins/sixrd/sixrd.h

libsixrd_plugin_la_LDFLAGS = -module
#BUILT_SOURCES =

lib_LTLIBRARIES = libsixrd_plugin.la

########################################
# iOAM Proof of Transit
########################################

ioam_pot_plugin_la_SOURCES = plugins/ioam/lib-pot/pot_util.c plugins/ioam/encap/ip6_ioam_pot.c \
	plugins/ioam/lib-pot/pot_util.h plugins/ioam/lib-pot/math64.h plugins/ioam/lib-pot/pot_api.c
ioam_pot_plugin_la_LDFLAGS = -module

BUILT_SOURCES = plugins/ioam/lib-pot/pot.api.h
SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \
	| vppapigen --input - --output $@ --show-name $@

nobase_include_HEADERS +=                       \
  plugins/ioam/lib-pot/pot_all_api_h.h  	\
  plugins/ioam/lib-pot/pot_msg_enum.h		\
  plugins/ioam/lib-pot/pot.api.h                \
  plugins/ioam/lib-pot/pot_util.h               \
  plugins/ioam/lib-pot/math64.h

ioam_pot_test_plugin_la_SOURCES = plugins/ioam/lib-pot/pot_test.c plugins/ioam/lib-pot/pot_plugin.api.h
ioam_pot_test_plugin_la_LDFLAGS = -module

lib_LTLIBRARIES += ioam_pot_plugin.la ioam_pot_test_plugin.la

########################################
# Virtual Carrier Grade NAT
########################################

libvcgn_plugin_la_SOURCES =						\
	plugins/vcgn/cnat_bulk_port.c					\
	plugins/vcgn/cnat_config.c					\
	plugins/vcgn/cnat_db_scanner.c					\
	plugins/vcgn/cnat_db_v2.c						\
	plugins/vcgn/cnat_debug_msg_handler.c				\
	plugins/vcgn/cnat_cli_handler.c					\
	plugins/vcgn/cnat_global.c					\
	plugins/vcgn/cnat_ipv4_udp_inside_input.c				\
	plugins/vcgn/cnat_ipv4_udp_inside_input_exceptions.c		\
	plugins/vcgn/cnat_ipv4_udp_outside_input.c			\
	plugins/vcgn/cnat_ipv4_tcp_inside_input.c				\
	plugins/vcgn/cnat_ipv4_tcp_inside_input_exceptions.c		\
	plugins/vcgn/cnat_ipv4_tcp_outside_input.c			\
	plugins/vcgn/cnat_ipv4_icmp_query_inside_input.c			\
	plugins/vcgn/cnat_ipv4_icmp_query_inside_input_exception.c	\
	plugins/vcgn/cnat_ipv4_icmp_query_outside_input.c			\
	plugins/vcgn/cnat_ipv4_icmp_error_inside_input.c			\
	plugins/vcgn/cnat_ipv4_icmp_error_outside_input.c			\
	plugins/vcgn/cnat_logging.c					\
	plugins/vcgn/cnat_ports.c						\
	plugins/vcgn/cnat_util.c						\
	plugins/vcgn/cnat_show.c						\
	plugins/vcgn/cnat_syslog.c					\
	plugins/vcgn/cnat_v4_functions.c					\
	plugins/vcgn/index_list.c						\
	plugins/vcgn/spp_platform_trace_log.c				\
	plugins/vcgn/vcgn_classify.c

nobase_include_HEADERS += plugins/vcgn/cgn_bitmap.h	\
    plugins/vcgn/cgse_defs.h	\
    plugins/vcgn/cnat_bulk_port_defs.h	\
    plugins/vcgn/cnat_bulk_port.h	\
    plugins/vcgn/cnat_cli.h	\
    plugins/vcgn/cnat_common_api.h	\
    plugins/vcgn/cnat_config_api.h	\
    plugins/vcgn/cnat_config.h	\
    plugins/vcgn/cnat_db.h	\
    plugins/vcgn/cnat_global.h	\
    plugins/vcgn/cnat_ipv4_icmp.h	\
    plugins/vcgn/cnat_ipv4_udp.h	\
    plugins/vcgn/cnat_log_api.h	\
    plugins/vcgn/cnat_log_common.h	\
    plugins/vcgn/cnat_logging.h	\
    plugins/vcgn/cnat_pcp_server.h	\
    plugins/vcgn/cnat_ports.h	\
    plugins/vcgn/cnat_show_api.h	\
    plugins/vcgn/cnat_show_response.h	\
    plugins/vcgn/cnat_syslog.h	\
    plugins/vcgn/cnat_v4_ftp_alg.h	\
    plugins/vcgn/cnat_v4_functions.h	\
    plugins/vcgn/cnat_v4_pptp_alg.h	\
    plugins/vcgn/cnat_va_db.h	\
    plugins/vcgn/dslite_db.h	\
    plugins/vcgn/dslite_defs.h	\
    plugins/vcgn/index_list.h	\
    plugins/vcgn/nat64_db.h	\
    plugins/vcgn/nat64_defs.h	\
    plugins/vcgn/nat64_tcp_sm.h	\
    plugins/vcgn/platform_common.h	\
    plugins/vcgn/platform_common_override.h	\
    plugins/vcgn/spp_ctx.h	\
    plugins/vcgn/spp_platform_trace_log.h	\
    plugins/vcgn/spp_timers.h	\
    plugins/vcgn/tcp_header_definitions.h	\
    plugins/vcgn/vcgn_db.h

libvcgn_plugin_la_LDFLAGS = -module

lib_LTLIBRARIES += libvcgn_plugin.la

if WITH_PLUGIN_TOOLKIT
install-data-hook:
	mkdir /usr/lib/vpp_plugins || true
	mkdir /usr/lib/vpp_api_test_plugins || true
	cp $(prefix)/lib/libsixrd_plugin.so.*.*.* /usr/lib/vpp_plugins
	cp $(prefix)/lib/libvcgn_plugin.so.*.*.* /usr/lib/vpp_plugins
	cp $(prefix)/lib/ioam_pot_plugin.so.*.*.* /usr/lib/vpp_plugins
	cp $(prefix)/lib/ioam_pot_test_plugin.so.*.*.* \
		/usr/lib/vpp_api_test_plugins
endif

