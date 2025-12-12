/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/format.h: ip 4 and/or 6 formatting */

#ifndef included_ip_format_h
#define included_ip_format_h

/* IP4 or IP6. */

format_function_t format_ip_protocol;
unformat_function_t unformat_ip_protocol;

format_function_t format_tcp_udp_port;
unformat_function_t unformat_tcp_udp_port;

typedef enum format_ip_adjacency_flags_t_
{
  FORMAT_IP_ADJACENCY_NONE,
  FORMAT_IP_ADJACENCY_BRIEF = FORMAT_IP_ADJACENCY_NONE,
  FORMAT_IP_ADJACENCY_DETAIL = (1 << 0),
} format_ip_adjacency_flags_t;

format_function_t format_ip_adjacency;
format_function_t format_ip_adjacency_packet_data;

/* unformat_ip46_address expects arguments (ip46_address_t *, ip46_type_t)
 * The type argument is used to enforce a particular IP version. */
unformat_function_t unformat_ip46_address;

/* IP4 */

/* Parse an IP4 address %d.%d.%d.%d. */
unformat_function_t unformat_ip4_address;
/* Parse an IP4 address and mask %d.%d.%d.%d/%d.%d.%d.%d */
unformat_function_t unformat_ip4_address_and_mask;

/* Format an IP4 address. */
format_function_t format_ip4_address;
format_function_t format_ip4_address_and_length;
format_function_t format_ip4_address_and_mask;

/* Parse an IP4 header. */
unformat_function_t unformat_ip4_header;

/* Format an IP4 header. */
format_function_t format_ip4_header;

/* Parse an IP packet matching pattern. */
unformat_function_t unformat_ip4_match;

unformat_function_t unformat_pg_ip4_header;

/* IP6 */
unformat_function_t unformat_ip6_address;
unformat_function_t unformat_ip6_address_and_mask;
format_function_t format_ip6_address;
format_function_t format_ip6_address_and_length;
format_function_t format_ip6_address_and_mask;
unformat_function_t unformat_ip6_header;
format_function_t format_ip6_header;
format_function_t format_ip6_frag_hdr;
unformat_function_t unformat_pg_ip6_header;

/* Format a TCP/UDP headers. */
format_function_t format_tcp_header, format_udp_header;

unformat_function_t unformat_pg_tcp_header, unformat_pg_udp_header;

#endif /* included_ip_format_h */
