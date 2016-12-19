/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * icmp46_packet.h: ip4/ip6 icmp packet format
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vnet_icmp46_packet_h
#define included_vnet_icmp46_packet_h

#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip6_packet.h>

#define foreach_icmp4_type			\
  _ (0, echo_reply)				\
  _ (3, destination_unreachable)		\
  _ (4, source_quench)				\
  _ (5, redirect)				\
  _ (6, alternate_host_address)			\
  _ (8, echo_request)				\
  _ (9, router_advertisement)			\
  _ (10, router_solicitation)			\
  _ (11, time_exceeded)				\
  _ (12, parameter_problem)			\
  _ (13, timestamp_request)			\
  _ (14, timestamp_reply)			\
  _ (15, information_request)			\
  _ (16, information_reply)			\
  _ (17, address_mask_request)			\
  _ (18, address_mask_reply)			\
  _ (30, traceroute)				\
  _ (31, datagram_conversion_error)		\
  _ (32, mobile_host_redirect)			\
  _ (33, ip6_where_are_you)			\
  _ (34, ip6_i_am_here)				\
  _ (35, mobile_registration_request)		\
  _ (36, mobile_registration_reply)		\
  _ (37, domain_name_request)			\
  _ (38, domain_name_reply)			\
  _ (39, skip)					\
  _ (40, photuris)

#define icmp_no_code 0

#define foreach_icmp4_code						\
  _ (destination_unreachable, 0, destination_unreachable_net)		\
  _ (destination_unreachable, 1, destination_unreachable_host)		\
  _ (destination_unreachable, 2, protocol_unreachable)			\
  _ (destination_unreachable, 3, port_unreachable)			\
  _ (destination_unreachable, 4, fragmentation_needed_and_dont_fragment_set) \
  _ (destination_unreachable, 5, source_route_failed)			\
  _ (destination_unreachable, 6, destination_network_unknown)		\
  _ (destination_unreachable, 7, destination_host_unknown)		\
  _ (destination_unreachable, 8, source_host_isolated)			\
  _ (destination_unreachable, 9, network_administratively_prohibited)	\
  _ (destination_unreachable, 10, host_administratively_prohibited)	\
  _ (destination_unreachable, 11, network_unreachable_for_type_of_service) \
  _ (destination_unreachable, 12, host_unreachable_for_type_of_service)	\
  _ (destination_unreachable, 13, communication_administratively_prohibited) \
  _ (destination_unreachable, 14, host_precedence_violation)		\
  _ (destination_unreachable, 15, precedence_cutoff_in_effect)		\
  _ (redirect, 0, network_redirect)					\
  _ (redirect, 1, host_redirect)					\
  _ (redirect, 2, type_of_service_and_network_redirect)			\
  _ (redirect, 3, type_of_service_and_host_redirect)			\
  _ (router_advertisement, 0, normal_router_advertisement)		\
  _ (router_advertisement, 16, does_not_route_common_traffic)		\
  _ (time_exceeded, 0, ttl_exceeded_in_transit)				\
  _ (time_exceeded, 1, fragment_reassembly_time_exceeded)		\
  _ (parameter_problem, 0, pointer_indicates_error)			\
  _ (parameter_problem, 1, missing_required_option)			\
  _ (parameter_problem, 2, bad_length)

/* ICMPv6 */
#define foreach_icmp6_type			\
  _ (1, destination_unreachable)		\
  _ (2, packet_too_big)				\
  _ (3, time_exceeded)				\
  _ (4, parameter_problem)			\
  _ (128, echo_request)				\
  _ (129, echo_reply)				\
  _ (130, multicast_listener_request)		\
  _ (131, multicast_listener_report)		\
  _ (132, multicast_listener_done)		\
  _ (133, router_solicitation)			\
  _ (134, router_advertisement)			\
  _ (135, neighbor_solicitation)		\
  _ (136, neighbor_advertisement)		\
  _ (137, redirect)				\
  _ (138, router_renumbering)			\
  _ (139, node_information_request)		\
  _ (140, node_information_response)		\
  _ (141, inverse_neighbor_solicitation)	\
  _ (142, inverse_neighbor_advertisement)	\
  _ (143, multicast_listener_report_v2)		\
  _ (144, home_agent_address_discovery_request)	\
  _ (145, home_agent_address_discovery_reply)	\
  _ (146, mobile_prefix_solicitation)		\
  _ (147, mobile_prefix_advertisement)		\
  _ (148, certification_path_solicitation)	\
  _ (149, certification_path_advertisement)	\
  _ (151, multicast_router_advertisement)	\
  _ (152, multicast_router_solicitation)	\
  _ (153, multicast_router_termination)		\
  _ (154, fmipv6_messages)

#define foreach_icmp6_code						\
  _ (destination_unreachable, 0, no_route_to_destination)		\
  _ (destination_unreachable, 1, destination_administratively_prohibited) \
  _ (destination_unreachable, 2, beyond_scope_of_source_address)	\
  _ (destination_unreachable, 3, address_unreachable)			\
  _ (destination_unreachable, 4, port_unreachable)			\
  _ (destination_unreachable, 5, source_address_failed_policy)		\
  _ (destination_unreachable, 6, reject_route_to_destination)		\
  _ (time_exceeded, 0, ttl_exceeded_in_transit)				\
  _ (time_exceeded, 1, fragment_reassembly_time_exceeded)		\
  _ (parameter_problem, 0, erroneous_header_field)			\
  _ (parameter_problem, 1, unrecognized_next_header)			\
  _ (parameter_problem, 2, unrecognized_option)				\
  _ (router_renumbering, 0, command)					\
  _ (router_renumbering, 1, result)					\
  _ (node_information_request, 0, data_contains_ip6_address)		\
  _ (node_information_request, 1, data_contains_name)			\
  _ (node_information_request, 2, data_contains_ip4_address)		\
  _ (node_information_response, 0, success)				\
  _ (node_information_response, 1, failed)				\
  _ (node_information_response, 2, unknown_request)

typedef enum
{
#define _(n,f) ICMP4_##f = n,
  foreach_icmp4_type
#undef _
} icmp4_type_t;

typedef enum
{
#define _(t,n,f) ICMP4_##t##_##f = n,
  foreach_icmp4_code
#undef _
} icmp4_code_t;

typedef enum
{
#define _(n,f) ICMP6_##f = n,
  foreach_icmp6_type
#undef _
} icmp6_type_t;

typedef enum
{
#define _(t,n,f) ICMP6_##t##_##f = n,
  foreach_icmp6_code
#undef _
} icmp6_code_t;

typedef CLIB_PACKED (struct
		     {
		     u8 type;
		     u8 code;
		     /* IP checksum of icmp header plus data which follows. */
		     u16 checksum;
		     }) icmp46_header_t;

/* ip6 neighbor discovery */
#define foreach_icmp6_neighbor_discovery_option	\
  _ (1, source_link_layer_address)		\
  _ (2, target_link_layer_address)		\
  _ (3, prefix_information)			\
  _ (4, redirected_header)			\
  _ (5, mtu)					\
  _ (6, nbma_shortcut_limit)			\
  _ (7, advertisement_interval)			\
  _ (8, home_agent_information)			\
  _ (9, source_address_list)			\
  _ (10, target_address_list)			\
  _ (11, cryptographically_generated_address)	\
  _ (12, rsa_signature)				\
  _ (13, timestamp)				\
  _ (14, nonce)					\
  _ (15, trust_anchor)				\
  _ (16, certificate)				\
  _ (17, ip_address_and_prefix)			\
  _ (18, new_router_prefix_information)		\
  _ (19, mobile_link_layer_address)		\
  _ (20, neighbor_advertisement_acknowledgment)	\
  _ (23, map)					\
  _ (24, route_information)			\
  _ (25, recursive_dns_server)			\
  _ (26, ra_flags_extension)			\
  _ (27, handover_key_request)			\
  _ (28, handover_key_reply)			\
  _ (29, handover_assist_information)		\
  _ (30, mobile_node_identifier)		\
  _ (31, dns_search_list)			\
  _ (138, card_request)				\
  _ (139, card_reply)

typedef enum icmp6_neighbor_discovery_option_type
{
#define _(n,f) ICMP6_NEIGHBOR_DISCOVERY_OPTION_##f = n,
  foreach_icmp6_neighbor_discovery_option
#undef _
} icmp6_neighbor_discovery_option_type_t;

typedef CLIB_PACKED (struct
		     {
		     /* Option type. */
		     u8 type;
		     /* Length of this header plus option data in 8 byte units. */
		     u8 n_data_u64s;
		     /* Option data follows. */
		     u8 data[0];
		     }) icmp6_neighbor_discovery_option_header_t;

typedef CLIB_PACKED (struct
		     {
		     icmp6_neighbor_discovery_option_header_t header;
		     u8 dst_address_length;
		     u8 flags;
#define ICMP6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_FLAG_ON_LINK (1 << 7)
#define ICMP6_NEIGHBOR_DISCOVERY_PREFIX_INFORMATION_AUTO (1 << 6)
		     u32 valid_time;
		     u32 preferred_time;
		     u32 unused; ip6_address_t dst_address;
		     }) icmp6_neighbor_discovery_prefix_information_option_t;

typedef CLIB_PACKED (struct
		     {
		     u8 type;
		     u8 aux_data_len_u32s;
		     u16 num_sources;
		     ip6_address_t mcast_addr; ip6_address_t source_addr[0];
		     }) icmp6_multicast_address_record_t;

typedef CLIB_PACKED (struct
		     {
		     ip6_hop_by_hop_ext_t ext_hdr;
		     ip6_router_alert_option_t alert;
		     ip6_padN_option_t pad;
		     icmp46_header_t icmp;
		     u16 rsvd;
		     u16 num_addr_records;
		     icmp6_multicast_address_record_t records[0];
		     }) icmp6_multicast_listener_report_header_t;

typedef CLIB_PACKED (struct
		     {
		     icmp6_neighbor_discovery_option_header_t header;
		     u8 reserved[6];
		     /* IP6 header plus payload follows. */
		     u8 data[0];
		     }) icmp6_neighbor_discovery_redirected_header_option_t;

typedef CLIB_PACKED (struct
		     {
		     icmp6_neighbor_discovery_option_header_t header;
		     u16 unused; u32 mtu;
		     }) icmp6_neighbor_discovery_mtu_option_t;

typedef CLIB_PACKED (struct
		     {
		     icmp6_neighbor_discovery_option_header_t header;
		     u8 ethernet_address[6];
		     })
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t;

typedef CLIB_PACKED (struct
		     {
		     icmp6_neighbor_discovery_option_header_t header;
		     u8 max_l2_address[6 + 8];
		     })
  icmp6_neighbor_discovery_max_link_layer_address_option_t;

/* Generic neighbor discover header.  Used for router solicitations,
   etc. */
typedef CLIB_PACKED (struct
		     {
		     icmp46_header_t icmp; u32 reserved_must_be_zero;
		     }) icmp6_neighbor_discovery_header_t;

/* Router advertisement packet formats. */
typedef CLIB_PACKED (struct
		     {
		     icmp46_header_t icmp;
		     /* Current hop limit to use for outgoing packets. */
		     u8 current_hop_limit;
		     u8 flags;
#define ICMP6_ROUTER_DISCOVERY_FLAG_ADDRESS_CONFIG_VIA_DHCP (1 << 7)
#define ICMP6_ROUTER_DISCOVERY_FLAG_OTHER_CONFIG_VIA_DHCP (1 << 6)
		     /* Zero means unspecified. */
		     u16 router_lifetime_in_sec;
		     /* Zero means unspecified. */
		     u32 neighbor_reachable_time_in_msec;
		     /* Zero means unspecified. */
		     u32
		     time_in_msec_between_retransmitted_neighbor_solicitations;
		     /* Options that may follow: source_link_layer_address, mtu, prefix_information. */
		     }) icmp6_router_advertisement_header_t;

/* Neighbor solicitation/advertisement header. */
typedef CLIB_PACKED (struct
		     {
		     icmp46_header_t icmp;
		     /* Zero for solicitation; flags for advertisement. */
		     u32 advertisement_flags;
		     /* Set when sent by a router. */
#define ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER (1 << 31)
		     /* Set when response to solicitation. */
#define ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED (1 << 30)
#define ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE (1 << 29)
		     ip6_address_t target_address;
		     /* Options that may follow: source_link_layer_address
		        (for solicitation) target_link_layer_address (for advertisement). */
		     }) icmp6_neighbor_solicitation_or_advertisement_header_t;

typedef CLIB_PACKED (struct
		     {
		     icmp46_header_t icmp;
		     u32 reserved_must_be_zero;
		     /* Better next hop to use for given destination. */
		     ip6_address_t better_next_hop_address;
		     ip6_address_t dst_address;
		     /* Options that may follow: target_link_layer_address,
		        redirected_header. */
		     }) icmp6_redirect_header_t;

/* Solicitation/advertisement packet format for ethernet. */
typedef CLIB_PACKED (struct
		     {
		     ip6_header_t ip;
		     icmp6_neighbor_solicitation_or_advertisement_header_t
		     neighbor;
		     icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
		     link_layer_option;
		     }) icmp6_neighbor_solicitation_header_t;

/* Router solicitation packet format for ethernet. */
typedef CLIB_PACKED (struct
		     {
		     ip6_header_t ip;
		     icmp6_neighbor_discovery_header_t neighbor;
		     icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
		     link_layer_option;
		     }) icmp6_router_solicitation_header_t;

/* router advertisement packet format for ethernet. */
typedef CLIB_PACKED (struct
		     {
		     ip6_header_t ip;
		     icmp6_router_advertisement_header_t router;
		     icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
		     link_layer_option;
		     icmp6_neighbor_discovery_mtu_option_t mtu_option;
		     icmp6_neighbor_discovery_prefix_information_option_t
		     prefix[0];
		     }) icmp6_router_advertisement_packet_t;

/* multicast listener report packet format for ethernet. */
typedef CLIB_PACKED (struct
		     {
		     ip6_header_t ip;
		     icmp6_multicast_listener_report_header_t report_hdr;
		     }) icmp6_multicast_listener_report_packet_t;

#endif /* included_vnet_icmp46_packet_h */
