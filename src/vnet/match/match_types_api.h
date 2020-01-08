/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_TYPES_API_H__
#define __MATCH_TYPES_API_H__

#include <vnet/match/match_types.h>
#include <vnet/match/match_types.api_types.h>

extern int match_tcp_flags_decode (const vl_api_match_tcp_flags_t * in,
				   match_tcp_flags_t * out);
extern void match_tcp_flags_encode (const match_tcp_flags_t * in,
				    vl_api_match_tcp_flags_t * out);

extern int match_ip_prefix_decode (const vl_api_prefix_t * in,
				   match_ip_prefix_t * out);
extern void match_ip_prefix_encode (const match_ip_prefix_t * in,
				    vl_api_prefix_t * out);

extern void match_mac_mask_decode (const vl_api_match_mac_mask_t * in,
				   match_mac_mask_t * out);
extern void match_mac_mask_encode (const match_mac_mask_t * in,
				   vl_api_match_mac_mask_t * out);

extern int match_port_range_decode (const vl_api_match_port_range_t * in,
				    match_port_range_t * out);
extern void match_port_range_encode (const match_port_range_t * in,
				     vl_api_match_port_range_t * out);

extern void match_icmp_code_range_decode (const vl_api_match_icmp_code_range_t
					  * in,
					  match_icmp_code_range_t * out);
extern void match_icmp_type_range_decode (const vl_api_match_icmp_type_range_t
					  * in,
					  match_icmp_type_range_t * out);
extern void match_icmp_code_range_encode (const match_icmp_code_range_t * in,
					  vl_api_match_icmp_code_range_t *
					  out);
extern void match_icmp_type_range_encode (const match_icmp_type_range_t * in,
					  vl_api_match_icmp_type_range_t *
					  out);

extern int match_type_decode (vl_api_match_type_t in, match_type_t * out);
extern vl_api_match_type_t match_type_encode (match_type_t in);
extern int match_orientation_decode (vl_api_match_orientation_t in,
				     match_orientation_t * out);
extern vl_api_match_orientation_t
match_orientation_encode (match_orientation_t in);

extern int match_rule_decode (const vl_api_match_rule_t * in,
			      match_rule_t * out);
extern int match_rule_exact_ip_l4_decode (const vl_api_match_exact_ip_l4_t *
					  in, match_rule_t * out);
extern int match_rule_mask_ip_mac_decode (const vl_api_match_mask_ip_mac_t *
					  in, match_rule_t * out);
extern int match_rule_mask_n_tuple_decode (const vl_api_match_mask_n_tuple_t *
					   in, match_rule_t * out);
extern int match_rule_sets_decode (const vl_api_match_sets_t * in,
				   match_rule_t * out);

extern void match_rule_encode (const match_rule_t * in,
			       vl_api_match_rule_t * out);
extern void match_rule_mask_ip_mac_encode (const match_rule_t * in,
					   vl_api_match_mask_ip_mac_t * out);
extern void match_rule_exact_ip_l4_encode (const match_rule_t * in,
					   vl_api_match_exact_ip_l4_t * out);
extern void match_rule_mask_n_tuple_encode (const match_rule_t * in,
					    vl_api_match_mask_n_tuple_t *
					    out);
extern void match_rule_sets_encode (const match_rule_t * in,
				    vl_api_match_sets_t * out);

extern void match_list_encode (const match_list_t * in,
			       vl_api_match_list_t * out);
extern int match_list_decode (const vl_api_match_list_t * in,
			      match_list_t * out);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
