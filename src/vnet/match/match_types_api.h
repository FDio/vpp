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

extern u32 match_types_api_list_size (const vl_api_match_list_t * ml);

extern void match_ip_prefix_decode (const vl_api_prefix_t * in,
				    match_ip_prefix_t * out);
extern void match_ip_prefix_encode (const match_ip_prefix_t * in,
				    vl_api_prefix_t * out);

extern void match_mac_mask_decode (const vl_api_match_mac_mask_t * in,
				   match_mac_mask_t * out);
extern void match_mac_mask_encode (const match_mac_mask_t * in,
				   vl_api_match_mac_mask_t * out);

extern void match_port_range_decode (const vl_api_match_port_range_t * in,
				     match_port_range_t * out);

extern int match_type_decode (vl_api_match_type_t in, match_type_t * out);
extern vl_api_match_type_t match_type_encode (match_type_t in);

extern int match_rule_decode (const vl_api_match_rule_t * in,
			      match_rule_t * out);
extern void match_rule_mask_ip_mac_decode (const vl_api_match_mask_ip_mac_t *
					   in, match_rule_t * out);

extern void match_rule_encode (const match_rule_t * in,
			       vl_api_match_rule_t * out);
extern void match_rule_mask_ip_mac_encode (const match_rule_t * in,
					   vl_api_match_mask_ip_mac_t * out);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
