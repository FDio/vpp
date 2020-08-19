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

#ifndef included_capo_match_h
#define included_capo_match_h


#include <acl/acl.h>
#include <acl/fa_node.h>

#include <capo/capo_ipset.h>
#include <capo/capo_policy.h>
#include <capo/capo_rule.h>

int capo_match_func (void *p_acl_main, u32 sw_if_index, u32 is_inbound,
		     fa_5tuple_opaque_t * opaque_5tuple,
		     int is_ip6, u8 * r_action, u32 * trace_bitmap);


int capo_match_policy (capo_policy_t * policy, u32 is_inbound, u32 is_ip6,
		       fa_5tuple_t * pkt_5tuple);
int capo_match_rule (capo_rule_t * rule, u32 is_ip6,
		     fa_5tuple_t * pkt_5tuple);

u8 ipset_contains_ip4 (capo_ipset_t * ipset, ip4_address_t * addr);
u8 ipset_contains_ip6 (capo_ipset_t * ipset, ip6_address_t * addr);
u8 ipport_ipset_contains_ip4 (capo_ipset_t * ipset, ip4_address_t * addr,
			      u8 l4proto, u16 port);
u8 ipport_ipset_contains_ip6 (capo_ipset_t * ipset, ip6_address_t * addr,
			      u8 l4proto, u16 port);


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
