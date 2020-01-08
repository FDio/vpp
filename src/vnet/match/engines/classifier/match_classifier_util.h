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

#ifndef _MATCH_ENGINE_CLASSIFIER_UTIL_H__
#define _MATCH_ENGINE_CLASSIFIER_UTIL_H__

#include <vnet/match/match_set.h>
#include <vnet/classify/vnet_classify.h>

#define ICMP_INVALID 0xff
#define PORT_MASK 0xffff

extern u8 *match_classifier_pad (u8 * s);
extern u32 match_classifier_table_vnet_add (void *mask,
					    u32 n_sessions,
					    u32 next_table_index,
					    uword user_ctx);
extern int match_classifier_session_vnet_add (u32 table_index,
					      void *match,
					      u32 usr_context,
					      u32 hit_next_index);

extern vnet_classify_entry_t *match_classifier_find_session (u32 table_index,
							     void *match);


extern u8 *match_classifier_build_ip_hdr (u8 * s,
					  const ip_prefix_t * sip,
					  const ip_prefix_t * dip,
					  ip_protocol_t proto);
extern u8 *match_classifier_build_ip_hdr2 (u8 * s,
					   match_orientation_t mo,
					   const ip_prefix_t * ip,
					   ip_protocol_t proto);

extern u8 *match_classifier_build_l4_hdr (u8 * s,
					  u16 s_port,
					  u16 d_port,
					  const match_tcp_flags_t * tcp);

extern u8 *match_classifier_build_icmp_hdr (u8 * s, u8 itype, u8 icode);
extern u8 *match_classifier_build_ip_mask (u8 * s,
					   ip_address_family_t af,
					   u8 src_len,
					   u8 dst_len, bool proto_exact);
extern u8 *match_classifier_build_ip_mask2 (u8 * s,
					    match_orientation_t mo,
					    ip_address_family_t af,
					    u8 len, bool proto_exact);

extern u8 *match_classifier_build_l4_mask (u8 * s,
					   bool src_port,
					   bool dst_port, u8 tmask);

extern u8 *match_classifier_build_icmp_mask (u8 * s, bool type, bool code);

extern u8 *match_classifier_build_mac_mask (u8 * s,
					    const mac_address_t * smask,
					    const mac_address_t * dmask);
extern u8 *match_classifier_build_mac_mask2 (u8 * s,
					     match_orientation_t mo,
					     const mac_address_t * mask);
extern u8 *match_classifier_build_mac_hdr2 (u8 * s,
					    match_orientation_t mo,
					    const mac_address_t * mac,
					    ethernet_type_t etype);
extern u8 *match_classifier_build_vlan_mask (u8 * s);
extern u8 *match_classifier_build_vlan_hdr (u8 * s, ethernet_type_t etype);
extern u8 *match_classifier_build_arp_mask2 (u8 * s,
					     match_orientation_t mo,
					     const mac_address_t * mask,
					     u8 len);
extern u8 *match_classifier_build_arp_hdr2 (u8 * s,
					    match_orientation_t mo,
					    const mac_address_t * mac,
					    const ip_prefix_t * ip);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
