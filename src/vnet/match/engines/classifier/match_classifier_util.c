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

#include <vnet/match/engines/classifier/match_classifier_util.h>

#include <vnet/ip/icmp46_packet.h>
#include <vnet/ethernet/arp_packet.h>

static u32
match_classifier_round_up_to_classifier_vector_size (u32 n_bytes)
{
  u32 d, m;
  /* round to size of u32x4 */
  d = n_bytes / VNET_CLASSIFY_VECTOR_SIZE;
  m = n_bytes % VNET_CLASSIFY_VECTOR_SIZE;
  if (m)
    d++;

  return ((d * VNET_CLASSIFY_VECTOR_SIZE) / VNET_CLASSIFY_VECTOR_SIZE);
}

u8 *
match_classifier_pad (u8 * s)
{
  u32 len;

  len =
    match_classifier_round_up_to_classifier_vector_size (vec_len (s)) *
    VNET_CLASSIFY_VECTOR_SIZE;

  vec_validate (s, len - 1);

  return (s);
}

u32
match_classifier_table_vnet_add (void *mask,
				 u32 n_sessions,
				 u32 next_table_index, uword user_ctx)
{
  vnet_classify_main_t *vcm = &vnet_classify_main;
  u32 memory_size = 2 << 22;
  u32 nbuckets = 32;
  u32 table_index = ~0;

  memory_size = (n_sessions * 128 *
		 (sizeof (vnet_classify_entry_t) + vec_len (mask)));
  nbuckets = max_pow2 (n_sessions);

  /* *INDENT-OFF* */
  if (vnet_classify_add_del_table (vcm, mask, nbuckets, memory_size,
                                   // no skip, the packet's current needs to be in the
                                   // correct location.
                                   0,
				   vec_len(mask) / VNET_CLASSIFY_VECTOR_SIZE,
                                   next_table_index,
				   // miss_next_index,
                                   0,
				   &table_index,
                                   CLASSIFY_FLAG_USE_CURR_DATA,
                                   //  offset
                                   0,
                                   // is_add,
				   1,
                                   // delete_chain
				   0))
    ASSERT (0);
  /* *INDENT-ON* */

  vnet_classify_table_t *vct;

  vct = pool_elt_at_index (vcm->tables, table_index);
  vct->user_ctx = user_ctx;

  return (table_index);
}

int
match_classifier_session_vnet_add (u32 table_index,
				   void *match,
				   u32 usr_context, u32 hit_next_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;

  /* *INDENT-OFF* */
  return (vnet_classify_add_del_session (cm, table_index, match,
                                         hit_next_index,
					 usr_context,
                                         0,	// advance,
					 CLASSIFY_ACTION_NONE,
					 0 /* metadata */ ,
					 1 /* is_add */ ));
  /* *INDENT-ON* */
}

vnet_classify_entry_t *
match_classifier_find_session (u32 table_index, void *match)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vnet_classify_table_t *vct;
  vnet_classify_entry_t *e;
  u64 hash;

  vct = pool_elt_at_index (cm->tables, table_index);
  hash = vnet_classify_hash_packet_inline (vct, match);

  e = vnet_classify_find_entry_inline (vct, match, hash, 0);

  return (e);
}

u8 *
match_classifier_build_l4_hdr (u8 * s,
			       u16 s_port, u16 d_port,
			       const match_tcp_flags_t * tflags)
{
  tcp_header_t *tcp;
  u8 *n;

  vec_add2 (s, n, sizeof (*tcp));
  tcp = (tcp_header_t *) n;

  tcp->src_port = clib_host_to_net_u16 (s_port);
  tcp->dst_port = clib_host_to_net_u16 (d_port);

  if (tflags)
    tcp->flags = tflags->mtf_flags;

  return (s);
}


static u8 *
match_classifier_build_ip4_hdr (u8 * s,
				const ip_prefix_t * sip,
				const ip_prefix_t * dip, ip_protocol_t proto)
{
  ip4_header_t *ip4;
  u8 *i;

  vec_add2 (s, i, sizeof (*ip4));
  ip4 = (ip4_header_t *) i;

  if (sip)
    ip4->src_address = ip_addr_v4 (&ip_prefix_addr (sip));
  if (dip)
    ip4->dst_address = ip_addr_v4 (&ip_prefix_addr (dip));

  ip4->protocol = proto;

  return (s);
}

static u8 *
match_classifier_build_ip6_hdr (u8 * s,
				const ip_prefix_t * sip,
				const ip_prefix_t * dip, ip_protocol_t proto)
{
  ip6_header_t *ip6;
  u8 *i;

  vec_add2 (s, i, sizeof (*ip6));
  ip6 = (ip6_header_t *) i;

  if (sip)
    ip6->src_address = ip_addr_v6 (&ip_prefix_addr (sip));
  if (dip)
    ip6->dst_address = ip_addr_v6 (&ip_prefix_addr (dip));

  ip6->protocol = proto;

  return (s);
}

u8 *
match_classifier_build_ip_hdr (u8 * s,
			       const ip_prefix_t * sip,
			       const ip_prefix_t * dip, ip_protocol_t proto)
{
  ip_address_family_t af;

  af = (sip ? ip_prefix_version (sip) : ip_prefix_version (dip));

  switch (af)
    {
    case AF_IP4:
      return (match_classifier_build_ip4_hdr (s, sip, dip, proto));
    case AF_IP6:
      return (match_classifier_build_ip6_hdr (s, sip, dip, proto));
    }

  ASSERT (0);
  return (NULL);
}

u8 *
match_classifier_build_ip_hdr2 (u8 * s,
				match_orientation_t mo,
				const ip_prefix_t * ip, ip_protocol_t proto)
{
  if (MATCH_SRC == mo)
    return (match_classifier_build_ip_hdr (s, ip, NULL, proto));
  else
    return (match_classifier_build_ip_hdr (s, NULL, ip, proto));
}

u8 *
match_classifier_build_icmp_hdr (u8 * s, u8 itype, u8 icode)
{
  icmp46_header_t *icmp;
  u8 *n;

  vec_add2 (s, n, sizeof (*icmp));
  icmp = (icmp46_header_t *) n;

  if (ICMP_INVALID != itype)
    icmp->type = itype;
  if (ICMP_INVALID != icode)
    icmp->code = icode;

  return (s);
}

static u8 *
match_classifier_build_ip4_mask (u8 * s,
				 u8 src_len, u8 dst_len, u8 proto_exact)
{
  ip4_header_t *ip4;
  u8 *n;

  vec_add2 (s, n, sizeof (*ip4));
  ip4 = (ip4_header_t *) n;

  ip4_preflen_to_mask (src_len, &ip4->src_address);
  ip4_preflen_to_mask (dst_len, &ip4->dst_address);

  ip4->protocol = (proto_exact ? 0xff : 0);

  return (s);
}

static u8 *
match_classifier_build_ip6_mask (u8 * s,
				 u8 src_len, u8 dst_len, u8 proto_exact)
{
  ip6_header_t *ip6;
  u8 *n;

  vec_add2 (s, n, sizeof (*ip6));
  ip6 = (ip6_header_t *) n;

  ip6_preflen_to_mask (src_len, &ip6->src_address);
  ip6_preflen_to_mask (dst_len, &ip6->dst_address);

  ip6->protocol = (proto_exact ? 0xff : 0);

  return (s);
}

u8 *
match_classifier_build_ip_mask (u8 * s,
				ip_address_family_t af,
				u8 src_len, u8 dst_len, bool proto_exact)
{
  switch (af)
    {
    case AF_IP4:
      return (match_classifier_build_ip4_mask
	      (s, src_len, dst_len, proto_exact));
    case AF_IP6:
      return (match_classifier_build_ip6_mask
	      (s, src_len, dst_len, proto_exact));
    }

  ASSERT (0);
  return (NULL);
}

u8 *
match_classifier_build_ip_mask2 (u8 * s,
				 match_orientation_t mo,
				 ip_address_family_t af,
				 u8 len, bool proto_exact)
{
  if (MATCH_SRC == mo)
    return (match_classifier_build_ip_mask (s, af, len, 0, proto_exact));
  else
    return (match_classifier_build_ip_mask (s, af, 0, len, proto_exact));
}

u8 *
match_classifier_build_icmp_mask (u8 * s, bool type, bool code)
{
  icmp46_header_t *icmp;
  u8 *n;

  vec_add2 (s, n, sizeof (*icmp));
  icmp = (icmp46_header_t *) n;

  icmp->type = (type ? 0xff : 0);
  icmp->code = (code ? 0xff : 0);

  return (s);
}

u8 *
match_classifier_build_l4_mask (u8 * s,
				bool src_port, bool dst_port, u8 tmask)
{
  tcp_header_t *tcp;
  u8 *n;

  vec_add2 (s, n, sizeof (*tcp));
  tcp = (tcp_header_t *) n;

  tcp->src_port = (src_port ? 0xffff : 0);
  tcp->dst_port = (dst_port ? 0xffff : 0);
  tcp->flags = tmask;

  return (s);
}

u8 *
match_classifier_build_mac_mask (u8 * s,
				 const mac_address_t * smask,
				 const mac_address_t * dmask)
{
  ethernet_header_t *eh;
  u8 *n;

  vec_add2 (s, n, sizeof (*eh));
  eh = (ethernet_header_t *) n;

  if (smask)
    mac_address_to_bytes (smask, eh->src_address);
  if (dmask)
    mac_address_to_bytes (dmask, eh->dst_address);

  eh->type = 0xffff;

  return (s);
}

u8 *
match_classifier_build_mac_hdr (u8 * s,
				const mac_address_t * smac,
				const mac_address_t * dmac,
				ethernet_type_t etype)
{
  ethernet_header_t *eh;
  u8 *n;

  vec_add2 (s, n, sizeof (*eh));
  eh = (ethernet_header_t *) n;

  if (smac)
    mac_address_to_bytes (smac, eh->src_address);
  if (dmac)
    mac_address_to_bytes (dmac, eh->dst_address);

  eh->type = clib_host_to_net_u16 (etype);

  return (s);
}

u8 *
match_classifier_build_mac_mask2 (u8 * s,
				  match_orientation_t mo,
				  const mac_address_t * mask)
{
  if (MATCH_SRC == mo)
    return (match_classifier_build_mac_mask (s, mask, NULL));
  else
    return (match_classifier_build_mac_mask (s, NULL, mask));
}

u8 *
match_classifier_build_mac_hdr2 (u8 * s,
				 match_orientation_t mo,
				 const mac_address_t * mac,
				 ethernet_type_t etype)
{
  if (MATCH_SRC == mo)
    return (match_classifier_build_mac_hdr (s, mac, NULL, etype));
  else
    return (match_classifier_build_mac_hdr (s, NULL, mac, etype));
}

u8 *
match_classifier_build_arp_mask (u8 * s,
				 const mac_address_t * smask,
				 const mac_address_t * dmask,
				 u8 slen, u8 dlen)
{
  ethernet_arp_header_t *arp;
  u8 *n;

  vec_add2 (s, n, sizeof (*arp));
  arp = (ethernet_arp_header_t *) n;

  if (smask)
    mac_address_copy (&arp->ip4_over_ethernet[ARP_SENDER].mac, smask);
  if (dmask)
    mac_address_copy (&arp->ip4_over_ethernet[ARP_TARGET].mac, dmask);

  ip4_preflen_to_mask (slen, &arp->ip4_over_ethernet[ARP_SENDER].ip4);
  ip4_preflen_to_mask (dlen, &arp->ip4_over_ethernet[ARP_TARGET].ip4);

  return (s);
}

u8 *
match_classifier_build_arp_mask2 (u8 * s,
				  match_orientation_t mo,
				  const mac_address_t * mask, u8 len)
{
  if (MATCH_SRC == mo)
    return (match_classifier_build_arp_mask (s, mask, NULL, len, 0));
  else
    return (match_classifier_build_arp_mask (s, NULL, mask, 0, len));
}

u8 *
match_classifier_build_vlan_mask (u8 * s)
{
  ethernet_vlan_header_t *ev;
  u8 *n;

  vec_add2 (s, n, sizeof (*ev));
  ev = (ethernet_vlan_header_t *) n;

  ev->type = 0xffff;

  return (s);
}

u8 *
match_classifier_build_vlan_hdr (u8 * s, ethernet_type_t etype)
{
  ethernet_vlan_header_t *ev;
  u8 *n;

  vec_add2 (s, n, sizeof (*ev));
  ev = (ethernet_vlan_header_t *) n;

  ev->type = clib_host_to_net_u16 (etype);

  return (s);
}

u8 *
match_classifier_build_arp_hdr (u8 * s,
				const mac_address_t * smac,
				const mac_address_t * dmac,
				const ip_prefix_t * sip,
				const ip_prefix_t * dip)
{
  ethernet_arp_header_t *arp;
  u8 *n;

  vec_add2 (s, n, sizeof (*arp));
  arp = (ethernet_arp_header_t *) n;

  if (smac)
    mac_address_copy (&arp->ip4_over_ethernet[ARP_SENDER].mac, smac);
  if (dmac)
    mac_address_copy (&arp->ip4_over_ethernet[ARP_TARGET].mac, dmac);

  if (sip)
    arp->ip4_over_ethernet[ARP_SENDER].ip4 =
      ip_addr_v4 (&ip_prefix_addr (sip));
  if (dip)
    arp->ip4_over_ethernet[ARP_TARGET].ip4 =
      ip_addr_v4 (&ip_prefix_addr (dip));

  return (s);
}

u8 *
match_classifier_build_arp_hdr2 (u8 * s,
				 match_orientation_t mo,
				 const mac_address_t * mac,
				 const ip_prefix_t * ip)
{
  if (MATCH_SRC == mo)
    return (match_classifier_build_arp_hdr (s, mac, NULL, ip, NULL));
  else
    return (match_classifier_build_arp_hdr (s, NULL, mac, NULL, ip));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
