/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_acl_inlines_h
#define included_acl_inlines_h

#include <stdint.h>

#include <vlib/unix/plugin.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <plugins/acl/hash_lookup_private.h>

#include <plugins/acl/exported_types.h>

#define LOAD_SYMBOL_FROM_PLUGIN_TO(p, s, st)                              \
({                                                                        \
    st = vlib_get_plugin_symbol(p, #s);                                    \
    if (!st)                                                               \
        return clib_error_return(0,                                       \
                "Plugin %s and/or symbol %s not found.", p, #s);          \
})

#define LOAD_SYMBOL(s) LOAD_SYMBOL_FROM_PLUGIN_TO("acl_plugin.so", s, s)


static inline clib_error_t * acl_plugin_exports_init (acl_plugin_methods_t *m)
{
    acl_plugin_methods_vtable_init_fn_t mvi;

    LOAD_SYMBOL_FROM_PLUGIN_TO("acl_plugin.so", acl_plugin_methods_vtable_init, mvi);
    return (mvi(m));
}

always_inline void *
get_ptr_to_offset (vlib_buffer_t * b0, int offset)
{
  u8 *p = vlib_buffer_get_current (b0) + offset;
  return p;
}

always_inline int
offset_within_packet (vlib_buffer_t * b0, int offset)
{
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset <= (b0->current_length - 8));
}


always_inline void
acl_fill_5tuple_l3_data (acl_main_t * am, vlib_buffer_t * b0, int is_ip6,
		 int l3_offset, fa_5tuple_t * p5tuple_pkt)
{
  if (is_ip6)
    {
      clib_memcpy (&p5tuple_pkt->ip6_addr,
		   get_ptr_to_offset (b0,
				      offsetof (ip6_header_t,
						src_address) + l3_offset),
		   sizeof (p5tuple_pkt->ip6_addr));
    }
  else
    {
      memset(p5tuple_pkt->l3_zero_pad, 0, sizeof(p5tuple_pkt->l3_zero_pad));
      clib_memcpy (&p5tuple_pkt->ip4_addr,
		   get_ptr_to_offset (b0,
				      offsetof (ip4_header_t,
						src_address) + l3_offset),
		   sizeof (p5tuple_pkt->ip4_addr));
    }
}

always_inline void
acl_fill_5tuple_l4_and_pkt_data (acl_main_t * am, u32 sw_if_index0, vlib_buffer_t * b0, int is_ip6, int is_input,
		 int l3_offset, fa_session_l4_key_t *p5tuple_l4, fa_packet_info_t *p5tuple_pkt)
{
  /* IP4 and IP6 protocol numbers of ICMP */
  static u8 icmp_protos_v4v6[] = { IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMP6 };

  int l4_offset;
  u16 ports[2];
  u8 proto;

  fa_session_l4_key_t tmp_l4 = { .lsb_of_sw_if_index = sw_if_index0 & 0xffff };
  fa_packet_info_t tmp_pkt = { .is_ip6 = is_ip6, .mask_type_index_lsb = ~0 };

  if (is_ip6)
    {
      proto =
	*(u8 *) get_ptr_to_offset (b0,
				   offsetof (ip6_header_t,
					     protocol) + l3_offset);
      l4_offset = l3_offset + sizeof (ip6_header_t);
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("ACL_FA_NODE_DBG: proto: %d, l4_offset: %d", proto,
		    l4_offset);
#endif
      /* IP6 EH handling is here, increment l4_offset if needs to, update the proto */
      int need_skip_eh = clib_bitmap_get (am->fa_ipv6_known_eh_bitmap, proto);
      if (PREDICT_FALSE (need_skip_eh))
	{
	  while (need_skip_eh && offset_within_packet (b0, l4_offset))
	    {
	      /* Fragment header needs special handling */
	      if (PREDICT_FALSE(ACL_EH_FRAGMENT == proto))
	        {
	          proto = *(u8 *) get_ptr_to_offset (b0, l4_offset);
		  u16 frag_offset;
		  clib_memcpy (&frag_offset, get_ptr_to_offset (b0, 2 + l4_offset), sizeof(frag_offset));
		  frag_offset = clib_net_to_host_u16(frag_offset) >> 3;
		  if (frag_offset)
		    {
                      tmp_pkt.is_nonfirst_fragment = 1;
                      /* invalidate L4 offset so we don't try to find L4 info */
                      l4_offset += b0->current_length;
		    }
		  else
		    {
		      /* First fragment: skip the frag header and move on. */
		      l4_offset += 8;
		    }
		}
              else
                {
	          u8 nwords = *(u8 *) get_ptr_to_offset (b0, 1 + l4_offset);
	          proto = *(u8 *) get_ptr_to_offset (b0, l4_offset);
	          l4_offset += 8 * (1 + (u16) nwords);
                }
#ifdef FA_NODE_VERBOSE_DEBUG
	      clib_warning ("ACL_FA_NODE_DBG: new proto: %d, new offset: %d",
			    proto, l4_offset);
#endif
	      need_skip_eh =
		clib_bitmap_get (am->fa_ipv6_known_eh_bitmap, proto);
	    }
	}
    }
  else
    {
      proto =
	*(u8 *) get_ptr_to_offset (b0,
				   offsetof (ip4_header_t,
					     protocol) + l3_offset);
      l4_offset = l3_offset + sizeof (ip4_header_t);
      u16 flags_and_fragment_offset;
      clib_memcpy (&flags_and_fragment_offset,
                   get_ptr_to_offset (b0,
                                      offsetof (ip4_header_t,
                                                flags_and_fragment_offset)) + l3_offset,
                                                sizeof(flags_and_fragment_offset));
      flags_and_fragment_offset = clib_net_to_host_u16 (flags_and_fragment_offset);

      /* non-initial fragments have non-zero offset */
      if ((PREDICT_FALSE(0xfff & flags_and_fragment_offset)))
        {
          tmp_pkt.is_nonfirst_fragment = 1;
          /* invalidate L4 offset so we don't try to find L4 info */
          l4_offset += b0->current_length;
        }

    }
  tmp_l4.proto = proto;
  tmp_l4.is_input = is_input;

  if (PREDICT_TRUE (offset_within_packet (b0, l4_offset)))
    {
      tmp_pkt.l4_valid = 1;
      if (icmp_protos_v4v6[is_ip6] == proto)
	{
	  /* type */
	  tmp_l4.port[0] =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset + offsetof (icmp46_header_t,
							     type));
	  /* code */
	  tmp_l4.port[1] =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset + offsetof (icmp46_header_t,
							     code));
          tmp_l4.is_slowpath = 1;
	}
      else if ((IP_PROTOCOL_TCP == proto) || (IP_PROTOCOL_UDP == proto))
	{
	  clib_memcpy (&ports,
		       get_ptr_to_offset (b0,
					  l4_offset + offsetof (tcp_header_t,
								src_port)),
		       sizeof (ports));
	  tmp_l4.port[0] = clib_net_to_host_u16 (ports[0]);
	  tmp_l4.port[1] = clib_net_to_host_u16 (ports[1]);

	  tmp_pkt.tcp_flags =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset + offsetof (tcp_header_t,
							     flags));
	  tmp_pkt.tcp_flags_valid = (proto == IP_PROTOCOL_TCP);
          tmp_l4.is_slowpath = 0;
	}
      else
        {
          tmp_l4.is_slowpath = 1;
        }
    }

  p5tuple_pkt->as_u64 = tmp_pkt.as_u64;
  p5tuple_l4->as_u64 = tmp_l4.as_u64;
}

always_inline void
acl_fill_5tuple (acl_main_t * am, u32 sw_if_index0, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_t * p5tuple_pkt)
{
  int l3_offset;

  if (is_l2_path)
    {
      l3_offset = ethernet_buffer_header_size(b0);
    }
  else
    {
      if (is_input)
        l3_offset = 0;
      else
        l3_offset = vnet_buffer(b0)->ip.save_rewrite_length;
    }

  /* key[0..3] contains src/dst address and is cleared/set below */
  /* Remainder of the key and per-packet non-key data */
  acl_fill_5tuple_l3_data(am, b0, is_ip6, l3_offset, p5tuple_pkt);
  acl_fill_5tuple_l4_and_pkt_data(am, sw_if_index0, b0, is_ip6, is_input, l3_offset, &p5tuple_pkt->l4, &p5tuple_pkt->pkt);
}

always_inline void
acl_plugin_fill_5tuple_inline (void *p_acl_main, u32 lc_index, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt)
{
  acl_main_t *am = p_acl_main;
  acl_fill_5tuple(am, 0, b0, is_ip6, is_input, is_l2_path, (fa_5tuple_t *)p5tuple_pkt);
}



always_inline int
fa_acl_match_ip4_addr (ip4_address_t * addr1, ip4_address_t * addr2,
		   int prefixlen)
{
  if (prefixlen == 0)
    {
      /* match any always succeeds */
      return 1;
    }
      uint32_t a1 = clib_net_to_host_u32 (addr1->as_u32);
      uint32_t a2 = clib_net_to_host_u32 (addr2->as_u32);
      uint32_t mask0 = 0xffffffff - ((1 << (32 - prefixlen)) - 1);
      return (a1 & mask0) == a2;
}

always_inline int
fa_acl_match_ip6_addr (ip6_address_t * addr1, ip6_address_t * addr2,
		   int prefixlen)
{
  if (prefixlen == 0)
    {
      /* match any always succeeds */
      return 1;
    }
      if (memcmp (addr1, addr2, prefixlen / 8))
	{
	  /* If the starting full bytes do not match, no point in bittwidling the thumbs further */
	  return 0;
	}
      if (prefixlen % 8)
	{
	  u8 b1 = *((u8 *) addr1 + 1 + prefixlen / 8);
	  u8 b2 = *((u8 *) addr2 + 1 + prefixlen / 8);
	  u8 mask0 = (0xff - ((1 << (8 - (prefixlen % 8))) - 1));
	  return (b1 & mask0) == b2;
	}
      else
	{
	  /* The prefix fits into integer number of bytes, so nothing left to do */
	  return 1;
	}
}

always_inline int
fa_acl_match_port (u16 port, u16 port_first, u16 port_last, int is_ip6)
{
  return ((port >= port_first) && (port <= port_last));
}

always_inline int
single_acl_match_5tuple (acl_main_t * am, u32 acl_index, fa_5tuple_t * pkt_5tuple,
		  int is_ip6, u8 * r_action, u32 * r_acl_match_p,
		  u32 * r_rule_match_p, u32 * trace_bitmap)
{
  int i;
  acl_list_t *a;
  acl_rule_t *r;

  if (pool_is_free_index (am->acls, acl_index))
    {
      if (r_acl_match_p)
	*r_acl_match_p = acl_index;
      if (r_rule_match_p)
	*r_rule_match_p = -1;
      /* the ACL does not exist but is used for policy. Block traffic. */
      return 0;
    }
  a = am->acls + acl_index;
  for (i = 0; i < a->count; i++)
    {
      r = a->rules + i;
      if (is_ip6 != r->is_ipv6)
	{
	  continue;
	}
      if (is_ip6) {
        if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[1], &r->dst.ip6, r->dst_prefixlen))
	continue;
        if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[0], &r->src.ip6, r->src_prefixlen))
	continue;
      } else {
        if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[1], &r->dst.ip4, r->dst_prefixlen))
	continue;
        if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[0], &r->src.ip4, r->src_prefixlen))
	continue;
      }

      if (r->proto)
	{
	  if (pkt_5tuple->l4.proto != r->proto)
	    continue;

          if (PREDICT_FALSE (pkt_5tuple->pkt.is_nonfirst_fragment &&
                     am->l4_match_nonfirst_fragment))
          {
            /* non-initial fragment with frag match configured - match this rule */
            *trace_bitmap |= 0x80000000;
            *r_action = r->is_permit;
            if (r_acl_match_p)
	      *r_acl_match_p = acl_index;
            if (r_rule_match_p)
	      *r_rule_match_p = i;
            return 1;
          }

	  /* A sanity check just to ensure we are about to match the ports extracted from the packet */
	  if (PREDICT_FALSE (!pkt_5tuple->pkt.l4_valid))
	    continue;

#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG acl %d rule %d pkt proto %d match rule %d",
	     acl_index, i, pkt_5tuple->l4.proto, r->proto);
#endif

	  if (!fa_acl_match_port
	      (pkt_5tuple->l4.port[0], r->src_port_or_type_first,
	       r->src_port_or_type_last, is_ip6))
	    continue;

#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG acl %d rule %d pkt sport %d match rule [%d..%d]",
	     acl_index, i, pkt_5tuple->l4.port[0], r->src_port_or_type_first,
	     r->src_port_or_type_last);
#endif

	  if (!fa_acl_match_port
	      (pkt_5tuple->l4.port[1], r->dst_port_or_code_first,
	       r->dst_port_or_code_last, is_ip6))
	    continue;

#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG acl %d rule %d pkt dport %d match rule [%d..%d]",
	     acl_index, i, pkt_5tuple->l4.port[1], r->dst_port_or_code_first,
	     r->dst_port_or_code_last);
#endif
	  if (pkt_5tuple->pkt.tcp_flags_valid
	      && ((pkt_5tuple->pkt.tcp_flags & r->tcp_flags_mask) !=
		  r->tcp_flags_value))
	    continue;
	}
      /* everything matches! */
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("ACL_FA_NODE_DBG acl %d rule %d FULL-MATCH, action %d",
		    acl_index, i, r->is_permit);
#endif
      *r_action = r->is_permit;
      if (r_acl_match_p)
	*r_acl_match_p = acl_index;
      if (r_rule_match_p)
	*r_rule_match_p = i;
      return 1;
    }
  return 0;
}

always_inline int
acl_plugin_single_acl_match_5tuple (void *p_acl_main, u32 acl_index, fa_5tuple_t * pkt_5tuple,
		  int is_ip6, u8 * r_action, u32 * r_acl_match_p,
		  u32 * r_rule_match_p, u32 * trace_bitmap)
{
  acl_main_t * am = p_acl_main;
  return single_acl_match_5tuple(am, acl_index, pkt_5tuple, is_ip6, r_action,
                                 r_acl_match_p, r_rule_match_p, trace_bitmap);
}

always_inline int
linear_multi_acl_match_5tuple (void *p_acl_main, u32 lc_index, fa_5tuple_t * pkt_5tuple,
		       int is_ip6, u8 *r_action, u32 *acl_pos_p, u32 * acl_match_p,
		       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  int i;
  u32 *acl_vector;
  u8 action = 0;
  acl_lookup_context_t *acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);

  acl_vector = acontext->acl_indices;

  for (i = 0; i < vec_len (acl_vector); i++)
    {
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("ACL_FA_NODE_DBG: Trying to match ACL: %d",
		    acl_vector[i]);
#endif
      if (single_acl_match_5tuple
	  (am, acl_vector[i], pkt_5tuple, is_ip6, &action,
	   acl_match_p, rule_match_p, trace_bitmap))
	{
	  *r_action = action;
          *acl_pos_p = i;
	  return 1;
	}
    }
  if (vec_len (acl_vector) > 0)
    {
      return 0;
    }
#ifdef FA_NODE_VERBOSE_DEBUG
  clib_warning ("ACL_FA_NODE_DBG: No ACL on lc_index %d", lc_index);
#endif
  /* If there are no ACLs defined we should not be here. */
  return 0;
}



/*
 * This returns true if there is indeed a match on the portranges.
 * With all these levels of indirections, this is not going to be very fast,
 * so, best use the individual ports or wildcard ports for performance.
 */
always_inline int
match_portranges(acl_main_t *am, fa_5tuple_t *match, u32 index)
{

  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, match->pkt.lc_index);
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), index);

  acl_rule_t *r = &(am->acls[pae->acl_index].rules[pae->ace_index]);

#ifdef FA_NODE_VERBOSE_DEBUG
  clib_warning("PORTMATCH: %d <= %d <= %d && %d <= %d <= %d ?",
		r->src_port_or_type_first, match->l4.port[0], r->src_port_or_type_last,
		r->dst_port_or_code_first, match->l4.port[1], r->dst_port_or_code_last);
#endif

  return ( ((r->src_port_or_type_first <= match->l4.port[0]) && r->src_port_or_type_last >= match->l4.port[0]) &&
           ((r->dst_port_or_code_first <= match->l4.port[1]) && r->dst_port_or_code_last >= match->l4.port[1]) );
}

always_inline int
single_rule_match_5tuple (acl_rule_t * r, int is_ip6, fa_5tuple_t * pkt_5tuple)
{
  if (is_ip6 != r->is_ipv6)
    {
      return 0;
    }

  if (is_ip6)
    {
      if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[1], &r->dst.ip6, r->dst_prefixlen))
	return 0;
      if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[0], &r->src.ip6, r->src_prefixlen))
	return 0;
    }
  else
    {
      if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[1], &r->dst.ip4, r->dst_prefixlen))
	return 0;
      if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[0], &r->src.ip4, r->src_prefixlen))
	return 0;
    }

  if (r->proto)
    {
      if (pkt_5tuple->l4.proto != r->proto)
	return 0;

      /* A sanity check just to ensure we are about to match the ports extracted from the packet */
      if (PREDICT_FALSE (!pkt_5tuple->pkt.l4_valid))
	return 0;


      if (!fa_acl_match_port
	  (pkt_5tuple->l4.port[0], r->src_port_or_type_first,
	   r->src_port_or_type_last, pkt_5tuple->pkt.is_ip6))
	return 0;


      if (!fa_acl_match_port
	  (pkt_5tuple->l4.port[1], r->dst_port_or_code_first,
	   r->dst_port_or_code_last, pkt_5tuple->pkt.is_ip6))
	return 0;

      if (pkt_5tuple->pkt.tcp_flags_valid
	  && ((pkt_5tuple->pkt.tcp_flags & r->tcp_flags_mask) !=
	      r->tcp_flags_value))
	return 0;
    }
  /* everything matches! */
  return 1;
}

always_inline u32
multi_acl_match_get_applied_ace_index (acl_main_t * am, int is_ip6, fa_5tuple_t * match)
{
  clib_bihash_kv_48_8_t kv;
  clib_bihash_kv_48_8_t result;
  fa_5tuple_t *kv_key = (fa_5tuple_t *) kv.key;
  hash_acl_lookup_value_t *result_val =
    (hash_acl_lookup_value_t *) & result.value;
  u64 *pmatch = (u64 *) match;
  u64 *pmask;
  u64 *pkey;
  int mask_type_index, order_index;
  u32 curr_match_index = (~0 - 1);



  u32 lc_index = match->pkt.lc_index;
  applied_hash_ace_entry_t **applied_hash_aces =
    vec_elt_at_index (am->hash_entry_vec_by_lc_index, lc_index);

  hash_applied_mask_info_t **hash_applied_mask_info_vec =
    vec_elt_at_index (am->hash_applied_mask_info_vec_by_lc_index, lc_index);

  hash_applied_mask_info_t *minfo;

  DBG ("TRYING TO MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
       pmatch[0], pmatch[1], pmatch[2], pmatch[3], pmatch[4], pmatch[5]);

  for (order_index = 0; order_index < vec_len ((*hash_applied_mask_info_vec));
       order_index++)
    {
      minfo = vec_elt_at_index ((*hash_applied_mask_info_vec), order_index);
      if (minfo->first_rule_index > curr_match_index)
	{
	  /* Index in this and following (by construction) partitions are greater than our candidate, Avoid trying to match! */
	  break;
	}

      mask_type_index = minfo->mask_type_index;
      ace_mask_type_entry_t *mte =
	vec_elt_at_index (am->ace_mask_type_pool, mask_type_index);
      pmatch = (u64 *) match;
      pmask = (u64 *) & mte->mask;
      pkey = (u64 *) kv.key;
      /*
       * unrolling the below loop results in a noticeable performance increase.
       int i;
       for(i=0; i<6; i++) {
       kv.key[i] = pmatch[i] & pmask[i];
       }
       */

      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;

      /*
       * The use of temporary variable convinces the compiler
       * to make a u64 write, avoiding the stall on crc32 operation
       * just a bit later.
       */
      fa_packet_info_t tmp_pkt = kv_key->pkt;
      tmp_pkt.mask_type_index_lsb = mask_type_index;
      kv_key->pkt.as_u64 = tmp_pkt.as_u64;

      int res =
	clib_bihash_search_inline_2_48_8 (&am->acl_lookup_hash, &kv, &result);

      if (res == 0)
	{
	  /* There is a hit in the hash, so check the collision vector */
	  u32 curr_index = result_val->applied_entry_index;
	  applied_hash_ace_entry_t *pae =
	    vec_elt_at_index ((*applied_hash_aces), curr_index);
	  collision_match_rule_t *crs = pae->colliding_rules;
	  int i;
	  for (i = 0; i < vec_len (crs); i++)
	    {
	      if (crs[i].applied_entry_index >= curr_match_index)
		{
		  continue;
		}
	      if (single_rule_match_5tuple (&crs[i].rule, is_ip6, match))
		{
		  curr_match_index = crs[i].applied_entry_index;
		}
	    }
	}
    }
  DBG ("MATCH-RESULT: %d", curr_match_index);
  return curr_match_index;
}

always_inline int
hash_multi_acl_match_5tuple (void *p_acl_main, u32 lc_index, fa_5tuple_t * pkt_5tuple,
                       int is_ip6, u8 *action, u32 *acl_pos_p, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
  u32 match_index = multi_acl_match_get_applied_ace_index(am, is_ip6, pkt_5tuple);
  if (match_index < vec_len((*applied_hash_aces))) {
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), match_index);
    pae->hitcount++;
    *acl_pos_p = pae->acl_position;
    *acl_match_p = pae->acl_index;
    *rule_match_p = pae->ace_index;
    *action = pae->action;
    return 1;
  }
  return 0;
}



always_inline int
acl_plugin_match_5tuple_inline (void *p_acl_main, u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  fa_5tuple_t * pkt_5tuple_internal = (fa_5tuple_t *)pkt_5tuple;
  pkt_5tuple_internal->pkt.lc_index = lc_index;
  if (PREDICT_TRUE(am->use_hash_acl_matching)) {
    if (PREDICT_FALSE(pkt_5tuple_internal->pkt.is_nonfirst_fragment)) {
      /*
       * tuplemerge does not take fragments into account,
       * and in general making fragments first class citizens has
       * proved more overhead than it's worth - so just fall back to linear
       * matching in that case.
       */
      return linear_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    } else {
      return hash_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    }
  } else {
    return linear_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
  }
}



#endif
