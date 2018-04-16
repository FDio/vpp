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

#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <plugins/acl/hash_lookup_private.h>

//#define VALE_ELOG_ACL //Added by Valerio

/* check if a given ACL exists */

#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS

/*
 * Define a pointer to the acl_main which will be filled during the initialization.
 */
acl_main_t *p_acl_main = 0;

/*
 * If the file is included more than once, the symbol collision will make the problem obvious.
 * If the include is done only once, it is just a lonely null var
 * sitting around.
 */
void *ERROR_ACL_PLUGIN_EXPORTS_FILE_MUST_BE_INCLUDED_ONLY_IN_ONE_PLACE = 0;

u8 (*acl_plugin_acl_exists) (u32 acl_index);
#else
u8 acl_plugin_acl_exists (u32 acl_index);
#endif


/*
 * If you are using ACL plugin, get this unique ID first,
 * so you can identify yourself when creating the lookup contexts.
 */

#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS
u32 (*acl_plugin_register_user_module) (char *caller_module_string, char *val1_label, char *val2_label);
#else
u32 acl_plugin_register_user_module (char *caller_module_string, char *val1_label, char *val2_label);
#endif

/*
 * Allocate a new lookup context index.
 * Supply the id assigned to your module during registration,
 * and two values of your choice identifying instances
 * of use within your module. They are useful for debugging.
 */
#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS
int (*acl_plugin_get_lookup_context_index) (u32 acl_user_id, u32 val1, u32 val2);
#else
int acl_plugin_get_lookup_context_index (u32 acl_user_id, u32 val1, u32 val2);
#endif

/*
 * Release the lookup context index and destroy
 * any asssociated data structures.
 */
#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS
void (*acl_plugin_put_lookup_context_index) (u32 lc_index);
#else
void acl_plugin_put_lookup_context_index (u32 lc_index);
#endif

/*
 * Prepare the sequential vector of ACL#s to lookup within a given context.
 * Any existing list will be overwritten. acl_list is a vector.
 */
#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS
int (*acl_plugin_set_acl_vec_for_context) (u32 lc_index, u32 *acl_list);
#else
int acl_plugin_set_acl_vec_for_context (u32 lc_index, u32 *acl_list);
#endif

/* Fill the 5-tuple from the packet */

#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS
void (*acl_plugin_fill_5tuple) (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt);
#else
void acl_plugin_fill_5tuple (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt);
#endif

#ifdef ACL_PLUGIN_DEFINED_BELOW_IN_FILE
static inline
void acl_plugin_fill_5tuple_inline (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt) {
  /* FIXME: normally the inlined version of filling in the 5-tuple. But for now just call the non-inlined version */
  acl_plugin_fill_5tuple(lc_index, b0, is_ip6, is_input, is_l2_path, p5tuple_pkt);
}
#endif


#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS
int (*acl_plugin_match_5tuple) (u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap);
#else
int acl_plugin_match_5tuple (u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap);
#endif

#ifdef ACL_PLUGIN_DEFINED_BELOW_IN_FILE
static inline int
acl_plugin_match_5tuple_inline (u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap) {
  return acl_plugin_match_5tuple(lc_index, pkt_5tuple, is_ip6, r_action, r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
}
#endif

#ifdef ACL_PLUGIN_EXTERNAL_EXPORTS

#define LOAD_SYMBOL_FROM_PLUGIN_TO(p, s, st)                              \
({                                                                        \
    st = vlib_get_plugin_symbol(p, #s);                                    \
    if (!st)                                                               \
        return clib_error_return(0,                                       \
                "Plugin %s and/or symbol %s not found.", p, #s);          \
})

#define LOAD_SYMBOL(s) LOAD_SYMBOL_FROM_PLUGIN_TO("acl_plugin.so", s, s)

static inline clib_error_t * acl_plugin_exports_init (void)
{
    LOAD_SYMBOL_FROM_PLUGIN_TO("acl_plugin.so", acl_main, p_acl_main);
    LOAD_SYMBOL(acl_plugin_acl_exists);
    LOAD_SYMBOL(acl_plugin_register_user_module);
    LOAD_SYMBOL(acl_plugin_get_lookup_context_index);
    LOAD_SYMBOL(acl_plugin_put_lookup_context_index);
    LOAD_SYMBOL(acl_plugin_set_acl_vec_for_context);
    LOAD_SYMBOL(acl_plugin_fill_5tuple);
    LOAD_SYMBOL(acl_plugin_match_5tuple);
    return 0;
}

#endif

static void *
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


always_inline int
fa_acl_match_addr (ip46_address_t * addr1, ip46_address_t * addr2,
		   int prefixlen, int is_ip6)
{
  if (prefixlen == 0)
    {
      /* match any always succeeds */
      return 1;
    }
  if (is_ip6)
    {
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
  else
    {
      uint32_t a1 = clib_net_to_host_u32 (addr1->ip4.as_u32);
      uint32_t a2 = clib_net_to_host_u32 (addr2->ip4.as_u32);
      uint32_t mask0 = 0xffffffff - ((1 << (32 - prefixlen)) - 1);
      return (a1 & mask0) == a2;
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
      if (!fa_acl_match_addr
	  (&pkt_5tuple->addr[1], &r->dst, r->dst_prefixlen, is_ip6))
	continue;

#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d pkt dst addr %U match rule addr %U/%d",
	 acl_index, i, format_ip46_address, &pkt_5tuple->addr[1],
	 r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4, format_ip46_address,
         &r->dst, r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4,
	 r->dst_prefixlen);
#endif

      if (!fa_acl_match_addr
	  (&pkt_5tuple->addr[0], &r->src, r->src_prefixlen, is_ip6))
	continue;

#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d pkt src addr %U match rule addr %U/%d",
	 acl_index, i, format_ip46_address, &pkt_5tuple->addr[0],
	 r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4, format_ip46_address,
         &r->src, r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4,
	 r->src_prefixlen);
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d trying to match pkt proto %d with rule %d",
	 acl_index, i, pkt_5tuple->l4.proto, r->proto);
#endif
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

always_inline void
acl_fill_5tuple (acl_main_t * am, u32 lc_index0, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_t * p5tuple_pkt0)
{
  /* IP4 and IP6 protocol numbers of ICMP */
  static u8 icmp_protos_v4v6[] = { IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMP6 };

  int l3_offset0;
  int l4_offset0;
  u16 ports0[2];
  u16 proto0;

  fa_packet_info_t pkt0 = { 0 };
  pkt0.lc_index = lc_index0;
  pkt0.is_ip6 = is_ip6;
  pkt0.mask_type_index_lsb = ~0;

  p5tuple_pkt0->kv.value = 0ULL;

  if (is_l2_path)
    {
      l3_offset0 = ethernet_buffer_header_size(b0);
    }
  else
    {
      if (is_input)
        l3_offset0 = 0;
      else
        l3_offset0 = vnet_buffer(b0)->ip.save_rewrite_length;
    }

  /* key[0..3] contains src/dst address and is cleared/set below */
  /* Remainder of the key and per-packet non-key data */
  // p5tuple_pkt0->kv.key[4] = 0;
  // p5tuple_pkt0->kv.value = 0;
  // p5tuple_pkt0->pkt.is_ip6 = is_ip6;

  if (is_ip6)
    {
      clib_memcpy (&p5tuple_pkt0->addr,
		   get_ptr_to_offset (b0,
				      offsetof (ip6_header_t,
						src_address) + l3_offset0),
		   sizeof (p5tuple_pkt0->addr));
      proto0 =
	*(u8 *) get_ptr_to_offset (b0,
				   offsetof (ip6_header_t,
					     protocol) + l3_offset0);
      l4_offset0 = l3_offset0 + sizeof (ip6_header_t);

      /* IP6 EH handling is here, increment l4_offset if needs to, update the proto */
      int need_skip_eh0 = clib_bitmap_get (am->fa_ipv6_known_eh_bitmap, proto0);
      if (PREDICT_FALSE (need_skip_eh0))
	{
	  while (need_skip_eh0 && offset_within_packet (b0, l4_offset0))
	    {
	      /* Fragment header needs special handling */
	      if (PREDICT_FALSE(ACL_EH_FRAGMENT == proto0))
	        {
	          proto0 = *(u8 *) get_ptr_to_offset (b0, l4_offset0);
		  u16 frag_offset0;
		  clib_memcpy (&frag_offset0, get_ptr_to_offset (b0, 2 + l4_offset0), sizeof(frag_offset0));
		  frag_offset0 = clib_net_to_host_u16(frag_offset0) >> 3;
		  if (frag_offset0)
		    {
                      p5tuple_pkt0->pkt.is_nonfirst_fragment = 1;
                      /* invalidate L4 offset so we don't try to find L4 info */
                      l4_offset0 += b0->current_length;
		    }
		  else
		    {
		      /* First fragment: skip the frag header and move on. */
		      l4_offset0 += 8;
		    }
		}
              else
                {
	          u8 nwords0 = *(u8 *) get_ptr_to_offset (b0, 1 + l4_offset0);
	          proto0 = *(u8 *) get_ptr_to_offset (b0, l4_offset0);
	          l4_offset0 += 8 * (1 + (u16) nwords0);
                }
	      need_skip_eh0 =
		clib_bitmap_get (am->fa_ipv6_known_eh_bitmap, proto0);
	    }
	}
    }
  else
    {
      /*
      p5tuple_pkt->kv.key[0] = 0;
      p5tuple_pkt->kv.key[1] = 0;
      p5tuple_pkt->kv.key[2] = 0;
      p5tuple_pkt->kv.key[3] = 0;
      */
      ip46_address_mask_ip4(&p5tuple_pkt0->addr[0]);
      ip46_address_mask_ip4(&p5tuple_pkt0->addr[1]);
      clib_memcpy (&p5tuple_pkt0->addr[0].ip4,
		   get_ptr_to_offset (b0,
				      offsetof (ip4_header_t,
						src_address) + l3_offset0),
		   sizeof (p5tuple_pkt0->addr[0].ip4));
      clib_memcpy (&p5tuple_pkt0->addr[1].ip4,
		   get_ptr_to_offset (b0,
				      offsetof (ip4_header_t,
						dst_address) + l3_offset0),
		   sizeof (p5tuple_pkt0->addr[1].ip4));
      proto0 =
	*(u8 *) get_ptr_to_offset (b0,
				   offsetof (ip4_header_t,
					     protocol) + l3_offset0);
      l4_offset0 = l3_offset0 + sizeof (ip4_header_t);
      u16 flags_and_fragment_offset0;
      clib_memcpy (&flags_and_fragment_offset0,
                   get_ptr_to_offset (b0,
                                      offsetof (ip4_header_t,
                                                flags_and_fragment_offset)) + l3_offset0,
                                                sizeof(flags_and_fragment_offset0));
      flags_and_fragment_offset0 = clib_net_to_host_u16 (flags_and_fragment_offset0);

      /* non-initial fragments have non-zero offset */
      if ((PREDICT_FALSE(0xfff & flags_and_fragment_offset0)))
        {
          p5tuple_pkt0->pkt.is_nonfirst_fragment = 1;
          /* invalidate L4 offset so we don't try to find L4 info */
          l4_offset0 += b0->current_length;
        }

    }
  p5tuple_pkt0->l4.proto = proto0;
  if (PREDICT_TRUE (offset_within_packet (b0, l4_offset0)))
    {
      vnet_buffer (b0)->l4_hdr_offset = l4_offset0;
      pkt0.l4_valid = 1;
      if (PREDICT_FALSE(icmp_protos_v4v6[is_ip6] == proto0))
	{
	  /* type */
	  p5tuple_pkt0->l4.port[0] =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset0 + offsetof (icmp46_header_t,
							     type));
	  /* code */
	  p5tuple_pkt0->l4.port[1] =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset0 + offsetof (icmp46_header_t,
							     code));
	}
      else if ((IP_PROTOCOL_TCP == proto0) || (IP_PROTOCOL_UDP == proto0))
	{
	  clib_memcpy (&ports0,
		       get_ptr_to_offset (b0,
					  l4_offset0 + offsetof (tcp_header_t,
								src_port)),
		       sizeof (ports0));
	  p5tuple_pkt0->l4.port[0] = clib_net_to_host_u16 (ports0[0]);
	  p5tuple_pkt0->l4.port[1] = clib_net_to_host_u16 (ports0[1]);

	  p5tuple_pkt0->pkt.tcp_flags =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset0 + offsetof (tcp_header_t,
							     flags));
	  p5tuple_pkt0->pkt.tcp_flags_valid = (proto0 == IP_PROTOCOL_TCP);
	}
    }
  p5tuple_pkt0->pkt.as_u64  = pkt0.as_u64;
}




always_inline void
acl_plugin_fill_5tuple_inline (u32 lc_index0, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt)
{
  acl_main_t *am = p_acl_main;
  acl_fill_5tuple(am, lc_index0, b0, is_ip6, is_input, is_l2_path, (fa_5tuple_t *)p5tuple_pkt);

}

#ifdef TO_DELETE

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
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning("ACL_FA_NODE_DBG acl %d rule %d tag %s", acl_index, i, a->tag);
#endif
      if (is_ip6 != r->is_ipv6)
	{
	  continue;
	}
      if (!fa_acl_match_addr
	  (&pkt_5tuple->addr[1], &r->dst, r->dst_prefixlen, is_ip6))
	continue;

#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d pkt dst addr %U match rule addr %U/%d",
	 acl_index, i, format_ip46_address, &pkt_5tuple->addr[1],
	 r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4, format_ip46_address,
         &r->dst, r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4,
	 r->dst_prefixlen);
#endif

      if (!fa_acl_match_addr
	  (&pkt_5tuple->addr[0], &r->src, r->src_prefixlen, is_ip6))
	continue;

#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d pkt src addr %U match rule addr %U/%d",
	 acl_index, i, format_ip46_address, &pkt_5tuple->addr[0],
	 r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4, format_ip46_address,
         &r->src, r->is_ipv6 ? IP46_TYPE_IP6: IP46_TYPE_IP4,
	 r->src_prefixlen);
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d trying to match pkt proto %d with rule %d",
	 acl_index, i, pkt_5tuple->l4.proto, r->proto);
#endif
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

#endif // TO_DELETE

always_inline int
acl_plugin_single_acl_match_5tuple (u32 acl_index, fa_5tuple_t * pkt_5tuple,
		  int is_ip6, u8 * r_action, u32 * r_acl_match_p,
		  u32 * r_rule_match_p, u32 * trace_bitmap)
{
  acl_main_t * am = p_acl_main;
  return single_acl_match_5tuple(am, acl_index, pkt_5tuple, is_ip6, r_action,
                                 r_acl_match_p, r_rule_match_p, trace_bitmap);
}

always_inline int
linear_multi_acl_match_5tuple (u32 lc_index, fa_5tuple_t * pkt_5tuple, 
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
tm_single_rule_match_5tuple (acl_rule_t *r, 
		fa_5tuple_t *pkt_5tuple)
{

	if (pkt_5tuple->pkt.is_ip6 != r->is_ipv6)
	{
		return 0;
	}
	if (!fa_acl_match_addr
			(&pkt_5tuple->addr[1], &r->dst, r->dst_prefixlen, pkt_5tuple->pkt.is_ip6))
		return 0;


	if (!fa_acl_match_addr
			(&pkt_5tuple->addr[0], &r->src, r->src_prefixlen, pkt_5tuple->pkt.is_ip6))
		return 0;

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

always_inline int
tm_single_ace_match_5tuple (acl_main_t *am, u32 acl_index, u32 ace_index, 
		fa_5tuple_t *pkt_5tuple)
{
	acl_list_t *a = &am->acls[acl_index];
	acl_rule_t *r = &a->rules[ace_index];
        return tm_single_rule_match_5tuple(r, pkt_5tuple);
}





always_inline u32
tm_multi_acl_match_get_applied_ace_index(acl_main_t *am, fa_5tuple_t *match)
{
  clib_bihash_kv_48_8_t kv;
  clib_bihash_kv_48_8_t result;
  // fa_5tuple_t *kv_key = (fa_5tuple_t *)kv.key;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  u64 *pmatch = (u64 *)match;
  u64 *pmask;
  u64 *pkey;
  int mask_type_index, order_index;
  u32 curr_match_index = (~0 -1);


//Added by Valerio
#ifdef VALE_ELOG_ACL

  u32 cand_ord_index=0; 
  u32 count_htaccess=0; 
  u32 count_col=0;

#endif


  u32 lc_index = match->pkt.lc_index;
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);

  hash_applied_mask_info_t **hash_applied_mask_pool = vec_elt_at_index(am->hash_applied_mask_pool_by_lc_index, lc_index);

  hash_applied_mask_info_t *minfo;

  DBG("TRYING TO MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
	       pmatch[0], pmatch[1], pmatch[2], pmatch[3], pmatch[4], pmatch[5]);

  //for(mask_type_index=0; mask_type_index < pool_len(am->ace_mask_type_pool); mask_type_index++) {
  for(order_index = 0; order_index < vec_len((*hash_applied_mask_pool)); order_index++) {

    //minfo = am->hash_applied_mask_pool[order_index]; 
    minfo = vec_elt_at_index((*hash_applied_mask_pool), order_index); 


    if (minfo->max_priority > (curr_match_index+1)) {
      /* Index in this partition are greater than our candidate, Avoid trying to match! */
	    break;
    }

    mask_type_index = minfo->mask_type_index; 
    ace_mask_type_entry_t *mte = vec_elt_at_index(am->ace_mask_type_pool, mask_type_index);

    pmatch = (u64 *)match;
    pmask = (u64 *)&mte->mask;
    pkey = (u64 *)kv.key;
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

    fa_packet_info_t last_search;
    last_search.as_u64 = *pmatch++ & *pmask++;
    last_search.mask_type_index_lsb = mask_type_index;
    *pkey++ = last_search.as_u64;

//Added by Valerio
#ifdef VALE_ELOG_ACL
  count_htaccess++; 
#endif
    DBG("        KEY %3d: %016llx %016llx %016llx %016llx %016llx %016llx", mask_type_index,
		kv.key[0], kv.key[1], kv.key[2], kv.key[3], kv.key[4], kv.key[5]);
    //int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
    int res = clib_bihash_search_inline_2_48_8 (&am->acl_lookup_hash, &kv, &result);

#ifdef OLD_STYLE
    if (res == 0) {
	    //check collisions
	    u32 curr_index = result_val->applied_entry_index;
	    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces),curr_index);
	    u64 collisions = pae->collision + 1;
	    int i=0;
	    for(i=0; i < collisions; i++){
		    pae = vec_elt_at_index((*applied_hash_aces),curr_index);
		    if(curr_index < curr_match_index){
			    //Added by Valerio
#ifdef VALE_ELOG_ACL
			    if(collisions > 1) count_col= (count_col + 1);
#endif
			    if(tm_single_ace_match_5tuple(am, pae->acl_index, pae->ace_index, match)){
				    curr_match_index = curr_index;
#ifdef VALE_ELOG_ACL
				    cand_ord_index = order_index;
#endif
			    }
		    }
		    curr_index = pae->next_applied_entry_index;
	    }
    }
#else
    if (res == 0) {
	    //check collisions
	    u32 curr_index = result_val->applied_entry_index;
	    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces),curr_index);
            collision_match_rule_t *crs = pae->colliding_rules;
	    int i;
	    for(i=0; i < vec_len(crs); i++){
		    if(crs[i].applied_entry_index >= curr_match_index){
                      continue;
                    }
#ifdef VALE_ELOG_ACL
		    if(collisions > 1) count_col= (count_col + 1);
#endif
		    if(tm_single_rule_match_5tuple(&crs[i].rule, match)){
			    curr_match_index = crs[i].applied_entry_index;
#ifdef VALE_ELOG_ACL
			    cand_ord_index = order_index;
#endif
		    }
	    }
    }

#endif
  }

  //Added by Valerio
#ifdef VALE_ELOG_ACL
  /*Log event*/
  // Replace and/or change with u32 Vector Size inside the stuct. Also change the %ll
  ELOG_TYPE_DECLARE (e) = {
	  .format = "ACE: %d, Order_i = %d, HT_a: %d, Col: %d ",
	  .format_args = "i4i4i4i4",
  };
  struct {u32 ace_i; u32 cand_ord_index; u32 ht_ac; u32 col;} *ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  //number of access in ht
  ed->ht_ac = count_htaccess;
  //number of collisions
  ed->col = count_col;
  ed->cand_ord_index = cand_ord_index;
  if (curr_match_index < vec_len((*applied_hash_aces))) {
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), curr_match_index);
    ed->ace_i = pae->ace_index;
}
  /*End of Log event*/

#endif


  DBG("MATCH-RESULT: %d", curr_match_index);
  return curr_match_index;
}


always_inline int
hash_multi_acl_match_5tuple (u32 lc_index, fa_5tuple_t * pkt_5tuple,
                       int is_ip6, u8 *action, u32 *acl_pos_p, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
  u32 match_index = tm_multi_acl_match_get_applied_ace_index(am, pkt_5tuple);

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

/*
static u8 *
format_fa_5tuple_1 (u8 * s, va_list * args)
{
  fa_5tuple_t *p5t = va_arg (*args, fa_5tuple_t *);

  return format(s, "lc_index %d (lsb16 of sw_if_index %d) l3 %s%s %U -> %U"
                   " l4 proto %d l4_valid %d port %d -> %d tcp flags (%s) %02x rsvd %x",
                p5t->pkt.lc_index, p5t->l4.lsb_of_sw_if_index, p5t->pkt.is_ip6 ? "ip6" : "ip4",
                p5t->pkt.is_nonfirst_fragment ? " non-initial fragment" : "",
                format_ip46_address, &p5t->addr[0], p5t->pkt.is_ip6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
                format_ip46_address, &p5t->addr[1], p5t->pkt.is_ip6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
                p5t->l4.proto, p5t->pkt.l4_valid,
                p5t->l4.port[0], p5t->l4.port[1],
                p5t->pkt.tcp_flags_valid ? "valid": "invalid",
                p5t->pkt.tcp_flags,
                p5t->pkt.flags_reserved);
}
*/


always_inline int
acl_tmhash_match_begin(acl_main_t *am, fa_5tuple_t * pkt_5tuple_internal, hash_lookup_wip_t *wip, int is_dummy)
{
  u32 lc_index = pkt_5tuple_internal->pkt.lc_index;
  wip->applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
  wip->hash_applied_mask_pool = vec_elt_at_index(am->hash_applied_mask_pool_by_lc_index, lc_index);
  wip->curr_match_index = (~0 -1);
  wip->order_index = 0;
  wip->is_dummy = is_dummy;
  return !is_dummy;
  // clib_warning("XXXMATCH - BEGIN, lc_index: %d, 5tuple: %U", lc_index, format_fa_5tuple_1, pkt_5tuple_internal);
}

always_inline int
acl_tmhash_match_hash_and_prefetch(acl_main_t *am, fa_5tuple_t * pkt_5tuple_internal, hash_lookup_wip_t *wip)
{
  if (PREDICT_FALSE(wip->is_dummy)) {
    return(1);
  }
  if (PREDICT_FALSE(wip->order_index >= vec_len((*wip->hash_applied_mask_pool)))) {
    return(0);
  }
  hash_applied_mask_info_t *minfo = vec_elt_at_index((*wip->hash_applied_mask_pool), wip->order_index);
  if (PREDICT_FALSE(minfo->max_priority > (wip->curr_match_index+1))) {
    /* make the lookup terminate */
    wip->order_index = vec_len((*wip->hash_applied_mask_pool));
    // break; 
    return(0);
  }
  int mask_type_index = minfo->mask_type_index;
  ace_mask_type_entry_t *mte = vec_elt_at_index(am->ace_mask_type_pool, mask_type_index);
  // clib_warning("XXXMATCH: wip: %d curr_match_index: %d, order_index: %d mask_type_index: %d", wip->id, wip->curr_match_index, wip->order_index, mask_type_index);

  u64 *pmatch = (u64 *) pkt_5tuple_internal->kv.key;
  u64 *pmask = (u64 *) &mte->mask;
  u64 *pkey = (u64 *) wip->kv.key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;

  fa_packet_info_t last_search;
  last_search.as_u64 = *pmatch++ & *pmask++;
  last_search.mask_type_index_lsb = mask_type_index;
  *pkey++ = last_search.as_u64;
  u64 hash = clib_bihash_hash_48_8(&wip->kv);
  clib_bihash_prefetch_bucket_48_8(&am->acl_lookup_hash, hash);
  wip->hash = hash;
  // clib_warning("XXXMATCH - HASH wip: %d hash: %016llx", wip->id, hash);
  return 1;
}

always_inline void
acl_tmhash_lookup_hash(acl_main_t *am, fa_5tuple_t * pkt_5tuple_internal, hash_lookup_wip_t *wip)
{
  if (PREDICT_FALSE(wip->is_dummy)) {
    return;
  }
  clib_bihash_kv_48_8_t result;
  int hash_lookup_res = clib_bihash_search_inline_2_with_hash_48_8(&am->acl_lookup_hash, wip->hash, &wip->kv, &result);
  if (PREDICT_FALSE(hash_lookup_res == 0)) {
    hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
    u32 curr_index = result_val->applied_entry_index;
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*wip->applied_hash_aces),curr_index);
    // collision_match_rule_t *crs = pae->colliding_rules;
    // clib_warning("XXXMATCH - HASH LOOKUP OK wip: %d hash: %016llx", wip->id, wip->hash);
    CLIB_PREFETCH (pae, CLIB_CACHE_LINE_BYTES, LOAD);
    wip->hash_match_pae = pae;
  } else {
    // clib_warning("XXXMATCH - HASH LOOKUP FAIL wip: %d hash: %016llx", wip->id, wip->hash);
  }
  wip->hash_lookup_res = hash_lookup_res;
}

always_inline void
acl_tmhash_check_collisions(acl_main_t *am, fa_5tuple_t * pkt_5tuple_internal, hash_lookup_wip_t *wip)
{
  if (PREDICT_FALSE(wip->is_dummy)) {
    return;
  }
  // clib_warning("XXXMATCH - check collisions - wip: %d hash lookup res: %d", wip->id, wip->hash_lookup_res);
  if (PREDICT_FALSE(wip->hash_lookup_res == 0)) {
    applied_hash_ace_entry_t *pae = wip->hash_match_pae;
    collision_match_rule_t *crs = pae->colliding_rules;
    int i;
    for(i=0; i < vec_len(crs); i++){
      if(crs[i].applied_entry_index >= wip->curr_match_index){
        // clib_warning("XXXMATCH - wip: %d collision applied entry index %d bigger than current %d, skip", wip->id, crs[i].applied_entry_index, wip->curr_match_index);
        continue;
      }
      if(tm_single_rule_match_5tuple(&crs[i].rule, pkt_5tuple_internal)){
        wip->curr_match_index = crs[i].applied_entry_index;
        // clib_warning("XXXMATCH - wip: %d new curr match index: %d", wip->id, wip->curr_match_index);
      }
    }
  }
  wip->order_index++; /* move to the next mask type */ 
}

always_inline int
acl_tmhash_check_finalize(acl_main_t *am, fa_5tuple_t * pkt_5tuple_internal, 
                          hash_lookup_wip_t *wip, u8 * r_action, u32 * r_acl_pos_p, u32 * r_acl_match_p, u32 * r_rule_match_p)
{
  int rv = !wip->is_dummy;

  if (PREDICT_FALSE(wip->is_dummy)) {
    *r_action = 0;
    return rv;
  }
  wip->is_dummy = 2;
  if (PREDICT_FALSE(wip->curr_match_index < vec_len((*wip->applied_hash_aces)))) {
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*wip->applied_hash_aces), wip->curr_match_index);
    pae->hitcount++;
    *r_acl_pos_p = pae->acl_position;
    *r_acl_match_p = pae->acl_index;
    *r_rule_match_p = pae->ace_index;
    *r_action = pae->action;
    // clib_warning("XXXMATCH: wip: %d PAE OK curr_match_index: %d, order_index: %d", wip->id, wip->curr_match_index, wip->order_index);
  } else {
    *r_action = 0;
    // clib_warning("XXXMATCH: wip: %d PAE NOK curr_match_index: %d, order_index: %d", wip->id, wip->curr_match_index, wip->order_index);
  }
  return rv;
}


always_inline int
acl_plugin_match_5tuple_inline (u32 lc_index,
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
       * For the non-initial fragments we can not build the key with ports,
       * thus the tuplemerge algorithm as is will give incorrect result.
       * Fallback to linear search in that case.
       *
       * TM can be made to work by never using ports as the key, but
       * it feels like potential performance impact on non-fragments
       * makes it a strategy not worth pursuing.
       *
       * Another option is to have a totally separate lookup for fragments but it looks like a bit of an overkill...
       */

      return linear_multi_acl_match_5tuple(lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    } else {
      return hash_multi_acl_match_5tuple(lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    }
  } else {
    return linear_multi_acl_match_5tuple(lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
  }
}

#endif
