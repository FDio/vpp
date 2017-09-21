/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <stddef.h>
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <acl/acl.h>
#include <vppinfra/bihash_40_8.h>

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include "fa_node.h"
#include "hash_lookup.h"

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 match_acl_in_index;
  u32 match_rule_index;
  u64 packet_info[6];
  u32 trace_bitmap;
  u8 action;
} acl_fa_trace_t;

/* packet trace format function */
static u8 *
format_acl_fa_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl_fa_trace_t *t = va_arg (*args, acl_fa_trace_t *);

  s =
    format (s,
	    "acl-plugin: sw_if_index %d, next index %d, action: %d, match: acl %d rule %d trace_bits %08x\n"
	    "  pkt info %016llx %016llx %016llx %016llx %016llx %016llx",
	    t->sw_if_index, t->next_index, t->action, t->match_acl_in_index,
	    t->match_rule_index, t->trace_bitmap,
	    t->packet_info[0], t->packet_info[1], t->packet_info[2],
	    t->packet_info[3], t->packet_info[4], t->packet_info[5]);
  return s;
}

/* *INDENT-OFF* */
#define foreach_acl_fa_error \
_(ACL_DROP, "ACL deny packets")  \
_(ACL_PERMIT, "ACL permit packets")  \
_(ACL_NEW_SESSION, "new sessions added") \
_(ACL_EXIST_SESSION, "existing session packets") \
_(ACL_CHECK, "checked packets") \
_(ACL_RESTART_SESSION_TIMER, "restart session timer") \
_(ACL_TOO_MANY_SESSIONS, "too many sessions to add new") \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_ERROR_##sym,
  foreach_acl_fa_error
#undef _
    ACL_FA_N_ERROR,
} acl_fa_error_t;

static char *acl_fa_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_fa_error
#undef _
};
/* *INDENT-ON* */

static void *
get_ptr_to_offset (vlib_buffer_t * b0, int offset)
{
  u8 *p = vlib_buffer_get_current (b0) + offset;
  return p;
}


static int
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
      uint32_t a1 = ntohl (addr1->ip4.as_u32);
      uint32_t a2 = ntohl (addr2->ip4.as_u32);
      uint32_t mask0 = 0xffffffff - ((1 << (32 - prefixlen)) - 1);
      return (a1 & mask0) == a2;
    }
}

static int
fa_acl_match_port (u16 port, u16 port_first, u16 port_last, int is_ip6)
{
  return ((port >= port_first) && (port <= port_last));
}

int
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
	 IP46_TYPE_ANY, format_ip46_address, &r->dst, IP46_TYPE_ANY,
	 r->dst_prefixlen);
#endif

      if (!fa_acl_match_addr
	  (&pkt_5tuple->addr[0], &r->src, r->src_prefixlen, is_ip6))
	continue;

#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning
	("ACL_FA_NODE_DBG acl %d rule %d pkt src addr %U match rule addr %U/%d",
	 acl_index, i, format_ip46_address, &pkt_5tuple->addr[0],
	 IP46_TYPE_ANY, format_ip46_address, &r->src, IP46_TYPE_ANY,
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

static u8
linear_multi_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
		       int is_ip6, int is_input, u32 * acl_match_p,
		       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = &acl_main;
  int i;
  u32 *acl_vector;
  u8 action = 0;

  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
      acl_vector = am->input_acl_vec_by_sw_if_index[sw_if_index];
    }
  else
    {
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
      acl_vector = am->output_acl_vec_by_sw_if_index[sw_if_index];
    }
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
	  return action;
	}
    }
  if (vec_len (acl_vector) > 0)
    {
      /* If there are ACLs and none matched, deny by default */
      return 0;
    }
#ifdef FA_NODE_VERBOSE_DEBUG
  clib_warning ("ACL_FA_NODE_DBG: No ACL on sw_if_index %d", sw_if_index);
#endif
  /* Deny by default. If there are no ACLs defined we should not be here. */
  return 0;
}

static u8
multi_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
                       int is_ip6, int is_input, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = &acl_main;
  if (am->use_hash_acl_matching) {
    return hash_multi_acl_match_5tuple(sw_if_index, pkt_5tuple, is_l2, is_ip6,
                                 is_input, acl_match_p, rule_match_p, trace_bitmap);
  } else {
    return linear_multi_acl_match_5tuple(sw_if_index, pkt_5tuple, is_l2, is_ip6,
                                 is_input, acl_match_p, rule_match_p, trace_bitmap);
  }
}

always_inline int
offset_within_packet (vlib_buffer_t * b0, int offset)
{
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset <= (b0->current_length - 8));
}

always_inline void
acl_fill_5tuple_and_session_key (acl_main_t * am, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_t * p5tuple_pkt, fa_5tuple_t * p5tuple_sess)
{
  int sess_src_index = is_input ? 0 : 1;
  int sess_dst_index = is_input ? 1 : 0;
  int l3_offset = ethernet_buffer_header_size(b0);
  int l4_offset;
  u16 ports[2];
  u16 proto;
  /* IP4 and IP6 protocol numbers of ICMP */
  static u8 icmp_protos[] = { IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMP6 };

  if (is_input && !(is_l2_path))
    {
      l3_offset = 0;
    }

  /* key[0..3] contains src/dst address and is cleared/set below */
  /* Remainder of the key and per-packet non-key data */
  p5tuple_pkt->kv.key[4] = 0;
  p5tuple_pkt->kv.value = 0;
  /* clean up the session key L4 */
  p5tuple_sess->l4.as_u64 = 0;

  if (is_ip6)
    {
      clib_memcpy (&p5tuple_pkt->addr,
		   get_ptr_to_offset (b0,
				      offsetof (ip6_header_t,
						src_address) + l3_offset),
		   sizeof (p5tuple_pkt->addr));
      /* fill in the session key addresses appropriately */
      p5tuple_sess->addr[sess_src_index] = p5tuple_pkt->addr[0];
      p5tuple_sess->addr[sess_dst_index] = p5tuple_pkt->addr[1];

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
		  frag_offset = ntohs(frag_offset) >> 3;
		  if (frag_offset)
		    {
                      p5tuple_pkt->pkt.is_nonfirst_fragment = 1;
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
      p5tuple_pkt->kv.key[0] = 0;
      p5tuple_pkt->kv.key[1] = 0;
      p5tuple_pkt->kv.key[2] = 0;
      p5tuple_pkt->kv.key[3] = 0;

      p5tuple_sess->kv.key[0] = 0;
      p5tuple_sess->kv.key[1] = 0;
      p5tuple_sess->kv.key[2] = 0;
      p5tuple_sess->kv.key[3] = 0;

      u32 *p_addr = get_ptr_to_offset (b0, offsetof (ip4_header_t, src_address) + l3_offset);
      /*
      p5tuple_pkt->addr[0].ip4.as_u32 = *(u32 *) get_ptr_to_offset (b0, offsetof (ip4_header_t, src_address) + l3_offset);
      p5tuple_pkt->addr[1].ip4.as_u32 = *(u32 *) get_ptr_to_offset (b0, offsetof (ip4_header_t, dst_address) + l3_offset);
      */
      p5tuple_sess->addr[sess_src_index].ip4.as_u32 = p5tuple_pkt->addr[0].ip4.as_u32 = *p_addr++;
      p5tuple_sess->addr[sess_dst_index].ip4.as_u32 = p5tuple_pkt->addr[1].ip4.as_u32 = *p_addr;
      proto =
	*(u8 *) get_ptr_to_offset (b0,
				   offsetof (ip4_header_t,
					     protocol) + l3_offset);
      l4_offset = l3_offset + sizeof (ip4_header_t);
      u16 flags_and_fragment_offset;
      flags_and_fragment_offset = *(u16 *) get_ptr_to_offset (b0, offsetof (ip4_header_t, flags_and_fragment_offset) + l3_offset);
      flags_and_fragment_offset = ntohs (flags_and_fragment_offset);

      /* non-initial fragments have non-zero offset */
      if ((PREDICT_FALSE(0xfff & flags_and_fragment_offset)))
        {
          p5tuple_pkt->pkt.is_nonfirst_fragment = 1;
          /* invalidate L4 offset so we don't try to find L4 info */
          l4_offset += b0->current_length;
        }

    }

  p5tuple_sess->l4.proto = p5tuple_pkt->l4.proto = proto;
  if (PREDICT_TRUE (offset_within_packet (b0, l4_offset)))
    {
      p5tuple_pkt->pkt.l4_valid = 1;
      if (icmp_protos[is_ip6] == proto)
	{
	  /* type */
	  p5tuple_pkt->l4.port[0] =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset + offsetof (icmp46_header_t,
							     type));
	  /* code */
	  p5tuple_pkt->l4.port[1] =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset + offsetof (icmp46_header_t,
							     code));
	}
      else if ((IPPROTO_TCP == proto) || (IPPROTO_UDP == proto))
	{
	  clib_memcpy (&ports,
		       get_ptr_to_offset (b0,
					  l4_offset + offsetof (tcp_header_t,
								src_port)),
		       sizeof (ports));
	  p5tuple_pkt->l4.port[0] = ntohs (ports[0]);
	  p5tuple_pkt->l4.port[1] = ntohs (ports[1]);

	  p5tuple_pkt->pkt.tcp_flags =
	    *(u8 *) get_ptr_to_offset (b0,
				       l4_offset + offsetof (tcp_header_t,
							     flags));
	  p5tuple_pkt->pkt.tcp_flags_valid = (proto == IPPROTO_TCP);
	}
      p5tuple_sess->l4.port[sess_src_index] = p5tuple_pkt->l4.port[0];
      p5tuple_sess->l4.port[sess_dst_index] = p5tuple_pkt->l4.port[1];

      /*
       * FIXME: rather than the above conditional, here could
       * be a nice generic mechanism to extract two L4 values:
       *
       * have a per-protocol array of 4 elements like this:
       *   u8 offset; to take the byte from, off L4 header
       *   u8 mask; to mask it with, before storing
       *
       * this way we can describe UDP, TCP and ICMP[46] semantics,
       * and add a sort of FPM-type behavior for other protocols.
       *
       * Of course, is it faster ? and is it needed ?
       *
       */
    }
}


/* Session keys match the packets received, and mirror the packets sent */
/*
static void
acl_make_5tuple_session_key (int is_input, fa_5tuple_t * p5tuple_pkt,
			     fa_5tuple_t * p5tuple_sess)
{
  int src_index = is_input ? 0 : 1;
  int dst_index = is_input ? 1 : 0;
  p5tuple_sess->addr[src_index] = p5tuple_pkt->addr[0];
  p5tuple_sess->addr[dst_index] = p5tuple_pkt->addr[1];
  p5tuple_sess->l4.as_u64 = p5tuple_pkt->l4.as_u64;
  p5tuple_sess->l4.port[src_index] = p5tuple_pkt->l4.port[0];
  p5tuple_sess->l4.port[dst_index] = p5tuple_pkt->l4.port[1];
}
*/


static int
acl_fa_ifc_has_sessions (acl_main_t * am, int sw_if_index0)
{
  return am->fa_sessions_hash_is_initialized;
}

static int
acl_fa_ifc_has_in_acl (acl_main_t * am, int sw_if_index0)
{
  int it_has = clib_bitmap_get (am->fa_in_acl_on_sw_if_index, sw_if_index0);
  return it_has;
}

static int
acl_fa_ifc_has_out_acl (acl_main_t * am, int sw_if_index0)
{
  int it_has = clib_bitmap_get (am->fa_out_acl_on_sw_if_index, sw_if_index0);
  return it_has;
}


static int
fa_session_get_timeout_type (acl_main_t * am, fa_session_t * sess)
{
  u16 masked_flags = 0;
      /* seen both SYNs and ACKs but not FINs means we are in establshed state */
      masked_flags = sess->tcp_flags_seen.as_u16 & ((TCP_FLAGS_RSTFINACKSYN << 8) +
				   TCP_FLAGS_RSTFINACKSYN);
  switch (sess->info.l4.proto)
    {
    case IPPROTO_TCP:
      if (((TCP_FLAGS_ACKSYN << 8) + TCP_FLAGS_ACKSYN) == masked_flags)
	{
	  return ACL_TIMEOUT_TCP_IDLE;
	}
      else
	{
	  return ACL_TIMEOUT_TCP_TRANSIENT;
	}
      break;
    case IPPROTO_UDP:
      return ACL_TIMEOUT_UDP_IDLE;
      break;
    default:
      return ACL_TIMEOUT_UDP_IDLE;
    }
}


static u64
fa_session_get_shortest_timeout(acl_main_t * am)
{
  int timeout_type;
  u64 timeout = ~0LL;
  for(timeout_type = 0; timeout_type < ACL_N_TIMEOUTS; timeout_type++) {
    if (timeout > am->session_timeout_sec[timeout_type]) {
      timeout = am->session_timeout_sec[timeout_type];
    }
  }
  return timeout;
}

/*
 * Get the timeout of the session in a list since its enqueue time.
 */

static u64
fa_session_get_list_timeout (acl_main_t * am, fa_session_t * sess)
{
  u64 timeout = am->vlib_main->clib_time.clocks_per_second;
  /*
   * we have the shortest possible timeout type in all the lists
   * (see README-multicore for the rationale)
   */
  timeout *= fa_session_get_shortest_timeout(am);
  return timeout;
}

/*
 * Get the idle timeout of a session.
 */

static u64
fa_session_get_timeout (acl_main_t * am, fa_session_t * sess)
{
  u64 timeout = am->vlib_main->clib_time.clocks_per_second;
  int timeout_type = fa_session_get_timeout_type (am, sess);
  timeout *= am->session_timeout_sec[timeout_type];
  return timeout;
}

static void
acl_fa_verify_init_sessions (acl_main_t * am)
{
  if (!am->fa_sessions_hash_is_initialized) {
    u16 wk;
    /* Allocate the per-worker sessions pools */
    for (wk = 0; wk < vec_len (am->per_worker_data); wk++) {
      acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
      pool_alloc_aligned(pw->fa_sessions_pool, am->fa_conn_table_max_entries, CLIB_CACHE_LINE_BYTES);
    }

    /* ... and the interface session hash table */
    BV (clib_bihash_init) (&am->fa_sessions_hash,
			 "ACL plugin FA session bihash",
			 am->fa_conn_table_hash_num_buckets,
			 am->fa_conn_table_hash_memory_size);
    am->fa_sessions_hash_is_initialized = 1;
  }
}

static inline fa_session_t *get_session_ptr(acl_main_t *am, u16 thread_index, u32 session_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  fa_session_t *sess = pool_is_free_index (pw->fa_sessions_pool, session_index) ? 0 : pool_elt_at_index(pw->fa_sessions_pool, session_index);
  CLIB_PREFETCH(sess, 2*CLIB_CACHE_LINE_BYTES, STORE);
  return sess;
}

static inline int is_valid_session_ptr(acl_main_t *am, u16 thread_index, fa_session_t *sess)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  return ((sess != 0) && ((sess - pw->fa_sessions_pool) < pool_len(pw->fa_sessions_pool)));
}

static void
acl_fa_conn_list_add_session (acl_main_t * am, fa_full_session_id_t sess_id, u64 now)
{
  fa_session_t *sess = get_session_ptr(am, sess_id.thread_index, sess_id.session_index);
  u8 list_id = fa_session_get_timeout_type(am, sess);
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  /* the retrieved session thread index must be necessarily the same as the one in the key */
  ASSERT (sess->thread_index == sess_id.thread_index);
  /* the retrieved session thread index must be the same as current thread */
  ASSERT (sess->thread_index == thread_index);
  sess->link_enqueue_time = now;
  sess->link_list_id = list_id;
  sess->link_next_idx = ~0;
  sess->link_prev_idx = pw->fa_conn_list_tail[list_id];
  if (~0 != pw->fa_conn_list_tail[list_id]) {
    fa_session_t *prev_sess = get_session_ptr(am, thread_index, pw->fa_conn_list_tail[list_id]);
    prev_sess->link_next_idx = sess_id.session_index;
    /* We should never try to link with a session on another thread */
    ASSERT(prev_sess->thread_index == sess->thread_index);
  }
  pw->fa_conn_list_tail[list_id] = sess_id.session_index;
  pw->serviced_sw_if_index_bitmap = clib_bitmap_set(pw->serviced_sw_if_index_bitmap, sess->sw_if_index, 1);

  if (~0 == pw->fa_conn_list_head[list_id]) {
    pw->fa_conn_list_head[list_id] = sess_id.session_index;
  }
}

static int
acl_fa_conn_list_delete_session (acl_main_t *am, fa_full_session_id_t sess_id)
{
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  if (thread_index != sess_id.thread_index) {
    /* If another thread attempts to delete the session, fail it. */
#ifdef FA_NODE_VERBOSE_DEBUG
    clib_warning("thread id in key %d != curr thread index, not deleting");
#endif
    return 0;
  }
  fa_session_t *sess = get_session_ptr(am, sess_id.thread_index, sess_id.session_index);
  /* we should never try to delete the session with another thread index */
  ASSERT(sess->thread_index == thread_index);
  if (~0 != sess->link_prev_idx) {
    fa_session_t *prev_sess = get_session_ptr(am, thread_index, sess->link_prev_idx);
    /* the previous session must be in the same list as this one */
    ASSERT(prev_sess->link_list_id == sess->link_list_id);
    prev_sess->link_next_idx = sess->link_next_idx;
  }
  if (~0 != sess->link_next_idx) {
    fa_session_t *next_sess = get_session_ptr(am, thread_index, sess->link_next_idx);
    /* The next session must be in the same list as the one we are deleting */
    ASSERT(next_sess->link_list_id == sess->link_list_id);
    next_sess->link_prev_idx = sess->link_prev_idx;
  }
  if (pw->fa_conn_list_head[sess->link_list_id] == sess_id.session_index) {
    pw->fa_conn_list_head[sess->link_list_id] = sess->link_next_idx;
  }
  if (pw->fa_conn_list_tail[sess->link_list_id] == sess_id.session_index) {
    pw->fa_conn_list_tail[sess->link_list_id] = sess->link_prev_idx;
  }
  return 1;
}

static int
acl_fa_restart_timer_for_session (acl_main_t * am, u64 now, fa_full_session_id_t sess_id)
{
  if (acl_fa_conn_list_delete_session(am, sess_id)) {
    acl_fa_conn_list_add_session(am, sess_id, now);
    return 1;
  } else {
    /*
     * Our thread does not own this connection, so we can not delete
     * The session. To avoid the complicated signaling, we simply
     * pick the list waiting time to be the shortest of the timeouts.
     * This way we do not have to do anything special, and let
     * the regular requeue check take care of everything.
     */
    return 0;
  }
}


static u8
acl_fa_track_session (acl_main_t * am, int is_input, u32 sw_if_index, u64 now,
		      fa_session_t * sess, fa_5tuple_t * pkt_5tuple)
{
  sess->last_active_time = now;
  if (pkt_5tuple->pkt.tcp_flags_valid)
    {
      sess->tcp_flags_seen.as_u8[is_input] |= pkt_5tuple->pkt.tcp_flags;
    }
  return 3;
}


static void
acl_fa_delete_session (acl_main_t * am, u32 sw_if_index, fa_full_session_id_t sess_id)
{
  void *oldheap = clib_mem_set_heap(am->acl_mheap);
  fa_session_t *sess = get_session_ptr(am, sess_id.thread_index, sess_id.session_index);
  ASSERT(sess->thread_index == os_get_thread_index ());
  BV (clib_bihash_add_del) (&am->fa_sessions_hash,
			    &sess->info.kv, 0);
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[sess_id.thread_index];
  pool_put_index (pw->fa_sessions_pool, sess_id.session_index);
  /* Deleting from timer structures not needed,
     as the caller must have dealt with the timers. */
  vec_validate (pw->fa_session_dels_by_sw_if_index, sw_if_index);
  clib_mem_set_heap (oldheap);
  pw->fa_session_dels_by_sw_if_index[sw_if_index]++;
  clib_smp_atomic_add(&am->fa_session_total_dels, 1);
}

static int
acl_fa_can_add_session (acl_main_t * am, int is_input, u32 sw_if_index)
{
  u64 curr_sess_count;
  curr_sess_count = am->fa_session_total_adds - am->fa_session_total_dels;
  return (curr_sess_count < am->fa_conn_table_max_entries);
}

static u64
acl_fa_get_list_head_expiry_time(acl_main_t *am, acl_fa_per_worker_data_t *pw, u64 now, u16 thread_index, int timeout_type)
{
  fa_session_t *sess = get_session_ptr(am, thread_index, pw->fa_conn_list_head[timeout_type]);
  /*
   * We can not check just the index here because inbetween the worker thread might
   * dequeue the connection from the head just as we are about to check it.
   */
  if (!is_valid_session_ptr(am, thread_index, sess)) {
    return ~0LL; // infinity.
  } else {
    u64 timeout_time =
              sess->link_enqueue_time + fa_session_get_list_timeout (am, sess);
    return timeout_time;
  }
}

static int
acl_fa_conn_time_to_check (acl_main_t *am, acl_fa_per_worker_data_t *pw, u64 now, u16 thread_index, u32 session_index)
{
  fa_session_t *sess = get_session_ptr(am, thread_index, session_index);
  u64 timeout_time =
              sess->link_enqueue_time + fa_session_get_list_timeout (am, sess);
  return (timeout_time < now) || (sess->link_enqueue_time <= pw->swipe_end_time);
}

/*
 * see if there are sessions ready to be checked,
 * do the maintenance (requeue or delete), and
 * return the total number of sessions reclaimed.
 */
static int
acl_fa_check_idle_sessions(acl_main_t *am, u16 thread_index, u64 now)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  fa_full_session_id_t fsid;
  fsid.thread_index = thread_index;
  int total_expired = 0;

  {
    u8 tt = 0;
    for(tt = 0; tt < ACL_N_TIMEOUTS; tt++) {
      while((vec_len(pw->expired) < am->fa_max_deleted_sessions_per_interval)
	    && (~0 != pw->fa_conn_list_head[tt])
	    && (acl_fa_conn_time_to_check(am, pw, now, thread_index,
					  pw->fa_conn_list_head[tt]))) {
	fsid.session_index = pw->fa_conn_list_head[tt];
	vec_add1(pw->expired, fsid.session_index);
	acl_fa_conn_list_delete_session(am, fsid);
      }
    }
  }

  u32 *psid = NULL;
  vec_foreach (psid, pw->expired)
  {
    fsid.session_index = *psid;
    if (!pool_is_free_index (pw->fa_sessions_pool, fsid.session_index))
      {
	fa_session_t *sess = get_session_ptr(am, thread_index, fsid.session_index);
	u32 sw_if_index = sess->sw_if_index;
	u64 sess_timeout_time =
	  sess->last_active_time + fa_session_get_timeout (am, sess);
	if ((now < sess_timeout_time) && (0 == clib_bitmap_get(pw->pending_clear_sw_if_index_bitmap, sw_if_index)))
	  {
#ifdef FA_NODE_VERBOSE_DEBUG
	    clib_warning ("ACL_FA_NODE_CLEAN: Restarting timer for session %d",
	       (int) session_index);
#endif
	    /* There was activity on the session, so the idle timeout
	       has not passed. Enqueue for another time period. */

	    acl_fa_conn_list_add_session(am, fsid, now);
	    pw->cnt_session_timer_restarted++;
	  }
	else
	  {
#ifdef FA_NODE_VERBOSE_DEBUG
	    clib_warning ("ACL_FA_NODE_CLEAN: Deleting session %d",
	       (int) session_index);
#endif
	    acl_fa_delete_session (am, sw_if_index, fsid);
	    pw->cnt_deleted_sessions++;
	  }
      }
    else
      {
	pw->cnt_already_deleted_sessions++;
      }
  }
  total_expired = vec_len(pw->expired);
  /* zero out the vector which we have acted on */
  if (pw->expired)
    _vec_len (pw->expired) = 0;
  /* if we were advancing and reached the end
   * (no more sessions to recycle), reset the fast-forward timestamp */

  if (pw->swipe_end_time && 0 == total_expired)
    pw->swipe_end_time = 0;
  return (total_expired);
}

always_inline void
acl_fa_try_recycle_session (acl_main_t * am, int is_input, u16 thread_index, u32 sw_if_index)
{
  /* try to recycle a TCP transient session */
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  u8 timeout_type = ACL_TIMEOUT_TCP_TRANSIENT;
  fa_full_session_id_t sess_id;
  sess_id.session_index = pw->fa_conn_list_head[timeout_type];
  if (~0 != sess_id.session_index) {
    sess_id.thread_index = thread_index;
    acl_fa_conn_list_delete_session(am, sess_id);
    acl_fa_delete_session(am, sw_if_index, sess_id);
  }
}

static fa_session_t *
acl_fa_add_session (acl_main_t * am, int is_input, u32 sw_if_index, u64 now,
		    fa_5tuple_t * p5tuple)
{
  clib_bihash_kv_40_8_t *pkv = &p5tuple->kv;
  clib_bihash_kv_40_8_t kv;
  fa_full_session_id_t f_sess_id;
  uword thread_index = os_get_thread_index();
  void *oldheap = clib_mem_set_heap(am->acl_mheap);
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  f_sess_id.thread_index = thread_index;
  fa_session_t *sess;

  pool_get_aligned (pw->fa_sessions_pool, sess, CLIB_CACHE_LINE_BYTES);
  f_sess_id.session_index = sess - pw->fa_sessions_pool;

  kv.key[0] = pkv->key[0];
  kv.key[1] = pkv->key[1];
  kv.key[2] = pkv->key[2];
  kv.key[3] = pkv->key[3];
  kv.key[4] = pkv->key[4];
  kv.value = f_sess_id.as_u64;

  memcpy (sess, pkv, sizeof (pkv->key));
  sess->last_active_time = now;
  sess->sw_if_index = sw_if_index;
  sess->tcp_flags_seen.as_u16 = 0;
  sess->thread_index = thread_index;
  sess->link_list_id = ~0;
  sess->link_prev_idx = ~0;
  sess->link_next_idx = ~0;



  ASSERT(am->fa_sessions_hash_is_initialized == 1);
  BV (clib_bihash_add_del) (&am->fa_sessions_hash,
			    &kv, 1);
  acl_fa_conn_list_add_session(am, f_sess_id, now);

  vec_validate (pw->fa_session_adds_by_sw_if_index, sw_if_index);
  clib_mem_set_heap (oldheap);
  pw->fa_session_adds_by_sw_if_index[sw_if_index]++;
  clib_smp_atomic_add(&am->fa_session_total_adds, 1);
  return sess;
}

static int
acl_fa_find_session (acl_main_t * am, u32 sw_if_index0, fa_5tuple_t * p5tuple,
		     clib_bihash_kv_40_8_t * pvalue_sess)
{
  return (BV (clib_bihash_search)
	  (&am->fa_sessions_hash, &p5tuple->kv,
	   pvalue_sess) == 0);
}


always_inline uword
acl_fa_node_fn (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame, int is_ip6,
		int is_input, int is_l2_path, u32 * l2_feat_next_node_index,
		vlib_node_registration_t * acl_fa_node)
{
  u32 n_left_from, *from, *to_next;
  acl_fa_next_t next_index;
  u32 pkts_acl_checked = 0;
  u32 pkts_new_session = 0;
  u32 pkts_exist_session = 0;
  u32 pkts_acl_permit = 0;
  u32 pkts_restart_session_timer = 0;
  u32 trace_bitmap = 0;
  acl_main_t *am = &acl_main;
  fa_5tuple_t fa_5tuple, kv_sess;
  clib_bihash_kv_40_8_t value_sess;
  vlib_node_runtime_t *error_node;
  u64 now = clib_cpu_time_now ();
  uword thread_index = os_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  error_node = vlib_node_get_runtime (vm, acl_fa_node->index);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = 0;
	  u8 action = 0;
	  u32 sw_if_index0;
	  int acl_check_needed = 1;
	  u32 match_acl_in_index = ~0;
	  u32 match_rule_index = ~0;
	  u8 error0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_input)
	    sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  else
	    sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

          /*
           * Kick off the prefetch for the next packet
           */
          if (PREDICT_TRUE(n_left_from > 2)) {
            u32 biX;
	    vlib_buffer_t *bX; // future block
            biX = from[2];
            bX = vlib_get_buffer (vm, biX);
            CLIB_PREFETCH(&bX->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
          }
          if (PREDICT_TRUE(n_left_from > 1)) {
            CLIB_PREFETCH(vnet_buffer(vlib_get_buffer(vm, from[1])), 2*CLIB_CACHE_LINE_BYTES, LOAD);
          }

	  /*
	   * Extract the L3/L4 matching info into a 5-tuple structure,
	   * then create a session key whose layout is independent on forward or reverse
	   * direction of the packet.
	   */

	  // acl_fill_5tuple (am, b0, is_ip6, is_input, is_l2_path, &fa_5tuple);
	  acl_fill_5tuple_and_session_key (am, b0, is_ip6, is_input, is_l2_path, &fa_5tuple, &kv_sess);
          fa_5tuple.l4.lsb_of_sw_if_index = sw_if_index0 & 0xffff;
	  // acl_make_5tuple_session_key (is_input, &fa_5tuple, &kv_sess);
	  fa_5tuple.pkt.sw_if_index = sw_if_index0;
          fa_5tuple.pkt.is_ip6 = is_ip6;
          fa_5tuple.pkt.is_input = is_input;
          fa_5tuple.pkt.mask_type_index_lsb = ~0;
#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG: session 5-tuple %016llx %016llx %016llx %016llx %016llx : %016llx",
	     kv_sess.kv.key[0], kv_sess.kv.key[1], kv_sess.kv.key[2],
	     kv_sess.kv.key[3], kv_sess.kv.key[4], kv_sess.kv.value);
	  clib_warning
	    ("ACL_FA_NODE_DBG: packet 5-tuple %016llx %016llx %016llx %016llx %016llx : %016llx",
	     fa_5tuple.kv.key[0], fa_5tuple.kv.key[1], fa_5tuple.kv.key[2],
	     fa_5tuple.kv.key[3], fa_5tuple.kv.key[4], fa_5tuple.kv.value);
#endif

	  /* Try to match an existing session first */

	  if (acl_fa_ifc_has_sessions (am, sw_if_index0))
	    {
	      if (acl_fa_find_session
		  (am, sw_if_index0, &kv_sess, &value_sess))
		{
		  trace_bitmap |= 0x80000000;
		  error0 = ACL_FA_ERROR_ACL_EXIST_SESSION;
		  fa_full_session_id_t f_sess_id;

                  f_sess_id.as_u64 = value_sess.value;
                  ASSERT(f_sess_id.thread_index < vec_len(vlib_mains));

		  fa_session_t *sess = get_session_ptr(am, f_sess_id.thread_index, f_sess_id.session_index);
		  int old_timeout_type =
		    fa_session_get_timeout_type (am, sess);
		  action =
		    acl_fa_track_session (am, is_input, sw_if_index0, now,
					  sess, &fa_5tuple);
		  /* expose the session id to the tracer */
		  match_rule_index = f_sess_id.session_index;
		  int new_timeout_type =
		    fa_session_get_timeout_type (am, sess);
		  acl_check_needed = 0;
		  pkts_exist_session += 1;
		  /* Tracking might have changed the session timeout type, e.g. from transient to established */
		  if (PREDICT_FALSE (old_timeout_type != new_timeout_type))
		    {
		      acl_fa_restart_timer_for_session (am, now, f_sess_id);
		      pkts_restart_session_timer++;
		      trace_bitmap |=
			0x00010000 + ((0xff & old_timeout_type) << 8) +
			(0xff & new_timeout_type);
		    }
                  /*
                   * I estimate the likelihood to be very low - the VPP needs
                   * to have >64K interfaces to start with and then on
                   * exactly 64K indices apart needs to be exactly the same
                   * 5-tuple... Anyway, since this probability is nonzero -
                   * print an error and drop the unlucky packet.
                   * If this shows up in real world, we would need to bump
                   * the hash key length.
                   */
		  if (PREDICT_FALSE(sess->sw_if_index != sw_if_index0)) {
                    clib_warning("BUG: session LSB16(sw_if_index) and 5-tuple collision!");
                    acl_check_needed = 0;
                    action = 0;
                  }
		}
	    }

	  if (acl_check_needed)
	    {
	      action =
		multi_acl_match_5tuple (sw_if_index0, &fa_5tuple, is_l2_path,
				       is_ip6, is_input, &match_acl_in_index,
				       &match_rule_index, &trace_bitmap);
	      error0 = action;
	      if (1 == action)
		pkts_acl_permit += 1;
	      if (2 == action)
		{
		  if (!acl_fa_can_add_session (am, is_input, sw_if_index0))
                    acl_fa_try_recycle_session (am, is_input, thread_index, sw_if_index0);

		  if (acl_fa_can_add_session (am, is_input, sw_if_index0))
		    {
                      fa_session_t *sess = acl_fa_add_session (am, is_input, sw_if_index0, now,
					                       &kv_sess);
                      acl_fa_track_session (am, is_input, sw_if_index0, now,
                                            sess, &fa_5tuple);
		      pkts_new_session += 1;
		    }
		  else
		    {
		      action = 0;
		      error0 = ACL_FA_ERROR_ACL_TOO_MANY_SESSIONS;
		    }
		}
	    }



	  if (action > 0)
	    {
	      if (is_l2_path)
		next0 = vnet_l2_feature_next (b0, l2_feat_next_node_index, 0);
	      else
		vnet_feature_next (sw_if_index0, &next0, b0);
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      acl_fa_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	      t->match_acl_in_index = match_acl_in_index;
	      t->match_rule_index = match_rule_index;
	      t->packet_info[0] = fa_5tuple.kv.key[0];
	      t->packet_info[1] = fa_5tuple.kv.key[1];
	      t->packet_info[2] = fa_5tuple.kv.key[2];
	      t->packet_info[3] = fa_5tuple.kv.key[3];
	      t->packet_info[4] = fa_5tuple.kv.key[4];
	      t->packet_info[5] = fa_5tuple.kv.value;
	      t->action = action;
	      t->trace_bitmap = trace_bitmap;
	    }

	  next0 = next0 < node->n_next_nodes ? next0 : 0;
	  if (0 == next0)
	    b0->error = error_node->errors[error0];

	  pkts_acl_checked += 1;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, acl_fa_node->index,
			       ACL_FA_ERROR_ACL_CHECK, pkts_acl_checked);
  vlib_node_increment_counter (vm, acl_fa_node->index,
			       ACL_FA_ERROR_ACL_PERMIT, pkts_acl_permit);
  vlib_node_increment_counter (vm, acl_fa_node->index,
			       ACL_FA_ERROR_ACL_NEW_SESSION,
			       pkts_new_session);
  vlib_node_increment_counter (vm, acl_fa_node->index,
			       ACL_FA_ERROR_ACL_EXIST_SESSION,
			       pkts_exist_session);
  vlib_node_increment_counter (vm, acl_fa_node->index,
			       ACL_FA_ERROR_ACL_RESTART_SESSION_TIMER,
			       pkts_restart_session_timer);
  return frame->n_vectors;
}


vlib_node_registration_t acl_in_l2_ip6_node;
static uword
acl_in_ip6_l2_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  acl_main_t *am = &acl_main;
  return acl_fa_node_fn (vm, node, frame, 1, 1, 1,
			 am->fa_acl_in_ip6_l2_node_feat_next_node_index,
			 &acl_in_l2_ip6_node);
}

vlib_node_registration_t acl_in_l2_ip4_node;
static uword
acl_in_ip4_l2_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  acl_main_t *am = &acl_main;
  return acl_fa_node_fn (vm, node, frame, 0, 1, 1,
			 am->fa_acl_in_ip4_l2_node_feat_next_node_index,
			 &acl_in_l2_ip4_node);
}

vlib_node_registration_t acl_out_l2_ip6_node;
static uword
acl_out_ip6_l2_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  acl_main_t *am = &acl_main;
  return acl_fa_node_fn (vm, node, frame, 1, 0, 1,
			 am->fa_acl_out_ip6_l2_node_feat_next_node_index,
			 &acl_out_l2_ip6_node);
}

vlib_node_registration_t acl_out_l2_ip4_node;
static uword
acl_out_ip4_l2_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  acl_main_t *am = &acl_main;
  return acl_fa_node_fn (vm, node, frame, 0, 0, 1,
			 am->fa_acl_out_ip4_l2_node_feat_next_node_index,
			 &acl_out_l2_ip4_node);
}


/**** L3 processing path nodes ****/


vlib_node_registration_t acl_in_fa_ip6_node;
static uword
acl_in_ip6_fa_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 1, 0, 0, &acl_in_fa_ip6_node);
}

vlib_node_registration_t acl_in_fa_ip4_node;
static uword
acl_in_ip4_fa_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 1, 0, 0, &acl_in_fa_ip4_node);
}

vlib_node_registration_t acl_out_fa_ip6_node;
static uword
acl_out_ip6_fa_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 0, 0, 0, &acl_out_fa_ip6_node);
}

vlib_node_registration_t acl_out_fa_ip4_node;
static uword
acl_out_ip4_fa_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 0, 0, 0, &acl_out_fa_ip4_node);
}

/*
 * This process ensures the connection cleanup happens every so often
 * even in absence of traffic, as well as provides general orchestration
 * for requests like connection deletion on a given sw_if_index.
 */


/* *INDENT-OFF* */
#define foreach_acl_fa_cleaner_error \
_(UNKNOWN_EVENT, "unknown event received")  \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_CLEANER_ERROR_##sym,
  foreach_acl_fa_cleaner_error
#undef _
    ACL_FA_CLEANER_N_ERROR,
} acl_fa_cleaner_error_t;

static char *acl_fa_cleaner_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_fa_cleaner_error
#undef _
};

/* *INDENT-ON* */

static vlib_node_registration_t acl_fa_session_cleaner_process_node;
static vlib_node_registration_t acl_fa_worker_session_cleaner_process_node;

/*
 * Per-worker thread interrupt-driven cleaner thread
 * to clean idle connections if there are no packets
 */
static uword
acl_fa_worker_conn_cleaner_process(vlib_main_t * vm,
              vlib_node_runtime_t * rt, vlib_frame_t * f)
{
   acl_main_t *am = &acl_main;
   u64 now = clib_cpu_time_now ();
   u16 thread_index = os_get_thread_index ();
   acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
   int num_expired;
#ifdef FA_NODE_VERBOSE_DEBUG
   clib_warning("\nacl_fa_worker_conn_cleaner: thread index %d now %lu\n\n", thread_index, now);
#endif
   /* allow another interrupt to be queued */
   pw->interrupt_is_pending = 0;
   if (pw->clear_in_process) {
     if (0 == pw->swipe_end_time) {
       /*
        * Someone has just set the flag to start clearing.
        * we do this by combing through the connections up to a "time T"
        * which is now, and requeueing everything except the expired
        * connections and those matching the interface(s) being cleared.
        */

       /*
        * first filter the sw_if_index bitmap that they want from us, by
        * a bitmap of sw_if_index for which we actually have connections.
        */
       if ((pw->pending_clear_sw_if_index_bitmap == 0)
           || (pw->serviced_sw_if_index_bitmap == 0)) {
#ifdef FA_NODE_VERBOSE_DEBUG
         clib_warning("WORKER-CLEAR: someone tried to call clear, but one of the bitmaps are empty");
#endif
	 clib_bitmap_zero(pw->pending_clear_sw_if_index_bitmap);
       } else {
#ifdef FA_NODE_VERBOSE_DEBUG
         clib_warning("WORKER-CLEAR: (before and) swiping sw-if-index bitmap: %U, my serviced bitmap %U",
                      format_bitmap_hex, pw->pending_clear_sw_if_index_bitmap,
                      format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
#endif
         pw->pending_clear_sw_if_index_bitmap = clib_bitmap_and(pw->pending_clear_sw_if_index_bitmap,
							      pw->serviced_sw_if_index_bitmap);
       }

       if (clib_bitmap_is_zero(pw->pending_clear_sw_if_index_bitmap)) {
         /* if the cross-section is a zero vector, no need to do anything. */
#ifdef FA_NODE_VERBOSE_DEBUG
         clib_warning("WORKER: clearing done - nothing to do");
#endif
         pw->clear_in_process = 0;
       } else {
#ifdef FA_NODE_VERBOSE_DEBUG
         clib_warning("WORKER-CLEAR: swiping sw-if-index bitmap: %U, my serviced bitmap %U",
                      format_bitmap_hex, pw->pending_clear_sw_if_index_bitmap,
                      format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
#endif
         /* swipe through the connection lists until enqueue timestamps become above "now" */
         pw->swipe_end_time = now;
       }
     }
   }
   num_expired = acl_fa_check_idle_sessions(am, thread_index, now);
   // clib_warning("WORKER-CLEAR: checked %d sessions (clear_in_progress: %d)", num_expired, pw->clear_in_process);
   if (pw->clear_in_process) {
     if (0 == num_expired) {
       /* we were clearing but we could not process any more connections. time to stop. */
       clib_bitmap_zero(pw->pending_clear_sw_if_index_bitmap);
       pw->clear_in_process = 0;
#ifdef FA_NODE_VERBOSE_DEBUG
       clib_warning("WORKER: clearing done, all done");
#endif
     } else {
#ifdef FA_NODE_VERBOSE_DEBUG
       clib_warning("WORKER-CLEAR: more work to do, raising interrupt");
#endif
       /* should continue clearing.. So could they please sent an interrupt again? */
       pw->interrupt_is_needed = 1;
     }
   } else {
     if (num_expired >= am->fa_max_deleted_sessions_per_interval) {
       /* there was too much work, we should get an interrupt ASAP */
       pw->interrupt_is_needed = 1;
       pw->interrupt_is_unwanted = 0;
     } else if (num_expired <= am->fa_min_deleted_sessions_per_interval) {
       /* signal that they should trigger us less */
       pw->interrupt_is_needed = 0;
       pw->interrupt_is_unwanted = 1;
     } else {
       /* the current rate of interrupts is ok */
       pw->interrupt_is_needed = 0;
       pw->interrupt_is_unwanted = 0;
     }
   }
   pw->interrupt_generation = am->fa_interrupt_generation;
   return 0;
}

static void
send_one_worker_interrupt (vlib_main_t * vm, acl_main_t *am, int thread_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  if (!pw->interrupt_is_pending) {
    pw->interrupt_is_pending = 1;
    vlib_node_set_interrupt_pending (vlib_mains[thread_index],
                  acl_fa_worker_session_cleaner_process_node.index);
    /* if the interrupt was requested, mark that done. */
    /* pw->interrupt_is_needed = 0; */
  }
}

static void
send_interrupts_to_workers (vlib_main_t * vm, acl_main_t *am)
{
  int i;
  /* Can't use vec_len(am->per_worker_data) since the threads might not have come up yet; */
  int n_threads = vec_len(vlib_mains);
  for (i = n_threads > 1 ? 1 : 0; i < n_threads; i++) {
    send_one_worker_interrupt(vm, am, i);
  }
}

/* centralized process to drive per-worker cleaners */
static uword
acl_fa_session_cleaner_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f)
{
  acl_main_t *am = &acl_main;
  u64 now;
  f64 cpu_cps = vm->clib_time.clocks_per_second;
  u64 next_expire;
  /* We should check if there are connections to clean up - at least twice a second */
  u64 max_timer_wait_interval = cpu_cps / 2;
  uword event_type, *event_data = 0;
  acl_fa_per_worker_data_t *pw0;

  am->fa_current_cleaner_timer_wait_interval = max_timer_wait_interval;
  am->fa_cleaner_node_index = acl_fa_session_cleaner_process_node.index;
  am->fa_interrupt_generation = 1;
  while (1)
    {
      now = clib_cpu_time_now ();
      next_expire = now + am->fa_current_cleaner_timer_wait_interval;
      int has_pending_conns = 0;
      u16 ti;
      u8 tt;

      /*
       * walk over all per-thread list heads of different timeouts,
       * and see if there are any connections pending.
       * If there aren't - we do not need to wake up until the
       * worker code signals that it has added a connection.
       *
       * Also, while we are at it, calculate the earliest we need to wake up.
       */
      for(ti = 0; ti < vec_len(vlib_mains); ti++) {
        if (ti >= vec_len(am->per_worker_data)) {
          continue;
        }
        acl_fa_per_worker_data_t *pw = &am->per_worker_data[ti];
        for(tt = 0; tt < vec_len(pw->fa_conn_list_head); tt++) {
          u64 head_expiry = acl_fa_get_list_head_expiry_time(am, pw, now, ti, tt);
          if ((head_expiry < next_expire) && !pw->interrupt_is_pending) {
#ifdef FA_NODE_VERBOSE_DEBUG
            clib_warning("Head expiry: %lu, now: %lu, next_expire: %lu (worker: %d, tt: %d)", head_expiry, now, next_expire, ti, tt);
#endif
            next_expire = head_expiry;
	  }
          if (~0 != pw->fa_conn_list_head[tt]) {
            has_pending_conns = 1;
          }
        }
      }

      /* If no pending connections and no ACL applied then no point in timing out */
      if (!has_pending_conns && (0 == am->fa_total_enabled_count))
        {
          am->fa_cleaner_cnt_wait_without_timeout++;
          (void) vlib_process_wait_for_event (vm);
          event_type = vlib_process_get_events (vm, &event_data);
        }
      else
	{
	  f64 timeout = ((i64) next_expire - (i64) now) / cpu_cps;
	  if (timeout <= 0)
	    {
	      /* skip waiting altogether */
	      event_type = ~0;
	    }
	  else
	    {
              am->fa_cleaner_cnt_wait_with_timeout++;
	      (void) vlib_process_wait_for_event_or_clock (vm, timeout);
	      event_type = vlib_process_get_events (vm, &event_data);
	    }
	}

      switch (event_type)
	{
	case ~0:
	  /* nothing to do */
	  break;
	case ACL_FA_CLEANER_RESCHEDULE:
	  /* Nothing to do. */
	  break;
	case ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX:
	  {
            uword *clear_sw_if_index_bitmap = 0;
	    uword *sw_if_index0;
            int clear_all = 0;
#ifdef FA_NODE_VERBOSE_DEBUG
	    clib_warning("ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX received");
#endif
	    vec_foreach (sw_if_index0, event_data)
	    {
              am->fa_cleaner_cnt_delete_by_sw_index++;
#ifdef FA_NODE_VERBOSE_DEBUG
	      clib_warning
		("ACL_FA_NODE_CLEAN: ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX: %d",
		 *sw_if_index0);
#endif
              if (*sw_if_index0 == ~0)
                {
                  clear_all = 1;
                }
              else
                {
                  if (!pool_is_free_index (am->vnet_main->interface_main.sw_interfaces, *sw_if_index0))
                    {
                      clear_sw_if_index_bitmap = clib_bitmap_set(clear_sw_if_index_bitmap, *sw_if_index0, 1);
                    }
                }
	    }
#ifdef FA_NODE_VERBOSE_DEBUG
	    clib_warning("ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX bitmap: %U", format_bitmap_hex, clear_sw_if_index_bitmap);
#endif
	    vec_foreach(pw0, am->per_worker_data) {
              CLIB_MEMORY_BARRIER ();
	      while (pw0->clear_in_process) {
                CLIB_MEMORY_BARRIER ();
#ifdef FA_NODE_VERBOSE_DEBUG
                clib_warning("ACL_FA_NODE_CLEAN: waiting previous cleaning cycle to finish on %d...", pw0 - am->per_worker_data);
#endif
                vlib_process_suspend(vm, 0.0001);
                if (pw0->interrupt_is_needed) {
                  send_one_worker_interrupt(vm, am, (pw0 - am->per_worker_data));
                }
              }
              if (pw0->clear_in_process) {
                clib_warning("ERROR-BUG! Could not initiate cleaning on worker because another cleanup in progress");
	      } else {
                if (clear_all)
                  {
                    /* if we need to clear all, then just clear the interfaces that we are servicing */
                    pw0->pending_clear_sw_if_index_bitmap = clib_bitmap_dup(pw0->serviced_sw_if_index_bitmap);
                  }
                else
                  {
                    pw0->pending_clear_sw_if_index_bitmap = clib_bitmap_dup(clear_sw_if_index_bitmap);
                  }
                pw0->clear_in_process = 1;
              }
            }
            /* send some interrupts so they can start working */
            send_interrupts_to_workers(vm, am);

            /* now wait till they all complete */
#ifdef FA_NODE_VERBOSE_DEBUG
	    clib_warning("CLEANER mains len: %d per-worker len: %d", vec_len(vlib_mains), vec_len(am->per_worker_data));
#endif
	    vec_foreach(pw0, am->per_worker_data) {
              CLIB_MEMORY_BARRIER ();
	      while (pw0->clear_in_process) {
                CLIB_MEMORY_BARRIER ();
#ifdef FA_NODE_VERBOSE_DEBUG
                clib_warning("ACL_FA_NODE_CLEAN: waiting for my cleaning cycle to finish on %d...", pw0 - am->per_worker_data);
#endif
                vlib_process_suspend(vm, 0.0001);
                if (pw0->interrupt_is_needed) {
                  send_one_worker_interrupt(vm, am, (pw0 - am->per_worker_data));
                }
              }
            }
#ifdef FA_NODE_VERBOSE_DEBUG
            clib_warning("ACL_FA_NODE_CLEAN: cleaning done");
#endif
            clib_bitmap_free(clear_sw_if_index_bitmap);
	  }
	  break;
	default:
#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning ("ACL plugin connection cleaner: unknown event %u",
			event_type);
#endif
          vlib_node_increment_counter (vm,
                                       acl_fa_session_cleaner_process_node.
                                       index,
                                       ACL_FA_CLEANER_ERROR_UNKNOWN_EVENT, 1);
          am->fa_cleaner_cnt_unknown_event++;
	  break;
	}

      send_interrupts_to_workers(vm, am);

      if (event_data)
	_vec_len (event_data) = 0;

      /*
       * If the interrupts were not processed yet, ensure we wait a bit,
       * but up to a point.
       */
      int need_more_wait = 0;
      int max_wait_cycles = 100;
      do {
        need_more_wait = 0;
        vec_foreach(pw0, am->per_worker_data) {
          if (pw0->interrupt_generation != am->fa_interrupt_generation) {
            need_more_wait = 1;
          }
        }
        if (need_more_wait) {
          vlib_process_suspend(vm, 0.0001);
        }
      } while (need_more_wait && (--max_wait_cycles > 0));

      int interrupts_needed = 0;
      int interrupts_unwanted = 0;

      vec_foreach(pw0, am->per_worker_data) {
        if (pw0->interrupt_is_needed) {
          interrupts_needed++;
          /* the per-worker value is reset when sending the interrupt */
        }
        if (pw0->interrupt_is_unwanted) {
          interrupts_unwanted++;
          pw0->interrupt_is_unwanted = 0;
        }
      }
      if (interrupts_needed) {
        /* they need more interrupts, do less waiting around next time */
        am->fa_current_cleaner_timer_wait_interval /= 2;
        /* never go into zero-wait either though - we need to give the space to others */
        am->fa_current_cleaner_timer_wait_interval += 1;
      } else if (interrupts_unwanted) {
        /* slowly increase the amount of sleep up to a limit */
        if (am->fa_current_cleaner_timer_wait_interval < max_timer_wait_interval)
          am->fa_current_cleaner_timer_wait_interval += cpu_cps * am->fa_cleaner_wait_time_increment;
      }
      am->fa_cleaner_cnt_event_cycles++;
      am->fa_interrupt_generation++;
    }
  /* NOT REACHED */
  return 0;
}


void
acl_fa_enable_disable (u32 sw_if_index, int is_input, int enable_disable)
{
  acl_main_t *am = &acl_main;
  if (enable_disable) {
    acl_fa_verify_init_sessions(am);
    am->fa_total_enabled_count++;
    void *oldheap = clib_mem_set_heap (am->vlib_main->heap_base);
    vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
                                 ACL_FA_CLEANER_RESCHEDULE, 0);
    clib_mem_set_heap (oldheap);
  } else {
    am->fa_total_enabled_count--;
  }

  if (is_input)
    {
      ASSERT(clib_bitmap_get(am->fa_in_acl_on_sw_if_index, sw_if_index) != enable_disable);
      void *oldheap = clib_mem_set_heap (am->vlib_main->heap_base);
      vnet_feature_enable_disable ("ip4-unicast", "acl-plugin-in-ip4-fa",
				   sw_if_index, enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "acl-plugin-in-ip6-fa",
				   sw_if_index, enable_disable, 0, 0);
      clib_mem_set_heap (oldheap);
      am->fa_in_acl_on_sw_if_index =
	clib_bitmap_set (am->fa_in_acl_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  else
    {
      ASSERT(clib_bitmap_get(am->fa_out_acl_on_sw_if_index, sw_if_index) != enable_disable);
      void *oldheap = clib_mem_set_heap (am->vlib_main->heap_base);
      vnet_feature_enable_disable ("ip4-output", "acl-plugin-out-ip4-fa",
				   sw_if_index, enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "acl-plugin-out-ip6-fa",
				   sw_if_index, enable_disable, 0, 0);
      clib_mem_set_heap (oldheap);
      am->fa_out_acl_on_sw_if_index =
	clib_bitmap_set (am->fa_out_acl_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  if ((!enable_disable) && (!acl_fa_ifc_has_in_acl (am, sw_if_index))
      && (!acl_fa_ifc_has_out_acl (am, sw_if_index)))
    {
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning("ENABLE-DISABLE: clean the connections on interface %d", sw_if_index);
#endif
      void *oldheap = clib_mem_set_heap (am->vlib_main->heap_base);
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
				 sw_if_index);
      clib_mem_set_heap (oldheap);
    }
}

void
show_fa_sessions_hash(vlib_main_t * vm, u32 verbose)
{
  acl_main_t *am = &acl_main;
  if (am->fa_sessions_hash_is_initialized) {
    vlib_cli_output(vm, "\nSession lookup hash table:\n%U\n\n",
                  BV (format_bihash), &am->fa_sessions_hash, verbose);
  } else {
    vlib_cli_output(vm, "\nSession lookup hash table is not allocated.\n\n");
  }
}


/* *INDENT-OFF* */

VLIB_REGISTER_NODE (acl_fa_worker_session_cleaner_process_node, static) = {
  .function = acl_fa_worker_conn_cleaner_process,
  .name = "acl-plugin-fa-worker-cleaner-process",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

VLIB_REGISTER_NODE (acl_fa_session_cleaner_process_node, static) = {
  .function = acl_fa_session_cleaner_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "acl-plugin-fa-cleaner-process",
  .n_errors = ARRAY_LEN (acl_fa_cleaner_error_strings),
  .error_strings = acl_fa_cleaner_error_strings,
  .n_next_nodes = 0,
  .next_nodes = {},
};


VLIB_REGISTER_NODE (acl_in_l2_ip6_node) =
{
  .function = acl_in_ip6_l2_node_fn,
  .name = "acl-plugin-in-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (acl_in_l2_ip4_node) =
{
  .function = acl_in_ip4_l2_node_fn,
  .name = "acl-plugin-in-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (acl_out_l2_ip6_node) =
{
  .function = acl_out_ip6_l2_node_fn,
  .name = "acl-plugin-out-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (acl_out_l2_ip4_node) =
{
  .function = acl_out_ip4_l2_node_fn,
  .name = "acl-plugin-out-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};


VLIB_REGISTER_NODE (acl_in_fa_ip6_node) =
{
  .function = acl_in_ip6_fa_node_fn,
  .name = "acl-plugin-in-ip6-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_ip6_fa_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "acl-plugin-in-ip6-fa",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};

VLIB_REGISTER_NODE (acl_in_fa_ip4_node) =
{
  .function = acl_in_ip4_fa_node_fn,
  .name = "acl-plugin-in-ip4-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_ip4_fa_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "acl-plugin-in-ip4-fa",
  .runs_before = VNET_FEATURES ("ip4-flow-classify"),
};


VLIB_REGISTER_NODE (acl_out_fa_ip6_node) =
{
  .function = acl_out_ip6_fa_node_fn,
  .name = "acl-plugin-out-ip6-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_ip6_fa_feature, static) =
{
  .arc_name = "ip6-output",
  .node_name = "acl-plugin-out-ip6-fa",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VLIB_REGISTER_NODE (acl_out_fa_ip4_node) =
{
  .function = acl_out_ip4_fa_node_fn,
  .name = "acl-plugin-out-ip4-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_fa_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
    /* edit / add dispositions here */
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_ip4_fa_feature, static) =
{
  .arc_name = "ip4-output",
  .node_name = "acl-plugin-out-ip4-fa",
  .runs_before = VNET_FEATURES ("interface-output"),
};


/* *INDENT-ON* */
