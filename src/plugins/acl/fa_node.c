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
#include "bihash_40_8.h"

#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include "fa_node.h"

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
acl_match_5tuple (acl_main_t * am, u32 acl_index, fa_5tuple_t * pkt_5tuple,
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
full_acl_match_5tuple (u32 sw_if_index, fa_5tuple_t * pkt_5tuple, int is_l2,
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
      if (acl_match_5tuple
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

static int
offset_within_packet (vlib_buffer_t * b0, int offset)
{
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset <= (b0->current_length - 8));
}

static void
acl_fill_5tuple (acl_main_t * am, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_t * p5tuple_pkt)
{
  int l3_offset = 14;
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

  if (is_ip6)
    {
      clib_memcpy (&p5tuple_pkt->addr,
		   get_ptr_to_offset (b0,
				      offsetof (ip6_header_t,
						src_address) + l3_offset),
		   sizeof (p5tuple_pkt->addr));
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
      clib_memcpy (&p5tuple_pkt->addr[0].ip4,
		   get_ptr_to_offset (b0,
				      offsetof (ip4_header_t,
						src_address) + l3_offset),
		   sizeof (p5tuple_pkt->addr[0].ip4));
      clib_memcpy (&p5tuple_pkt->addr[1].ip4,
		   get_ptr_to_offset (b0,
				      offsetof (ip4_header_t,
						dst_address) + l3_offset),
		   sizeof (p5tuple_pkt->addr[1].ip4));
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
      flags_and_fragment_offset = ntohs (flags_and_fragment_offset);

      /* non-initial fragments have non-zero offset */
      if ((PREDICT_FALSE(0xfff & flags_and_fragment_offset)))
        {
          p5tuple_pkt->pkt.is_nonfirst_fragment = 1;
          /* invalidate L4 offset so we don't try to find L4 info */
          l4_offset += b0->current_length;
        }

    }
  p5tuple_pkt->l4.proto = proto;
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


static int
acl_fa_ifc_has_sessions (acl_main_t * am, int sw_if_index0)
{
  int has_sessions =
    clib_bitmap_get (am->fa_sessions_on_sw_if_index, sw_if_index0);
  return has_sessions;
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
  /* seen both SYNs and ACKs but not FINs means we are in establshed state */
  u16 masked_flags =
    sess->tcp_flags_seen.as_u16 & ((TCP_FLAGS_RSTFINACKSYN << 8) +
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
fa_session_get_timeout (acl_main_t * am, fa_session_t * sess)
{
  u64 timeout = am->vlib_main->clib_time.clocks_per_second;
  int timeout_type = fa_session_get_timeout_type (am, sess);
  timeout *= am->session_timeout_sec[timeout_type];
  return timeout;
}

static void
acl_fa_ifc_init_sessions (acl_main_t * am, int sw_if_index0)
{
#ifdef FA_NODE_VERBOSE_DEBUG
  clib_warning
    ("Initializing bihash for sw_if_index %d num buckets %lu memory size %llu",
     sw_if_index0, am->fa_conn_table_hash_num_buckets,
     am->fa_conn_table_hash_memory_size);
#endif
  vec_validate (am->fa_sessions_by_sw_if_index, sw_if_index0);
  BV (clib_bihash_init) (&am->fa_sessions_by_sw_if_index
			 [sw_if_index0], "ACL plugin FA session bihash",
			 am->fa_conn_table_hash_num_buckets,
			 am->fa_conn_table_hash_memory_size);
  am->fa_sessions_on_sw_if_index =
    clib_bitmap_set (am->fa_sessions_on_sw_if_index, sw_if_index0, 1);
}

static void
acl_fa_conn_list_add_session (acl_main_t * am, u32 sess_id)
{
  fa_session_t *sess = am->fa_sessions_pool + sess_id;
  u8 list_id = fa_session_get_timeout_type(am, sess);
  sess->link_list_id = list_id;
  sess->link_next_idx = ~0;
  sess->link_prev_idx = am->fa_conn_list_tail[list_id];
  if (~0 != am->fa_conn_list_tail[list_id]) {
    fa_session_t *prev_sess = am->fa_sessions_pool + am->fa_conn_list_tail[list_id];
    prev_sess->link_next_idx = sess_id;
  }
  am->fa_conn_list_tail[list_id] = sess_id;

  if (~0 == am->fa_conn_list_head[list_id]) {
    am->fa_conn_list_head[list_id] = sess_id;
    /* If it is a first conn in any list, kick off the cleaner */
    vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
                                 ACL_FA_CLEANER_RESCHEDULE, 0);

  }
}

static void
acl_fa_conn_list_delete_session (acl_main_t *am, u32 sess_id)
{
  fa_session_t *sess = am->fa_sessions_pool + sess_id;
  if (~0 != sess->link_prev_idx) {
    fa_session_t *prev_sess = am->fa_sessions_pool + sess->link_prev_idx;
    prev_sess->link_next_idx = sess->link_next_idx;
    if (prev_sess->link_list_id != sess->link_list_id)
      clib_warning("(prev_sess->link_list_id != sess->link_list_id)");
  }
  if (~0 != sess->link_next_idx) {
    fa_session_t *next_sess = am->fa_sessions_pool + sess->link_next_idx;
    next_sess->link_prev_idx = sess->link_prev_idx;
    if (next_sess->link_list_id != sess->link_list_id)
      clib_warning("(next_sess->link_list_id != sess->link_list_id)");
  }
  if (am->fa_conn_list_head[sess->link_list_id] == sess_id) {
    am->fa_conn_list_head[sess->link_list_id] = sess->link_next_idx;
  }
  if (am->fa_conn_list_tail[sess->link_list_id] == sess_id) {
    am->fa_conn_list_tail[sess->link_list_id] = sess->link_prev_idx;
  }
}


int
acl_fa_session_is_dead (acl_main_t * am, u32 sw_if_index, u64 now,
			u32 sess_id)
{
  return 0;
}

static void
acl_fa_restart_timer_for_session (acl_main_t * am, u64 now, u32 sess_id)
{
  // fa_session_t *sess = am->fa_sessions_pool + sess_id;
  acl_fa_conn_list_delete_session(am, sess_id);
  acl_fa_conn_list_add_session(am, sess_id);
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
acl_fa_delete_session (acl_main_t * am, u32 sw_if_index, u32 sess_id)
{
  fa_session_t *sess = (fa_session_t *) am->fa_sessions_pool + sess_id;
  BV (clib_bihash_add_del) (&am->fa_sessions_by_sw_if_index[sw_if_index],
			    &sess->info.kv, 0);
  pool_put_index (am->fa_sessions_pool, sess_id);
  /* Deleting from timer wheel not needed, as the cleaner deals with the timers. */
  vec_validate (am->fa_session_dels_by_sw_if_index, sw_if_index);
  am->fa_session_dels_by_sw_if_index[sw_if_index]++;
}

static int
acl_fa_can_add_session (acl_main_t * am, int is_input, u32 sw_if_index)
{
  u64 curr_sess;
  vec_validate (am->fa_session_adds_by_sw_if_index, sw_if_index);
  vec_validate (am->fa_session_dels_by_sw_if_index, sw_if_index);
  curr_sess =
    am->fa_session_adds_by_sw_if_index[sw_if_index] -
    am->fa_session_dels_by_sw_if_index[sw_if_index];
  return (curr_sess < am->fa_conn_table_max_entries);
}

always_inline void
acl_fa_try_recycle_session (acl_main_t * am, int is_input, u32 sw_if_index)
{
  /* try to recycle a TCP transient session */
  u8 timeout_type = ACL_TIMEOUT_TCP_TRANSIENT;
  u32 sess_id = am->fa_conn_list_head[timeout_type];
  if (~0 != sess_id) {
    acl_fa_conn_list_delete_session(am, sess_id);
    acl_fa_delete_session(am, sw_if_index, sess_id);
  }
}

static void
acl_fa_add_session (acl_main_t * am, int is_input, u32 sw_if_index, u64 now,
		    fa_5tuple_t * p5tuple)
{
  clib_bihash_kv_40_8_t *pkv = &p5tuple->kv;
  clib_bihash_kv_40_8_t kv;
  u32 sess_id;
  fa_session_t *sess;

  pool_get (am->fa_sessions_pool, sess);
  sess_id = sess - am->fa_sessions_pool;


  kv.key[0] = pkv->key[0];
  kv.key[1] = pkv->key[1];
  kv.key[2] = pkv->key[2];
  kv.key[3] = pkv->key[3];
  kv.key[4] = pkv->key[4];
  kv.value = sess_id;

  memcpy (sess, pkv, sizeof (pkv->key));
  sess->last_active_time = now;
  sess->sw_if_index = sw_if_index;
  sess->tcp_flags_seen.as_u16 = 0;
  sess->reserved1 = 0;
  sess->link_list_id = ~0;
  sess->link_prev_idx = ~0;
  sess->link_next_idx = ~0;



  if (!acl_fa_ifc_has_sessions (am, sw_if_index))
    {
      acl_fa_ifc_init_sessions (am, sw_if_index);
    }

  BV (clib_bihash_add_del) (&am->fa_sessions_by_sw_if_index[sw_if_index],
			    &kv, 1);
  acl_fa_conn_list_add_session(am, sess_id);

  vec_validate (am->fa_session_adds_by_sw_if_index, sw_if_index);
  am->fa_session_adds_by_sw_if_index[sw_if_index]++;
}

static int
acl_fa_find_session (acl_main_t * am, u32 sw_if_index0, fa_5tuple_t * p5tuple,
		     clib_bihash_kv_40_8_t * pvalue_sess)
{
  return (BV (clib_bihash_search)
	  (&am->fa_sessions_by_sw_if_index[sw_if_index0], &p5tuple->kv,
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
  u32 feature_bitmap0;
  acl_main_t *am = &acl_main;
  fa_5tuple_t fa_5tuple, kv_sess;
  clib_bihash_kv_40_8_t value_sess;
  vlib_node_runtime_t *error_node;
  u64 now = clib_cpu_time_now ();

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
	  if (is_l2_path)
	    feature_bitmap0 = vnet_buffer (b0)->l2.feature_bitmap;

	  /*
	   * Extract the L3/L4 matching info into a 5-tuple structure,
	   * then create a session key whose layout is independent on forward or reverse
	   * direction of the packet.
	   */

	  acl_fill_5tuple (am, b0, is_ip6, is_input, is_l2_path, &fa_5tuple);
	  acl_make_5tuple_session_key (is_input, &fa_5tuple, &kv_sess);
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
		  // FIXME assert(value_sess.value == (0xffffffff & value_sess.value));
		  u32 sess_id = value_sess.value;
		  fa_session_t *sess = am->fa_sessions_pool + sess_id;
		  int old_timeout_type =
		    fa_session_get_timeout_type (am, sess);
		  action =
		    acl_fa_track_session (am, is_input, sw_if_index0, now,
					  sess, &fa_5tuple);
		  /* expose the session id to the tracer */
		  match_rule_index = sess_id;
		  int new_timeout_type =
		    fa_session_get_timeout_type (am, sess);
		  acl_check_needed = 0;
		  pkts_exist_session += 1;
		  /* Tracking might have changed the session timeout type, e.g. from transient to established */
		  if (PREDICT_FALSE (old_timeout_type != new_timeout_type))
		    {
		      acl_fa_restart_timer_for_session (am, now, sess_id);
		      pkts_restart_session_timer++;
		      trace_bitmap |=
			0x00010000 + ((0xff & old_timeout_type) << 8) +
			(0xff & new_timeout_type);
		    }
		}
	    }

	  if (acl_check_needed)
	    {
	      action =
		full_acl_match_5tuple (sw_if_index0, &fa_5tuple, is_l2_path,
				       is_ip6, is_input, &match_acl_in_index,
				       &match_rule_index, &trace_bitmap);
	      error0 = action;
	      if (1 == action)
		pkts_acl_permit += 1;
	      if (2 == action)
		{
		  if (!acl_fa_can_add_session (am, is_input, sw_if_index0))
                    acl_fa_try_recycle_session (am, is_input, sw_if_index0);

		  if (acl_fa_can_add_session (am, is_input, sw_if_index0))
		    {
                      acl_fa_add_session (am, is_input, sw_if_index0, now,
					  &kv_sess);
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
		next0 =
		  feat_bitmap_get_next_node_index (l2_feat_next_node_index,
						   feature_bitmap0);
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
 * This process performs all the connection clean up - both for idle connections,
 * as well as receiving the signals to clean up the connections in case of sw_if_index deletion,
 * or (maybe in the future) the connection deletion due to policy reasons.
 *
 * The previous iteration (l2sess) attempted to clean up the connections in small increments,
 * in-band, but the problem it tried to preemptively address (process starvation) is yet to be seen.
 *
 * The approach with a single thread deleting the connections is simpler, thus we use it until
 * there is a real starvation problem to solve.
 *
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

static int
acl_fa_clean_sessions_by_sw_if_index (acl_main_t *am, u32 sw_if_index, u32 *count)
{

  int undeleted = 0;
  fa_session_t *sess;
  uword *dv = NULL;
  uword *ii;

  pool_foreach(sess, am->fa_sessions_pool, ({
    if ( (~0 == sw_if_index) || (sw_if_index == sess->sw_if_index) )
      vec_add1(dv, sess-am->fa_sessions_pool);
  }));
  vec_foreach(ii, dv)
  {
    sess =  pool_elt_at_index(am->fa_sessions_pool, *ii);
    acl_fa_delete_session(am, sess->sw_if_index, *ii);
    (*count)++;
  }

  pool_foreach(sess, am->fa_sessions_pool, ({
    if ( (~0 == sw_if_index) || (sw_if_index == sess->sw_if_index) )
      undeleted++;
  }));
  if (undeleted == 0)
    {
      if (~0 == sw_if_index)
        {
          /* FIXME: clean-up tables ? */
        }
      else
        {
          /* FIXME: clean-up tables ? */
        }
    }
  return (undeleted == 0);
}
/* *INDENT-ON* */

static vlib_node_registration_t acl_fa_session_cleaner_process_node;

static int
acl_fa_conn_has_timed_out (acl_main_t *am, u64 now, u32 session_index)
{
  fa_session_t *sess = am->fa_sessions_pool + session_index;
  u64 sess_timeout_time =
              sess->last_active_time + fa_session_get_timeout (am, sess);
  return (sess_timeout_time < now);
}


static uword
acl_fa_session_cleaner_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
				vlib_frame_t * f)
{
  acl_main_t *am = &acl_main;
  u64 now = clib_cpu_time_now ();
  f64 cpu_cps = vm->clib_time.clocks_per_second;
  u64 next_expire;
  /* We should call timer wheel at least twice a second */
  u64 max_timer_wait_interval = cpu_cps / 2;
  am->fa_current_cleaner_timer_wait_interval = max_timer_wait_interval;

  u32 *expired = NULL;
  uword event_type, *event_data = 0;

  am->fa_cleaner_node_index = acl_fa_session_cleaner_process_node.index;

  while (1)
    {
      u32 count_deleted_sessions = 0;
      u32 count_already_deleted = 0;
      now = clib_cpu_time_now ();
      next_expire = now + am->fa_current_cleaner_timer_wait_interval;
      int has_pending_conns = 0;
      u8 tt;
      for(tt = 0; tt < ACL_N_TIMEOUTS; tt++)
        {
          if (~0 != am->fa_conn_list_head[tt])
            has_pending_conns = 1;
        }

      /* If no pending connections then no point in timing out */
      if (!has_pending_conns)
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
	      /* Timing wheel code is happier if it is called regularly */
	      if (timeout > 0.5)
		timeout = 0.5;
              am->fa_cleaner_cnt_wait_with_timeout++;
	      (void) vlib_process_wait_for_event_or_clock (vm, timeout);
	      event_type = vlib_process_get_events (vm, &event_data);
	    }
	}

      now = clib_cpu_time_now ();
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
	    uword *sw_if_index0;
	    vec_foreach (sw_if_index0, event_data)
	    {
              am->fa_cleaner_cnt_delete_by_sw_index++;
#ifdef FA_NODE_VERBOSE_DEBUG
	      clib_warning
		("ACL_FA_NODE_CLEAN: ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX: %d",
		 *sw_if_index0);
#endif
	      u32 count = 0;
	      int result =
		acl_fa_clean_sessions_by_sw_if_index (am, *sw_if_index0,
						      &count);
	      count_deleted_sessions += count;
              am->fa_cleaner_cnt_delete_by_sw_index_ok += result;
	    }
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

      {
        u8 tt = 0;
        for(tt = 0; tt < ACL_N_TIMEOUTS; tt++) {
          while((vec_len(expired) < 2*am->fa_max_deleted_sessions_per_interval)
                && (~0 != am->fa_conn_list_head[tt])
                && (acl_fa_conn_has_timed_out(am, now,
                                              am->fa_conn_list_head[tt]))) {
            u32 sess_id = am->fa_conn_list_head[tt];
            vec_add1(expired, sess_id);
            acl_fa_conn_list_delete_session(am, sess_id);
          }
        }
      }

      u32 *psid = NULL;
      vec_foreach (psid, expired)
      {
	u32 session_index = *psid;
	if (!pool_is_free_index (am->fa_sessions_pool, session_index))
	  {
	    fa_session_t *sess = am->fa_sessions_pool + session_index;
	    u32 sw_if_index = sess->sw_if_index;
	    u64 sess_timeout_time =
	      sess->last_active_time + fa_session_get_timeout (am, sess);
	    if (now < sess_timeout_time)
	      {
		/* clib_warning ("ACL_FA_NODE_CLEAN: Restarting timer for session %d",
		   (int) session_index); */

                /* There was activity on the session, so the idle timeout
                   has not passed. Enqueue for another time period. */

                acl_fa_conn_list_add_session(am, session_index);

		/* FIXME: When/if moving to timer wheel,
                   pretend we did this in the past,
                   at last_active moment, so the timer is accurate */
                am->fa_cleaner_cnt_timer_restarted++;
	      }
	    else
	      {
		/* clib_warning ("ACL_FA_NODE_CLEAN: Deleting session %d",
		   (int) session_index); */
		acl_fa_delete_session (am, sw_if_index, session_index);
                count_deleted_sessions++;
	      }
	  }
	else
	  {
	    count_already_deleted++;
	  }
      }
      if (expired)
	_vec_len (expired) = 0;
      if (event_data)
	_vec_len (event_data) = 0;

      if (count_deleted_sessions > am->fa_max_deleted_sessions_per_interval) {
        /* if there was too many sessions to delete, do less waiting around next time */
        am->fa_current_cleaner_timer_wait_interval /= 2;
      } else if (count_deleted_sessions < am->fa_min_deleted_sessions_per_interval) {
        /* Too few deleted sessions, slowly increase the amount of sleep up to a limit */
        if (am->fa_current_cleaner_timer_wait_interval < max_timer_wait_interval)
          am->fa_current_cleaner_timer_wait_interval += cpu_cps * am->fa_cleaner_wait_time_increment;
      }
      am->fa_cleaner_cnt_event_cycles++;
      am->fa_cleaner_cnt_deleted_sessions += count_deleted_sessions;
      am->fa_cleaner_cnt_already_deleted += count_already_deleted;
    }
  /* NOT REACHED */
  return 0;
}


void
acl_fa_enable_disable (u32 sw_if_index, int is_input, int enable_disable)
{
  acl_main_t *am = &acl_main;
  if (is_input)
    {
      vnet_feature_enable_disable ("ip4-unicast", "acl-plugin-in-ip4-fa",
				   sw_if_index, enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "acl-plugin-in-ip6-fa",
				   sw_if_index, enable_disable, 0, 0);
      am->fa_in_acl_on_sw_if_index =
	clib_bitmap_set (am->fa_in_acl_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  else
    {
      vnet_feature_enable_disable ("ip4-output", "acl-plugin-out-ip4-fa",
				   sw_if_index, enable_disable, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "acl-plugin-out-ip6-fa",
				   sw_if_index, enable_disable, 0, 0);
      am->fa_out_acl_on_sw_if_index =
	clib_bitmap_set (am->fa_out_acl_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  if ((!enable_disable) && (!acl_fa_ifc_has_in_acl (am, sw_if_index))
      && (!acl_fa_ifc_has_out_acl (am, sw_if_index)))
    {
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
				 sw_if_index);
    }
}



/* *INDENT-OFF* */


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
