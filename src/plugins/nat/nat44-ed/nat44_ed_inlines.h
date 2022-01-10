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
/**
 * @brief The NAT inline functions
 */

#ifndef __included_nat44_ed_inlines_h__
#define __included_nat44_ed_inlines_h__

#include <float.h>
#include <vppinfra/clib.h>
#include <vnet/fib/ip4_fib.h>

#include <nat/lib/log.h>
#include <nat/lib/ipfix_logging.h>
#include <nat/nat44-ed/nat44_ed.h>

always_inline void
init_ed_k (clib_bihash_kv_16_8_t *kv, u32 l_addr, u16 l_port, u32 r_addr,
	   u16 r_port, u32 fib_index, ip_protocol_t proto)
{
  kv->key[0] = (u64) r_addr << 32 | l_addr;
  kv->key[1] =
    (u64) r_port << 48 | (u64) l_port << 32 | fib_index << 8 | proto;
}

always_inline void
init_ed_kv (clib_bihash_kv_16_8_t *kv, u32 l_addr, u16 l_port, u32 r_addr,
	    u16 r_port, u32 fib_index, u8 proto, u32 thread_index,
	    u32 session_index)
{
  init_ed_k (kv, l_addr, l_port, r_addr, r_port, fib_index, proto);
  kv->value = (u64) thread_index << 32 | session_index;
}

always_inline void
nat44_ed_sm_init_i2o_kv (clib_bihash_kv_16_8_t *kv, u32 addr, u16 port,
			 u32 fib_index, u8 proto, u32 sm_index)
{
  return init_ed_kv (kv, addr, port, 0, 0, fib_index, proto, 0, sm_index);
}

always_inline void
nat44_ed_sm_init_o2i_kv (clib_bihash_kv_16_8_t *kv, u32 e_addr, u16 e_port,
			 u32 fib_index, u8 proto, u32 sm_index)
{
  return init_ed_kv (kv, 0, 0, e_addr, e_port, fib_index, proto, 0, sm_index);
}

always_inline void
nat44_ed_sm_init_i2o_k (clib_bihash_kv_16_8_t *kv, u32 addr, u16 port,
			u32 fib_index, u8 proto)
{
  return nat44_ed_sm_init_i2o_kv (kv, addr, port, fib_index, proto, 0);
}

always_inline void
nat44_ed_sm_init_o2i_k (clib_bihash_kv_16_8_t *kv, u32 e_addr, u16 e_port,
			u32 fib_index, u8 proto)
{
  return nat44_ed_sm_init_o2i_kv (kv, e_addr, e_port, fib_index, proto, 0);
}

always_inline u32
ed_value_get_thread_index (clib_bihash_kv_16_8_t *value)
{
  return value->value >> 32;
}

always_inline u32
ed_value_get_session_index (clib_bihash_kv_16_8_t *value)
{
  return value->value & ~(u32) 0;
}

always_inline void
split_ed_kv (clib_bihash_kv_16_8_t *kv, ip4_address_t *l_addr,
	     ip4_address_t *r_addr, u8 *proto, u32 *fib_index, u16 *l_port,
	     u16 *r_port)
{
  if (l_addr)
    {
      l_addr->as_u32 = kv->key[0] & (u32) ~0;
    }
  if (r_addr)
    {
      r_addr->as_u32 = kv->key[0] >> 32;
    }
  if (r_port)
    {
      *r_port = kv->key[1] >> 48;
    }
  if (l_port)
    {
      *l_port = (kv->key[1] >> 32) & (u16) ~0;
    }
  if (fib_index)
    {
      *fib_index = (kv->key[1] >> 8) & ((1 << 24) - 1);
    }
  if (proto)
    {
      *proto = kv->key[1] & (u8) ~0;
    }
}

static_always_inline int
nat_get_icmp_session_lookup_values (vlib_buffer_t *b, ip4_header_t *ip0,
				    ip4_address_t *lookup_saddr,
				    u16 *lookup_sport,
				    ip4_address_t *lookup_daddr,
				    u16 *lookup_dport, u8 *lookup_protocol)
{
  icmp46_header_t *icmp0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  // avoid warning about unused variables in caller by setting to bogus values
  *lookup_sport = 0;
  *lookup_dport = 0;

  if (!icmp_type_is_error_message (
	vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
    {
      *lookup_protocol = IP_PROTOCOL_ICMP;
      lookup_saddr->as_u32 = ip0->src_address.as_u32;
      *lookup_sport = vnet_buffer (b)->ip.reass.l4_src_port;
      lookup_daddr->as_u32 = ip0->dst_address.as_u32;
      *lookup_dport = vnet_buffer (b)->ip.reass.l4_dst_port;
    }
  else
    {
      inner_ip0 = (ip4_header_t *) (echo0 + 1);
      l4_header = ip4_next_header (inner_ip0);
      *lookup_protocol = inner_ip0->protocol;
      lookup_saddr->as_u32 = inner_ip0->dst_address.as_u32;
      lookup_daddr->as_u32 = inner_ip0->src_address.as_u32;
      switch (inner_ip0->protocol)
	{
	case IP_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  *lookup_sport = inner_echo0->identifier;
	  *lookup_dport = inner_echo0->identifier;
	  break;
	case IP_PROTOCOL_UDP:
	case IP_PROTOCOL_TCP:
	  *lookup_sport = ((tcp_udp_header_t *) l4_header)->dst_port;
	  *lookup_dport = ((tcp_udp_header_t *) l4_header)->src_port;
	  break;
	default:
	  return NAT_IN2OUT_ED_ERROR_UNSUPPORTED_PROTOCOL;
	}
    }
  return 0;
}

always_inline int
nat44_ed_tcp_is_established (nat44_ed_tcp_state_e state)
{
  static int lookup[] = {
    [NAT44_ED_TCP_STATE_CLOSED] = 0,
    [NAT44_ED_TCP_STATE_SYN_I2O] = 0,
    [NAT44_ED_TCP_STATE_SYN_O2I] = 0,
    [NAT44_ED_TCP_STATE_ESTABLISHED] = 1,
    [NAT44_ED_TCP_STATE_FIN_I2O] = 1,
    [NAT44_ED_TCP_STATE_FIN_O2I] = 1,
    [NAT44_ED_TCP_STATE_RST_TRANS] = 0,
    [NAT44_ED_TCP_STATE_FIN_TRANS] = 0,
    [NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O] = 0,
    [NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I] = 0,
    [NAT44_ED_TCP_N_STATE] = 0,
  };
  ASSERT (state <= ARRAY_LEN (lookup));
  return lookup[state];
}

always_inline u32
nat44_session_get_timeout (snat_main_t *sm, snat_session_t *s)
{
  switch (s->proto)
    {
    case IP_PROTOCOL_ICMP:
      /* fallthrough */
    case IP_PROTOCOL_ICMP6:
      return sm->timeouts.icmp;
    case IP_PROTOCOL_UDP:
      return sm->timeouts.udp;
    case IP_PROTOCOL_TCP:
      {
	if (nat44_ed_tcp_is_established (s->tcp_state))
	  return sm->timeouts.tcp.established;
	else
	  return sm->timeouts.tcp.transitory;
      }
    default:
      return sm->timeouts.udp;
    }

  return 0;
}

static_always_inline u8
nat44_ed_maximum_sessions_exceeded (snat_main_t *sm, u32 fib_index,
				    u32 thread_index)
{
  u32 translations;
  translations = pool_elts (sm->per_thread_data[thread_index].sessions);
  if (vec_len (sm->max_translations_per_fib) <= fib_index)
    fib_index = 0;
  return translations >= sm->max_translations_per_fib[fib_index];
}

static_always_inline int
nat_ed_lru_insert (snat_main_per_thread_data_t *tsm, snat_session_t *s,
		   f64 now, u8 proto)
{
  dlist_elt_t *lru_list_elt;
  pool_get (tsm->lru_pool, lru_list_elt);
  s->lru_index = lru_list_elt - tsm->lru_pool;
  switch (proto)
    {
    case IP_PROTOCOL_UDP:
      s->lru_head_index = tsm->udp_lru_head_index;
      break;
    case IP_PROTOCOL_TCP:
      s->lru_head_index = tsm->tcp_trans_lru_head_index;
      break;
    case IP_PROTOCOL_ICMP:
      s->lru_head_index = tsm->icmp_lru_head_index;
      break;
    default:
      s->lru_head_index = tsm->unk_proto_lru_head_index;
      break;
    }
  clib_dlist_addtail (tsm->lru_pool, s->lru_head_index, s->lru_index);
  lru_list_elt->value = s - tsm->sessions;
  s->last_lru_update = now;
  return 1;
}

static_always_inline void
nat_6t_flow_to_ed_k (clib_bihash_kv_16_8_t *kv, nat_6t_flow_t *f)
{
  init_ed_k (kv, f->match.saddr.as_u32, f->match.sport, f->match.daddr.as_u32,
	     f->match.dport, f->match.fib_index, f->match.proto);
}

static_always_inline void
nat_6t_flow_to_ed_kv (clib_bihash_kv_16_8_t *kv, nat_6t_flow_t *f,
		      u32 thread_idx, u32 session_idx)
{
  init_ed_kv (kv, f->match.saddr.as_u32, f->match.sport, f->match.daddr.as_u32,
	      f->match.dport, f->match.fib_index, f->match.proto, thread_idx,
	      session_idx);
}

static_always_inline int
nat_ed_ses_i2o_flow_hash_add_del (snat_main_t *sm, u32 thread_idx,
				  snat_session_t *s, int is_add)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  clib_bihash_kv_16_8_t kv;
  if (0 == is_add)
    {
      nat_6t_flow_to_ed_k (&kv, &s->i2o);
    }
  else
    {
      nat_6t_flow_to_ed_kv (&kv, &s->i2o, thread_idx, s - tsm->sessions);
      nat_6t_l3_l4_csum_calc (&s->i2o);
    }

  ASSERT (thread_idx == s->thread_index);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, is_add);
}

static_always_inline int
nat_ed_ses_o2i_flow_hash_add_del (snat_main_t *sm, u32 thread_idx,
				  snat_session_t *s, int is_add)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  clib_bihash_kv_16_8_t kv;
  if (0 == is_add)
    {
      nat_6t_flow_to_ed_k (&kv, &s->o2i);
    }
  else
    {
      nat_6t_flow_to_ed_kv (&kv, &s->o2i, thread_idx, s - tsm->sessions);
      if (!(s->flags & SNAT_SESSION_FLAG_STATIC_MAPPING))
	{
	  if (nat44_ed_sm_o2i_lookup (sm, s->o2i.match.daddr,
				      s->o2i.match.dport, 0,
				      s->o2i.match.proto))
	    {
	      return -1;
	    }
	}
      nat_6t_l3_l4_csum_calc (&s->o2i);
    }
  ASSERT (thread_idx == s->thread_index);
  return clib_bihash_add_del_16_8 (&sm->flow_hash, &kv, is_add);
}

always_inline void
nat_ed_session_delete (snat_main_t *sm, snat_session_t *ses, u32 thread_index,
		       int lru_delete
		       /* delete from global LRU list */)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);

  if (lru_delete)
    {
      clib_dlist_remove (tsm->lru_pool, ses->lru_index);
    }
  pool_put_index (tsm->lru_pool, ses->lru_index);
  if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, ses, 0))
    nat_elog_warn (sm, "flow hash del failed");
  if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, ses, 0))
    nat_elog_warn (sm, "flow hash del failed");
  pool_put (tsm->sessions, ses);
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));
}

static_always_inline int
nat_lru_free_one_with_head (snat_main_t *sm, int thread_index, f64 now,
			    u32 head_index)
{
  snat_session_t *s = NULL;
  dlist_elt_t *oldest_elt;
  f64 sess_timeout_time;
  u32 oldest_index;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  oldest_index = clib_dlist_remove_head (tsm->lru_pool, head_index);
  if (~0 != oldest_index)
    {
      oldest_elt = pool_elt_at_index (tsm->lru_pool, oldest_index);
      s = pool_elt_at_index (tsm->sessions, oldest_elt->value);

      sess_timeout_time =
	s->last_heard + (f64) nat44_session_get_timeout (sm, s);
      if (now >= sess_timeout_time)
	{
	  nat44_ed_free_session_data (sm, s, thread_index, 0);
	  nat_ed_session_delete (sm, s, thread_index, 0);
	  return 1;
	}
      else
	{
	  clib_dlist_addhead (tsm->lru_pool, head_index, oldest_index);
	}
    }
  return 0;
}

static_always_inline int
nat_lru_free_one (snat_main_t *sm, int thread_index, f64 now)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  int rc = 0;
#define _(p)                                                                  \
  if ((rc = nat_lru_free_one_with_head (sm, thread_index, now,                \
					tsm->p##_lru_head_index)))            \
    {                                                                         \
      return rc;                                                              \
    }
  _ (tcp_trans);
  _ (udp);
  _ (unk_proto);
  _ (icmp);
  _ (tcp_estab);
#undef _
  return 0;
}

static_always_inline snat_session_t *
nat_ed_session_alloc (snat_main_t *sm, u32 thread_index, f64 now, u8 proto)
{
  snat_session_t *s;
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

  nat_lru_free_one (sm, thread_index, now);

  pool_get (tsm->sessions, s);
  clib_memset (s, 0, sizeof (*s));

  nat_ed_lru_insert (tsm, s, now, proto);

  s->ha_last_refreshed = now;
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));
#if CLIB_ASSERT_ENABLE
  s->thread_index = thread_index;
#endif
  return s;
}

// slow path
static_always_inline void
per_vrf_sessions_cleanup (u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions_t *per_vrf_sessions;
  u32 *to_free = 0, *i;

  vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
    {
      if (per_vrf_sessions->expired)
	{
	  if (per_vrf_sessions->ses_count == 0)
	    {
	      vec_add1 (to_free, per_vrf_sessions - tsm->per_vrf_sessions_vec);
	    }
	}
    }

  if (vec_len (to_free))
    {
      vec_foreach (i, to_free)
	{
	  vec_del1 (tsm->per_vrf_sessions_vec, *i);
	}
    }

  vec_free (to_free);
}

// slow path
static_always_inline void
per_vrf_sessions_register_session (snat_session_t *s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions_t *per_vrf_sessions;

  per_vrf_sessions_cleanup (thread_index);

  // s->per_vrf_sessions_index == ~0 ... reuse of old session

  vec_foreach (per_vrf_sessions, tsm->per_vrf_sessions_vec)
    {
      // ignore already expired registrations
      if (per_vrf_sessions->expired)
	continue;

      if ((s->in2out.fib_index == per_vrf_sessions->rx_fib_index) &&
	  (s->out2in.fib_index == per_vrf_sessions->tx_fib_index))
	{
	  goto done;
	}
      if ((s->in2out.fib_index == per_vrf_sessions->tx_fib_index) &&
	  (s->out2in.fib_index == per_vrf_sessions->rx_fib_index))
	{
	  goto done;
	}
    }

  // create a new registration
  vec_add2 (tsm->per_vrf_sessions_vec, per_vrf_sessions, 1);
  clib_memset (per_vrf_sessions, 0, sizeof (*per_vrf_sessions));

  per_vrf_sessions->rx_fib_index = s->in2out.fib_index;
  per_vrf_sessions->tx_fib_index = s->out2in.fib_index;

done:
  s->per_vrf_sessions_index = per_vrf_sessions - tsm->per_vrf_sessions_vec;
  per_vrf_sessions->ses_count++;
}

// fast path
static_always_inline void
per_vrf_sessions_unregister_session (snat_session_t *s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  per_vrf_sessions_t *per_vrf_sessions;

  ASSERT (s->per_vrf_sessions_index != ~0);

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions =
    vec_elt_at_index (tsm->per_vrf_sessions_vec, s->per_vrf_sessions_index);

  ASSERT (per_vrf_sessions->ses_count != 0);

  per_vrf_sessions->ses_count--;
  s->per_vrf_sessions_index = ~0;
}

// fast path
static_always_inline u8
per_vrf_sessions_is_expired (snat_session_t *s, u32 thread_index)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  per_vrf_sessions_t *per_vrf_sessions;

  ASSERT (s->per_vrf_sessions_index != ~0);

  tsm = vec_elt_at_index (sm->per_thread_data, thread_index);
  per_vrf_sessions =
    vec_elt_at_index (tsm->per_vrf_sessions_vec, s->per_vrf_sessions_index);
  return per_vrf_sessions->expired;
}

static_always_inline void
nat_6t_flow_init (nat_6t_flow_t *f, u32 thread_idx, ip4_address_t saddr,
		  u16 sport, ip4_address_t daddr, u16 dport, u32 fib_index,
		  u8 proto, u32 session_idx)
{
  clib_memset (f, 0, sizeof (*f));
  f->match.saddr = saddr;
  f->match.sport = sport;
  f->match.daddr = daddr;
  f->match.dport = dport;
  f->match.proto = proto;
  f->match.fib_index = fib_index;
}

static_always_inline void
nat_6t_i2o_flow_init (snat_main_t *sm, u32 thread_idx, snat_session_t *s,
		      ip4_address_t saddr, u16 sport, ip4_address_t daddr,
		      u16 dport, u32 fib_index, u8 proto)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  nat_6t_flow_init (&s->i2o, thread_idx, saddr, sport, daddr, dport, fib_index,
		    proto, s - tsm->sessions);
}

static_always_inline void
nat_6t_o2i_flow_init (snat_main_t *sm, u32 thread_idx, snat_session_t *s,
		      ip4_address_t saddr, u16 sport, ip4_address_t daddr,
		      u16 dport, u32 fib_index, u8 proto)
{
  snat_main_per_thread_data_t *tsm =
    vec_elt_at_index (sm->per_thread_data, thread_idx);
  nat_6t_flow_init (&s->o2i, thread_idx, saddr, sport, daddr, dport, fib_index,
		    proto, s - tsm->sessions);
}

static_always_inline int
nat_6t_t_eq (nat_6t_t *t1, nat_6t_t *t2)
{
  return t1->as_u64[0] == t2->as_u64[0] && t1->as_u64[1] == t2->as_u64[1];
}

static inline uword
nat_pre_node_fn_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, u32 def_next)
{
  u32 n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from >= 2)
    {
      u32 next0, next1;
      u32 arc_next0, arc_next1;
      vlib_buffer_t *b0, *b1;

      b0 = *b;
      b++;
      b1 = *b;
      b++;

      /* Prefetch next iteration. */
      if (PREDICT_TRUE (n_left_from >= 4))
	{
	  vlib_buffer_t *p2, *p3;

	  p2 = *b;
	  p3 = *(b + 1);

	  vlib_prefetch_buffer_header (p2, LOAD);
	  vlib_prefetch_buffer_header (p3, LOAD);

	  clib_prefetch_load (p2->data);
	  clib_prefetch_load (p3->data);
	}

      next0 = def_next;
      next1 = def_next;

      vnet_feature_next (&arc_next0, b0);
      vnet_feature_next (&arc_next1, b1);

      vnet_buffer2 (b0)->nat.arc_next = arc_next0;
      vnet_buffer2 (b1)->nat.arc_next = arc_next1;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	{
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nat_pre_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->arc_next_index = arc_next0;
	    }
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      nat_pre_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next1;
	      t->arc_next_index = arc_next1;
	    }
	}

      n_left_from -= 2;
      next[0] = next0;
      next[1] = next1;
      next += 2;
    }

  while (n_left_from > 0)
    {
      u32 next0;
      u32 arc_next0;
      vlib_buffer_t *b0;

      b0 = *b;
      b++;

      next0 = def_next;
      vnet_feature_next (&arc_next0, b0);
      vnet_buffer2 (b0)->nat.arc_next = arc_next0;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nat_pre_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->next_index = next0;
	  t->arc_next_index = arc_next0;
	}

      n_left_from--;
      next[0] = next0;
      next++;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

static_always_inline u16
snat_random_port (u16 min, u16 max)
{
  snat_main_t *sm = &snat_main;
  u32 rwide;
  u16 r;

  rwide = random_u32 (&sm->random_seed);
  r = rwide & 0xFFFF;
  if (r >= min && r <= max)
    return r;

  return min + (rwide % (max - min + 1));
}

always_inline u8
is_interface_addr (snat_main_t *sm, vlib_node_runtime_t *node,
		   u32 sw_if_index0, u32 ip4_addr)
{
  snat_runtime_t *rt = (snat_runtime_t *) node->runtime_data;
  u8 ip4_addr_exists;

  if (PREDICT_FALSE (rt->cached_sw_if_index != sw_if_index0))
    {
      ip_lookup_main_t *lm = &sm->ip4_main->lookup_main;
      ip_interface_address_t *ia;
      ip4_address_t *a;

      rt->cached_sw_if_index = ~0;
      hash_free (rt->cached_presence_by_ip4_address);

      foreach_ip_interface_address (
	lm, ia, sw_if_index0, 1 /* honor unnumbered */, ({
	  a = ip_interface_address_get_address (lm, ia);
	  hash_set (rt->cached_presence_by_ip4_address, a->as_u32, 1);
	  rt->cached_sw_if_index = sw_if_index0;
	}));

      if (rt->cached_sw_if_index == ~0)
	return 0;
    }

  ip4_addr_exists = !!hash_get (rt->cached_presence_by_ip4_address, ip4_addr);
  if (PREDICT_FALSE (ip4_addr_exists))
    return 1;
  else
    return 0;
}

always_inline void
nat44_ed_session_reopen (u32 thread_index, snat_session_t *s)
{
  nat_syslog_nat44_sdel (0, s->in2out.fib_index, &s->in2out.addr,
			 s->in2out.port, &s->ext_host_nat_addr,
			 s->ext_host_nat_port, &s->out2in.addr, s->out2in.port,
			 &s->ext_host_addr, s->ext_host_port, s->proto,
			 nat44_ed_is_twice_nat_session (s));

  nat_ipfix_logging_nat44_ses_delete (
    thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32, s->proto,
    s->in2out.port, s->out2in.port, s->in2out.fib_index);
  nat_ipfix_logging_nat44_ses_create (
    thread_index, s->in2out.addr.as_u32, s->out2in.addr.as_u32, s->proto,
    s->in2out.port, s->out2in.port, s->in2out.fib_index);

  nat_syslog_nat44_sadd (0, s->in2out.fib_index, &s->in2out.addr,
			 s->in2out.port, &s->ext_host_nat_addr,
			 s->ext_host_nat_port, &s->out2in.addr, s->out2in.port,
			 &s->ext_host_addr, s->ext_host_port, s->proto, 0);
  s->total_pkts = 0;
  s->total_bytes = 0;
}

always_inline void
nat44_ed_init_tcp_state_stable (snat_main_t *sm)
{
  /* first make sure whole table is initialised in a way where state
   * is not changed, then define special cases */
  nat44_ed_tcp_state_e s;
  for (s = 0; s < NAT44_ED_TCP_N_STATE; ++s)
    {
      int i;
      for (i = 0; i < NAT44_ED_N_DIR; ++i)
	{
	  int j = 0;
	  for (j = 0; j < NAT44_ED_TCP_N_FLAG; ++j)
	    {
	      sm->tcp_state_change_table[s][i][j] = s;
	    }
	}
    }

  /* CLOSED and any kind of SYN -> HALF-OPEN */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_CLOSED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_CLOSED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_SYN_O2I;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_CLOSED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_CLOSED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_SYN_O2I;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_CLOSED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_CLOSED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_SYN_O2I;

  /* HALF-OPEN and any kind of SYN in right direction -> ESTABLISHED */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_SYN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_SYN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_SYN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_SYN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_SYN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_SYN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_ESTABLISHED;

  /* ESTABLISHED and any kind of RST -> RST_TRANS */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_RST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_RST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNRST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNRST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_FINRST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_FINRST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_RST_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_RST_TRANS;

  /* ESTABLISHED and any kind of FIN without RST -> HALF-CLOSED */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_FIN] =
    NAT44_ED_TCP_STATE_FIN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_FIN] =
    NAT44_ED_TCP_STATE_FIN_O2I;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_FIN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_ESTABLISHED][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_FIN_O2I;

  /* HALF-CLOSED and any kind of FIN -> FIN_TRANS */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_FIN] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_FIN] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_FINRST] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_FINRST] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_I2O][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_FIN_TRANS;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_O2I][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_FIN_TRANS;

  /* RST_TRANS and anything non-RST -> ESTABLISHED */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_NONE] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_NONE] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_FIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_FIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_RST_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;

  /* FIN_TRANS and any kind of SYN -> HALF-REOPEN */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNRST] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNRST] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_I2O]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_TRANS][NAT44_ED_DIR_O2I]
			    [NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I;

  /* HALF-REOPEN and any kind of SYN in right direction -> ESTABLISHED */
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O]
			    [NAT44_ED_DIR_O2I][NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I]
			    [NAT44_ED_DIR_I2O][NAT44_ED_TCP_FLAG_SYN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O]
			    [NAT44_ED_DIR_O2I][NAT44_ED_TCP_FLAG_SYNRST] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I]
			    [NAT44_ED_DIR_I2O][NAT44_ED_TCP_FLAG_SYNRST] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O]
			    [NAT44_ED_DIR_O2I][NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I]
			    [NAT44_ED_DIR_I2O][NAT44_ED_TCP_FLAG_SYNFIN] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O]
			    [NAT44_ED_DIR_O2I][NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
  sm->tcp_state_change_table[NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I]
			    [NAT44_ED_DIR_I2O][NAT44_ED_TCP_FLAG_SYNFINRST] =
    NAT44_ED_TCP_STATE_ESTABLISHED;
}

/* TCP state tracking according to RFC 7857 (and RFC 6146, which is referenced
 * by RFC 7857). Our implementation also goes beyond by supporting creation of
 * a new session while old session is in transitory timeout after seeing FIN
 * packets from both sides. */
always_inline void
nat44_set_tcp_session_state (snat_main_t *sm, f64 now, snat_session_t *ses,
			     u8 tcp_flags, u32 thread_index,
			     nat44_ed_dir_e dir)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  nat44_ed_tcp_flag_e flags =
    tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST);

  u8 old_state = ses->tcp_state;
  ses->tcp_state = sm->tcp_state_change_table[ses->tcp_state][dir][flags];

  if (old_state != ses->tcp_state)
    {
      if (nat44_ed_tcp_is_established (ses->tcp_state))
	{
	  if (NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O == old_state ||
	      NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I == old_state)
	    {
	      nat44_ed_session_reopen (thread_index, ses);
	    }
	  ses->lru_head_index = tsm->tcp_estab_lru_head_index;
	}
      else
	{
	  if (NAT44_ED_TCP_STATE_ESTABLISHED == old_state)
	    { // need to update last heard otherwise session might get
	      // immediately timed out if it has been idle longer than
	      // transitory timeout
	      ses->last_heard = now;
	    }
	  ses->lru_head_index = tsm->tcp_trans_lru_head_index;
	}
      ses->last_lru_update = now;
      clib_dlist_remove (tsm->lru_pool, ses->lru_index);
      clib_dlist_addtail (tsm->lru_pool, ses->lru_head_index, ses->lru_index);
    }
}

always_inline void
nat44_set_tcp_session_state_i2o (snat_main_t *sm, f64 now, snat_session_t *ses,
				 u8 tcp_flags, u32 thread_index)
{
  return nat44_set_tcp_session_state (sm, now, ses, tcp_flags, thread_index,
				      NAT44_ED_DIR_I2O);
}

always_inline void
nat44_set_tcp_session_state_o2i (snat_main_t *sm, f64 now, snat_session_t *ses,
				 u8 tcp_flags, u32 thread_index)
{
  return nat44_set_tcp_session_state (sm, now, ses, tcp_flags, thread_index,
				      NAT44_ED_DIR_O2I);
}

always_inline void
nat44_session_update_counters (snat_session_t *s, f64 now, uword bytes,
			       u32 thread_index)
{
  if (NAT44_ED_TCP_STATE_RST_TRANS != s->tcp_state &&
      NAT44_ED_TCP_STATE_FIN_TRANS != s->tcp_state &&
      NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_I2O != s->tcp_state &&
      NAT44_ED_TCP_STATE_FIN_REOPEN_SYN_O2I != s->tcp_state)
    {
      s->last_heard = now;
    }
  s->total_pkts++;
  s->total_bytes += bytes;
}

/** \brief Per-user LRU list maintenance */
always_inline void
nat44_session_update_lru (snat_main_t *sm, snat_session_t *s, u32 thread_index)
{
  /* don't update too often - timeout is in magnitude of seconds anyway */
  if (s->last_heard > s->last_lru_update + 1)
    {
      clib_dlist_remove (sm->per_thread_data[thread_index].lru_pool,
			 s->lru_index);
      clib_dlist_addtail (sm->per_thread_data[thread_index].lru_pool,
			  s->lru_head_index, s->lru_index);
      s->last_lru_update = s->last_heard;
    }
}

static_always_inline int
nat44_ed_is_unk_proto (u8 proto)
{
  static const int lookup_table[256] = {
    [IP_PROTOCOL_TCP] = 1,
    [IP_PROTOCOL_UDP] = 1,
    [IP_PROTOCOL_ICMP] = 1,
    [IP_PROTOCOL_ICMP6] = 1,
  };

  return 1 - lookup_table[proto];
}

#endif /* __included_nat44_ed_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
