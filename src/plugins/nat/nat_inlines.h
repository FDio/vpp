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

#ifndef __included_nat_inlines_h__
#define __included_nat_inlines_h__

#include <vnet/fib/ip4_fib.h>
#include <nat/nat.h>
#include <nat/nat_ha.h>

always_inline u64
calc_nat_key (ip4_address_t addr, u16 port, u32 fib_index, u8 proto)
{
  ASSERT (fib_index <= (1 << 14) - 1);
  ASSERT (proto <= (1 << 3) - 1);
  return (u64) addr.as_u32 << 32 | (u64) port << 16 | fib_index << 3 | (proto
									&
									0x7);
}

always_inline void
split_nat_key (u64 key, ip4_address_t * addr, u16 * port,
	       u32 * fib_index, nat_protocol_t * proto)
{
  if (addr)
    {
      addr->as_u32 = key >> 32;
    }
  if (port)
    {
      *port = (key >> 16) & (u16) ~ 0;
    }
  if (fib_index)
    {
      *fib_index = key >> 3 & ((1 << 13) - 1);
    }
  if (proto)
    {
      *proto = key & 0x7;
    }
}

always_inline void
init_nat_k (clib_bihash_kv_8_8_t * kv, ip4_address_t addr, u16 port,
	    u32 fib_index, nat_protocol_t proto)
{
  kv->key = calc_nat_key (addr, port, fib_index, proto);
  kv->value = ~0ULL;
}

always_inline void
init_nat_kv (clib_bihash_kv_8_8_t * kv, ip4_address_t addr, u16 port,
	     u32 fib_index, nat_protocol_t proto, u64 value)
{
  init_nat_k (kv, addr, port, fib_index, proto);
  kv->value = value;
}

always_inline void
init_nat_i2o_k (clib_bihash_kv_8_8_t * kv, snat_session_t * s)
{
  return init_nat_k (kv, s->in2out.addr, s->in2out.port,
		     s->in2out.fib_index, s->nat_proto);
}

always_inline void
init_nat_i2o_kv (clib_bihash_kv_8_8_t * kv, snat_session_t * s, u64 value)
{
  init_nat_k (kv, s->in2out.addr, s->in2out.port, s->in2out.fib_index,
	      s->nat_proto);
  kv->value = value;
}

always_inline void
init_nat_o2i_k (clib_bihash_kv_8_8_t * kv, snat_session_t * s)
{
  return init_nat_k (kv, s->out2in.addr, s->out2in.port,
		     s->out2in.fib_index, s->nat_proto);
}

always_inline void
init_nat_o2i_kv (clib_bihash_kv_8_8_t * kv, snat_session_t * s, u64 value)
{
  init_nat_k (kv, s->out2in.addr, s->out2in.port, s->out2in.fib_index,
	      s->nat_proto);
  kv->value = value;
}

static inline uword
nat_pre_node_fn_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame, u32 def_next)
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

	  CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, LOAD);
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

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
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

always_inline u8
is_interface_addr (snat_main_t * sm, vlib_node_runtime_t * node,
		   u32 sw_if_index0, u32 ip4_addr)
{
  snat_runtime_t *rt = (snat_runtime_t *) node->runtime_data;
  ip4_address_t *first_int_addr;

  if (PREDICT_FALSE (rt->cached_sw_if_index != sw_if_index0))
    {
      first_int_addr =
	ip4_interface_first_address (sm->ip4_main, sw_if_index0,
				     0 /* just want the address */ );
      rt->cached_sw_if_index = sw_if_index0;
      if (first_int_addr)
	rt->cached_ip4_address = first_int_addr->as_u32;
      else
	rt->cached_ip4_address = 0;
    }

  if (PREDICT_FALSE (ip4_addr == rt->cached_ip4_address))
    return 1;
  else
    return 0;
}

always_inline void
user_session_increment (snat_main_t * sm, snat_user_t * u, u8 is_static)
{
  if (u->nsessions + u->nstaticsessions < sm->max_translations_per_user)
    {
      if (is_static)
	u->nstaticsessions++;
      else
	u->nsessions++;
    }
}

always_inline void
nat44_delete_user_with_no_session (snat_main_t * sm, snat_user_t * u,
				   u32 thread_index)
{
  clib_bihash_kv_8_8_t kv;
  snat_user_key_t u_key;
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       thread_index);

  if (u->nstaticsessions == 0 && u->nsessions == 0)
    {
      u_key.addr.as_u32 = u->addr.as_u32;
      u_key.fib_index = u->fib_index;
      kv.key = u_key.as_u64;
      pool_put_index (tsm->list_pool, u->sessions_per_user_list_head_index);
      pool_put (tsm->users, u);
      clib_bihash_add_del_8_8 (&tsm->user_hash, &kv, 0);
      vlib_set_simple_counter (&sm->total_users, thread_index, 0,
			       pool_elts (tsm->users));
    }
}

always_inline void
nat44_delete_session (snat_main_t * sm, snat_session_t * ses,
		      u32 thread_index)
{
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       thread_index);
  clib_bihash_kv_8_8_t kv, value;
  snat_user_t *u;
  const snat_user_key_t u_key = {
    .addr = ses->in2out.addr,
    .fib_index = ses->in2out.fib_index
  };
  const u8 u_static = snat_is_session_static (ses);

  clib_dlist_remove (tsm->list_pool, ses->per_user_index);
  pool_put_index (tsm->list_pool, ses->per_user_index);
  if (sm->endpoint_dependent)
    {
      clib_dlist_remove (tsm->lru_pool, ses->lru_index);
      pool_put_index (tsm->lru_pool, ses->lru_index);
    }
  pool_put (tsm->sessions, ses);
  vlib_set_simple_counter (&sm->total_sessions, thread_index, 0,
			   pool_elts (tsm->sessions));

  kv.key = u_key.as_u64;
  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
    {
      u = pool_elt_at_index (tsm->users, value.value);
      if (u_static)
	u->nstaticsessions--;
      else
	u->nsessions--;

      nat44_delete_user_with_no_session (sm, u, thread_index);
    }
}

always_inline void
nat44_set_tcp_session_state_i2o (snat_main_t * sm, f64 now,
				 snat_session_t * ses, vlib_buffer_t * b,
				 u32 thread_index)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  u8 tcp_flags = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
  u32 tcp_ack_number = vnet_buffer (b)->ip.reass.tcp_ack_number;
  u32 tcp_seq_number = vnet_buffer (b)->ip.reass.tcp_seq_number;
  if ((ses->state == 0) && (tcp_flags & TCP_FLAG_RST))
    ses->state = NAT44_SES_RST;
  if ((ses->state == NAT44_SES_RST) && !(tcp_flags & TCP_FLAG_RST))
    ses->state = 0;
  if ((tcp_flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_I2O_SYN) &&
      (ses->state & NAT44_SES_O2I_SYN))
    ses->state = 0;
  if (tcp_flags & TCP_FLAG_SYN)
    ses->state |= NAT44_SES_I2O_SYN;
  if (tcp_flags & TCP_FLAG_FIN)
    {
      ses->i2o_fin_seq = clib_net_to_host_u32 (tcp_seq_number);
      ses->state |= NAT44_SES_I2O_FIN;
    }
  if ((tcp_flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_O2I_FIN))
    {
      if (clib_net_to_host_u32 (tcp_ack_number) > ses->o2i_fin_seq)
	{
	  ses->state |= NAT44_SES_O2I_FIN_ACK;
	  if (nat44_is_ses_closed (ses))
	    {			// if session is now closed, save the timestamp
	      ses->tcp_closed_timestamp = now + sm->timeouts.tcp.transitory;
	      ses->last_lru_update = now;
	    }
	}
    }

  // move the session to proper LRU
  if (ses->state)
    {
      ses->lru_head_index = tsm->tcp_trans_lru_head_index;
    }
  else
    {
      ses->lru_head_index = tsm->tcp_estab_lru_head_index;
    }
  clib_dlist_remove (tsm->lru_pool, ses->lru_index);
  clib_dlist_addtail (tsm->lru_pool, ses->lru_head_index, ses->lru_index);
}

always_inline void
nat44_set_tcp_session_state_o2i (snat_main_t * sm, f64 now,
				 snat_session_t * ses, u8 tcp_flags,
				 u32 tcp_ack_number, u32 tcp_seq_number,
				 u32 thread_index)
{
  snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
  if ((ses->state == 0) && (tcp_flags & TCP_FLAG_RST))
    ses->state = NAT44_SES_RST;
  if ((ses->state == NAT44_SES_RST) && !(tcp_flags & TCP_FLAG_RST))
    ses->state = 0;
  if ((tcp_flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_I2O_SYN) &&
      (ses->state & NAT44_SES_O2I_SYN))
    ses->state = 0;
  if (tcp_flags & TCP_FLAG_SYN)
    ses->state |= NAT44_SES_O2I_SYN;
  if (tcp_flags & TCP_FLAG_FIN)
    {
      ses->o2i_fin_seq = clib_net_to_host_u32 (tcp_seq_number);
      ses->state |= NAT44_SES_O2I_FIN;
    }
  if ((tcp_flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_I2O_FIN))
    {
      if (clib_net_to_host_u32 (tcp_ack_number) > ses->i2o_fin_seq)
	ses->state |= NAT44_SES_I2O_FIN_ACK;
      if (nat44_is_ses_closed (ses))
	{			// if session is now closed, save the timestamp
	  ses->tcp_closed_timestamp = now + sm->timeouts.tcp.transitory;
	  ses->last_lru_update = now;
	}
    }
  // move the session to proper LRU
  if (ses->state)
    {
      ses->lru_head_index = tsm->tcp_trans_lru_head_index;
    }
  else
    {
      ses->lru_head_index = tsm->tcp_estab_lru_head_index;
    }
  clib_dlist_remove (tsm->lru_pool, ses->lru_index);
  clib_dlist_addtail (tsm->lru_pool, ses->lru_head_index, ses->lru_index);
}

always_inline u32
nat44_session_get_timeout (snat_main_t * sm, snat_session_t * s)
{
  switch (s->nat_proto)
    {
    case NAT_PROTOCOL_ICMP:
      return sm->timeouts.icmp;
    case NAT_PROTOCOL_UDP:
      return sm->timeouts.udp;
    case NAT_PROTOCOL_TCP:
      {
	if (s->state)
	  return sm->timeouts.tcp.transitory;
	else
	  return sm->timeouts.tcp.established;
      }
    default:
      return sm->timeouts.udp;
    }

  return 0;
}

always_inline void
nat44_session_update_counters (snat_session_t * s, f64 now, uword bytes,
			       u32 thread_index)
{
  s->last_heard = now;
  s->total_pkts++;
  s->total_bytes += bytes;
  nat_ha_sref (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
	       s->ext_host_port, s->nat_proto, s->out2in.fib_index,
	       s->total_pkts, s->total_bytes, thread_index,
	       &s->ha_last_refreshed, now);
}

/** \brief Per-user LRU list maintenance */
always_inline void
nat44_session_update_lru (snat_main_t * sm, snat_session_t * s,
			  u32 thread_index)
{
  /* don't update too often - timeout is in magnitude of seconds anyway */
  if (s->last_heard > s->last_lru_update + 1)
    {
      if (!sm->endpoint_dependent)
	{
	  clib_dlist_remove (sm->per_thread_data[thread_index].list_pool,
			     s->per_user_index);
	  clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
			      s->per_user_list_head_index, s->per_user_index);
	}
      else
	{
	  clib_dlist_remove (sm->per_thread_data[thread_index].lru_pool,
			     s->lru_index);
	  clib_dlist_addtail (sm->per_thread_data[thread_index].lru_pool,
			      s->lru_head_index, s->lru_index);
	}
      s->last_lru_update = s->last_heard;
    }
}

always_inline void
init_ed_k (clib_bihash_kv_16_8_t * kv, ip4_address_t l_addr, u16 l_port,
	   ip4_address_t r_addr, u16 r_port, u32 fib_index, u8 proto)
{
  kv->key[0] = (u64) r_addr.as_u32 << 32 | l_addr.as_u32;
  kv->key[1] =
    (u64) r_port << 48 | (u64) l_port << 32 | fib_index << 8 | proto;
}

always_inline void
init_ed_kv (clib_bihash_kv_16_8_t * kv, ip4_address_t l_addr, u16 l_port,
	    ip4_address_t r_addr, u16 r_port, u32 fib_index, u8 proto,
	    u32 thread_index, u32 session_index)
{
  init_ed_k (kv, l_addr, l_port, r_addr, r_port, fib_index, proto);
  kv->value = (u64) thread_index << 32 | session_index;
}

always_inline u32
ed_value_get_thread_index (clib_bihash_kv_16_8_t * value)
{
  return value->value >> 32;
}

always_inline u32
ed_value_get_session_index (clib_bihash_kv_16_8_t * value)
{
  return value->value & ~(u32) 0;
}

always_inline void
split_ed_kv (clib_bihash_kv_16_8_t * kv,
	     ip4_address_t * l_addr, ip4_address_t * r_addr, u8 * proto,
	     u32 * fib_index, u16 * l_port, u16 * r_port)
{
  if (l_addr)
    {
      l_addr->as_u32 = kv->key[0] & (u32) ~ 0;
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
      *l_port = (kv->key[1] >> 32) & (u16) ~ 0;
    }
  if (fib_index)
    {
      *fib_index = (kv->key[1] >> 8) & ((1 << 24) - 1);
    }
  if (proto)
    {
      *proto = kv->key[1] & (u8) ~ 0;
    }
}

static_always_inline int
nat_get_icmp_session_lookup_values (vlib_buffer_t * b, ip4_header_t * ip0,
				    ip4_address_t * lookup_saddr,
				    u16 * lookup_sport,
				    ip4_address_t * lookup_daddr,
				    u16 * lookup_dport, u8 * lookup_protocol)
{
  icmp46_header_t *icmp0;
  icmp_echo_header_t *echo0, *inner_echo0 = 0;
  ip4_header_t *inner_ip0 = 0;
  void *l4_header = 0;
  icmp46_header_t *inner_icmp0;

  icmp0 = (icmp46_header_t *) ip4_next_header (ip0);
  echo0 = (icmp_echo_header_t *) (icmp0 + 1);

  if (!icmp_type_is_error_message
      (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
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
      switch (ip_proto_to_nat_proto (inner_ip0->protocol))
	{
	case NAT_PROTOCOL_ICMP:
	  inner_icmp0 = (icmp46_header_t *) l4_header;
	  inner_echo0 = (icmp_echo_header_t *) (inner_icmp0 + 1);
	  *lookup_sport = inner_echo0->identifier;
	  *lookup_dport = inner_echo0->identifier;
	  break;
	case NAT_PROTOCOL_UDP:
	case NAT_PROTOCOL_TCP:
	  *lookup_sport = ((tcp_udp_header_t *) l4_header)->dst_port;
	  *lookup_dport = ((tcp_udp_header_t *) l4_header)->src_port;
	  break;
	default:
	  return NAT_IN2OUT_ED_ERROR_UNSUPPORTED_PROTOCOL;
	}
    }
  return 0;
}

/**
 * @brief Check if packet should be translated
 *
 * Packets aimed at outside interface and external address with active session
 * should be translated.
 *
 * @param sm            NAT main
 * @param rt            NAT runtime data
 * @param sw_if_index0  index of the inside interface
 * @param ip0           IPv4 header
 * @param proto0        NAT protocol
 * @param rx_fib_index0 RX FIB index
 *
 * @returns 0 if packet should be translated otherwise 1
 */
static inline int
snat_not_translate_fast (snat_main_t * sm, vlib_node_runtime_t * node,
			 u32 sw_if_index0, ip4_header_t * ip0, u32 proto0,
			 u32 rx_fib_index0)
{
  if (sm->out2in_dpo)
    return 0;

  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;
  nat_outside_fib_t *outside_fib;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr = {
		.ip4.as_u32 = ip0->dst_address.as_u32,
		}
    ,
  };

  /* Don't NAT packet aimed at the intfc address */
  if (PREDICT_FALSE (is_interface_addr (sm, node, sw_if_index0,
					ip0->dst_address.as_u32)))
    return 1;

  fei = fib_table_lookup (rx_fib_index0, &pfx);
  if (FIB_NODE_INDEX_INVALID != fei)
    {
      u32 sw_if_index = fib_entry_get_resolving_interface (fei);
      if (sw_if_index == ~0)
	{
	  vec_foreach (outside_fib, sm->outside_fibs)
	  {
	    fei = fib_table_lookup (outside_fib->fib_index, &pfx);
	    if (FIB_NODE_INDEX_INVALID != fei)
	      {
		sw_if_index = fib_entry_get_resolving_interface (fei);
		if (sw_if_index != ~0)
		  break;
	      }
	  }
	}
      if (sw_if_index == ~0)
	return 1;

      snat_interface_t *i;
      /* *INDENT-OFF* */
      pool_foreach (i, sm->interfaces, ({
        /* NAT packet aimed at outside interface */
	if ((nat_interface_is_outside (i)) && (sw_if_index == i->sw_if_index))
          return 0;
      }));
      /* *INDENT-ON* */
    }

  return 1;
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

#endif /* __included_nat_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
