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

always_inline u32
ip_proto_to_snat_proto (u8 ip_proto)
{
  u32 snat_proto = ~0;

  snat_proto = (ip_proto == IP_PROTOCOL_UDP) ? SNAT_PROTOCOL_UDP : snat_proto;
  snat_proto = (ip_proto == IP_PROTOCOL_TCP) ? SNAT_PROTOCOL_TCP : snat_proto;
  snat_proto =
    (ip_proto == IP_PROTOCOL_ICMP) ? SNAT_PROTOCOL_ICMP : snat_proto;
  snat_proto =
    (ip_proto == IP_PROTOCOL_ICMP6) ? SNAT_PROTOCOL_ICMP : snat_proto;

  return snat_proto;
}

always_inline u8
snat_proto_to_ip_proto (snat_protocol_t snat_proto)
{
  u8 ip_proto = ~0;

  ip_proto = (snat_proto == SNAT_PROTOCOL_UDP) ? IP_PROTOCOL_UDP : ip_proto;
  ip_proto = (snat_proto == SNAT_PROTOCOL_TCP) ? IP_PROTOCOL_TCP : ip_proto;
  ip_proto = (snat_proto == SNAT_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP : ip_proto;

  return ip_proto;
}

static_always_inline u8
icmp_is_error_message (icmp46_header_t * icmp)
{
  switch (icmp->type)
    {
    case ICMP4_destination_unreachable:
    case ICMP4_time_exceeded:
    case ICMP4_parameter_problem:
    case ICMP4_source_quench:
    case ICMP4_redirect:
    case ICMP4_alternate_host_address:
      return 1;
    }
  return 0;
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

always_inline u8
maximum_sessions_exceeded (snat_main_t * sm, u32 thread_index)
{
  if (pool_elts (sm->per_thread_data[thread_index].sessions) >=
      sm->max_translations)
    return 1;

  return 0;
}

always_inline void
nat_send_all_to_node (vlib_main_t * vm, u32 * bi_vector,
		      vlib_node_runtime_t * node, vlib_error_t * error,
		      u32 next)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;

  from = bi_vector;
  n_left_from = vec_len (bi_vector);
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_buffer_t *p0 = vlib_get_buffer (vm, bi0);
	  if (error)
	    p0->error = *error;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
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
    }
}

always_inline void
nat44_delete_session (snat_main_t * sm, snat_session_t * ses,
		      u32 thread_index)
{
  snat_main_per_thread_data_t *tsm = vec_elt_at_index (sm->per_thread_data,
						       thread_index);
  clib_bihash_kv_8_8_t kv, value;
  snat_user_key_t u_key;
  snat_user_t *u;

  nat_log_debug ("session deleted %U", format_snat_session, tsm, ses);

  clib_dlist_remove (tsm->list_pool, ses->per_user_index);
  pool_put_index (tsm->list_pool, ses->per_user_index);
  pool_put (tsm->sessions, ses);

  u_key.addr = ses->in2out.addr;
  u_key.fib_index = ses->in2out.fib_index;
  kv.key = u_key.as_u64;
  if (!clib_bihash_search_8_8 (&tsm->user_hash, &kv, &value))
    {
      u = pool_elt_at_index (tsm->users, value.value);
      if (snat_is_session_static (ses))
	u->nstaticsessions--;
      else
	u->nsessions--;

      nat44_delete_user_with_no_session (sm, u, thread_index);
    }
}

/** \brief Set TCP session state.
    @return 1 if session was closed, otherwise 0
*/
always_inline int
nat44_set_tcp_session_state_i2o (snat_main_t * sm, snat_session_t * ses,
				 tcp_header_t * tcp, u32 thread_index)
{
  if ((ses->state == 0) && (tcp->flags & TCP_FLAG_RST))
    ses->state = NAT44_SES_RST;
  if ((ses->state == NAT44_SES_RST) && !(tcp->flags & TCP_FLAG_RST))
    ses->state = 0;
  if ((tcp->flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_I2O_SYN) &&
      (ses->state & NAT44_SES_O2I_SYN))
    ses->state = 0;
  if (tcp->flags & TCP_FLAG_SYN)
    ses->state |= NAT44_SES_I2O_SYN;
  if (tcp->flags & TCP_FLAG_FIN)
    {
      ses->i2o_fin_seq = clib_net_to_host_u32 (tcp->seq_number);
      ses->state |= NAT44_SES_I2O_FIN;
    }
  if ((tcp->flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_O2I_FIN))
    {
      if (clib_net_to_host_u32 (tcp->ack_number) > ses->o2i_fin_seq)
	ses->state |= NAT44_SES_O2I_FIN_ACK;
    }
  if (nat44_is_ses_closed (ses)
      && !(ses->flags & SNAT_SESSION_FLAG_OUTPUT_FEATURE))
    {
      nat_log_debug ("TCP close connection %U", format_snat_session,
		     &sm->per_thread_data[thread_index], ses);
      nat_free_session_data (sm, ses, thread_index);
      nat44_delete_session (sm, ses, thread_index);
      return 1;
    }
  return 0;
}

always_inline int
nat44_set_tcp_session_state_o2i (snat_main_t * sm, snat_session_t * ses,
				 tcp_header_t * tcp, u32 thread_index)
{
  if ((ses->state == 0) && (tcp->flags & TCP_FLAG_RST))
    ses->state = NAT44_SES_RST;
  if ((ses->state == NAT44_SES_RST) && !(tcp->flags & TCP_FLAG_RST))
    ses->state = 0;
  if ((tcp->flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_I2O_SYN) &&
      (ses->state & NAT44_SES_O2I_SYN))
    ses->state = 0;
  if (tcp->flags & TCP_FLAG_SYN)
    ses->state |= NAT44_SES_O2I_SYN;
  if (tcp->flags & TCP_FLAG_FIN)
    {
      ses->o2i_fin_seq = clib_net_to_host_u32 (tcp->seq_number);
      ses->state |= NAT44_SES_O2I_FIN;
    }
  if ((tcp->flags & TCP_FLAG_ACK) && (ses->state & NAT44_SES_I2O_FIN))
    {
      if (clib_net_to_host_u32 (tcp->ack_number) > ses->i2o_fin_seq)
	ses->state |= NAT44_SES_I2O_FIN_ACK;
    }
  if (nat44_is_ses_closed (ses))
    {
      nat_log_debug ("TCP close connection %U", format_snat_session,
		     &sm->per_thread_data[thread_index], ses);
      nat_free_session_data (sm, ses, thread_index);
      nat44_delete_session (sm, ses, thread_index);
      return 1;
    }
  return 0;
}

always_inline u32
nat44_session_get_timeout (snat_main_t * sm, snat_session_t * s)
{
  switch (s->in2out.protocol)
    {
    case SNAT_PROTOCOL_ICMP:
      return sm->icmp_timeout;
    case SNAT_PROTOCOL_UDP:
      return sm->udp_timeout;
    case SNAT_PROTOCOL_TCP:
      {
	if (s->state)
	  return sm->tcp_transitory_timeout;
	else
	  return sm->tcp_established_timeout;
      }
    default:
      return sm->udp_timeout;
    }

  return 0;
}

always_inline void
nat44_session_update_counters (snat_session_t * s, f64 now, uword bytes)
{
  s->last_heard = now;
  s->total_pkts++;
  s->total_bytes += bytes;
}

/** \brief Per-user LRU list maintenance */
always_inline void
nat44_session_update_lru (snat_main_t * sm, snat_session_t * s,
			  u32 thread_index)
{
  clib_dlist_remove (sm->per_thread_data[thread_index].list_pool,
		     s->per_user_index);
  clib_dlist_addtail (sm->per_thread_data[thread_index].list_pool,
		      s->per_user_list_head_index, s->per_user_index);
}

always_inline void
make_ed_kv (clib_bihash_kv_16_8_t * kv, ip4_address_t * l_addr,
	    ip4_address_t * r_addr, u8 proto, u32 fib_index, u16 l_port,
	    u16 r_port)
{
  nat_ed_ses_key_t *key = (nat_ed_ses_key_t *) kv->key;

  key->l_addr.as_u32 = l_addr->as_u32;
  key->r_addr.as_u32 = r_addr->as_u32;
  key->fib_index = fib_index;
  key->proto = proto;
  key->l_port = l_port;
  key->r_port = r_port;

  kv->value = ~0ULL;
}

always_inline void
make_sm_kv (clib_bihash_kv_8_8_t * kv, ip4_address_t * addr, u8 proto,
	    u32 fib_index, u16 port)
{
  snat_session_key_t key;

  key.addr.as_u32 = addr->as_u32;
  key.port = port;
  key.protocol = proto;
  key.fib_index = fib_index;

  kv->key = key.as_u64;
  kv->value = ~0ULL;
}

always_inline void
mss_clamping (snat_main_t * sm, tcp_header_t * tcp, ip_csum_t * sum)
{
  u8 *data;
  u8 opt_len, opts_len, kind;
  u16 mss;

  if (!(sm->mss_clamping && tcp_syn (tcp)))
    return;

  opts_len = (tcp_doff (tcp) << 2) - sizeof (tcp_header_t);
  data = (u8 *) (tcp + 1);
  for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
      kind = data[0];

      if (kind == TCP_OPTION_EOL)
	break;
      else if (kind == TCP_OPTION_NOOP)
	{
	  opt_len = 1;
	  continue;
	}
      else
	{
	  if (opts_len < 2)
	    return;
	  opt_len = data[1];

	  if (opt_len < 2 || opt_len > opts_len)
	    return;
	}

      if (kind == TCP_OPTION_MSS)
	{
	  mss = *(u16 *) (data + 2);
	  if (clib_net_to_host_u16 (mss) > sm->mss_clamping)
	    {
	      *sum =
		ip_csum_update (*sum, mss, sm->mss_value_net, ip4_header_t,
				length);
	      clib_memcpy (data + 2, &sm->mss_value_net, 2);
	    }
	  return;
	}
    }
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
      pool_foreach (i, sm->interfaces, (
					 {
					 /* NAT packet aimed at outside interface */
					 if ((nat_interface_is_outside (i))
					     && (sw_if_index ==
						 i->sw_if_index)) return 0;}
		    ));
    }

  return 1;
}

#endif /* __included_nat_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
