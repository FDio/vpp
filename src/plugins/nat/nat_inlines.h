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

always_inline int
nat44_set_tcp_session_state_o2i (snat_main_t * sm, snat_session_t * ses,
				 tcp_header_t * tcp, u32 thread_index)
{
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

#endif /* __included_nat_inlines_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
