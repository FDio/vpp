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


/* ICMPv4 invert type for stateful ACL */
static const u8 icmp4_invmap[] = {
  [ICMP4_echo_reply] = ICMP4_echo_request + 1,
  [ICMP4_timestamp_reply] = ICMP4_timestamp_request + 1,
  [ICMP4_information_reply] = ICMP4_information_request + 1,
  [ICMP4_address_mask_reply] = ICMP4_address_mask_request + 1
};

/* Supported ICMPv4 messages for session creation */
static const u8 icmp4_valid_new[] = {
  [ICMP4_echo_request] = 1,
  [ICMP4_timestamp_request] = 1,
  [ICMP4_information_request] = 1,
  [ICMP4_address_mask_request] = 1
};

/* ICMPv6 invert type for stateful ACL */
static const u8 icmp6_invmap[] = {
  [ICMP6_echo_reply - 128] = ICMP6_echo_request + 1,
  [ICMP6_node_information_response - 128] = ICMP6_node_information_request + 1
};

/* Supported ICMPv6 messages for session creation */
static const u8 icmp6_valid_new[] = {
  [ICMP6_echo_request - 128] = 1,
  [ICMP6_node_information_request - 128] = 1
};

/* IP4 and IP6 protocol numbers of ICMP */
static u8 icmp_protos[] = { IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMP6 };



always_inline int
acl_fa_ifc_has_sessions (acl_main_t * am, int sw_if_index0)
{
  return am->fa_sessions_hash_is_initialized;
}

always_inline int
acl_fa_ifc_has_in_acl (acl_main_t * am, int sw_if_index0)
{
  int it_has = clib_bitmap_get (am->fa_in_acl_on_sw_if_index, sw_if_index0);
  return it_has;
}

always_inline int
acl_fa_ifc_has_out_acl (acl_main_t * am, int sw_if_index0)
{
  int it_has = clib_bitmap_get (am->fa_out_acl_on_sw_if_index, sw_if_index0);
  return it_has;
}

/* Session keys match the packets received, and mirror the packets sent */
always_inline u32
acl_make_5tuple_session_key (acl_main_t * am, int is_input, int is_ip6,
			     u32 sw_if_index, fa_5tuple_t * p5tuple_pkt,
			     fa_5tuple_t * p5tuple_sess)
{
  int src_index = is_input ? 0 : 1;
  int dst_index = is_input ? 1 : 0;
  u32 valid_new_sess = 1;
  p5tuple_sess->addr[src_index] = p5tuple_pkt->addr[0];
  p5tuple_sess->addr[dst_index] = p5tuple_pkt->addr[1];
  p5tuple_sess->l4.as_u64 = p5tuple_pkt->l4.as_u64;

  if (PREDICT_TRUE (p5tuple_pkt->l4.proto != icmp_protos[is_ip6]))
    {
      p5tuple_sess->l4.port[src_index] = p5tuple_pkt->l4.port[0];
      p5tuple_sess->l4.port[dst_index] = p5tuple_pkt->l4.port[1];
    }
  else
    {
      static const u8 *icmp_invmap[] = { icmp4_invmap, icmp6_invmap };
      static const u8 *icmp_valid_new[] =
	{ icmp4_valid_new, icmp6_valid_new };
      static const u8 icmp_invmap_size[] = { sizeof (icmp4_invmap),
	sizeof (icmp6_invmap)
      };
      static const u8 icmp_valid_new_size[] = { sizeof (icmp4_valid_new),
	sizeof (icmp6_valid_new)
      };
      int type =
	is_ip6 ? p5tuple_pkt->l4.port[0] - 128 : p5tuple_pkt->l4.port[0];

      p5tuple_sess->l4.port[0] = p5tuple_pkt->l4.port[0];
      p5tuple_sess->l4.port[1] = p5tuple_pkt->l4.port[1];

      /*
       * Invert ICMP type for valid icmp_invmap messages:
       *  1) input node with outbound ACL interface
       *  2) output node with inbound ACL interface
       *
       */
      if ((is_input && acl_fa_ifc_has_out_acl (am, sw_if_index)) ||
	  (!is_input && acl_fa_ifc_has_in_acl (am, sw_if_index)))
	{
	  if (type >= 0 &&
	      type <= icmp_invmap_size[is_ip6] && icmp_invmap[is_ip6][type])
	    {
	      p5tuple_sess->l4.port[0] = icmp_invmap[is_ip6][type] - 1;
	    }
	}

      /*
       * ONLY ICMP messages defined in icmp4_valid_new/icmp6_valid_new table
       * are allowed to create stateful ACL.
       * The other messages will be forwarded without creating a reflexive ACL.
       */
      if (type < 0 ||
	  type > icmp_valid_new_size[is_ip6] || !icmp_valid_new[is_ip6][type])
	{
	  valid_new_sess = 0;
	}
    }

  return valid_new_sess;
}

always_inline int
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

/*
 * Get the idle timeout of a session.
 */

always_inline u64
fa_session_get_timeout (acl_main_t * am, fa_session_t * sess)
{
  u64 timeout = am->vlib_main->clib_time.clocks_per_second;
  int timeout_type = fa_session_get_timeout_type (am, sess);
  timeout *= am->session_timeout_sec[timeout_type];
  return timeout;
}



always_inline fa_session_t *
get_session_ptr (acl_main_t * am, u16 thread_index, u32 session_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  fa_session_t *sess = pool_is_free_index (pw->fa_sessions_pool,
					   session_index) ? 0 :
    pool_elt_at_index (pw->fa_sessions_pool,
		       session_index);
  return sess;
}

always_inline int
is_valid_session_ptr (acl_main_t * am, u16 thread_index, fa_session_t * sess)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  return ((sess != 0)
	  && ((sess - pw->fa_sessions_pool) <
	      pool_len (pw->fa_sessions_pool)));
}

always_inline void
acl_fa_conn_list_add_session (acl_main_t * am, fa_full_session_id_t sess_id,
			      u64 now)
{
  fa_session_t *sess =
    get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
  u8 list_id = fa_session_get_timeout_type (am, sess);
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
  if (~0 != pw->fa_conn_list_tail[list_id])
    {
      fa_session_t *prev_sess =
	get_session_ptr (am, thread_index, pw->fa_conn_list_tail[list_id]);
      prev_sess->link_next_idx = sess_id.session_index;
      /* We should never try to link with a session on another thread */
      ASSERT (prev_sess->thread_index == sess->thread_index);
    }
  pw->fa_conn_list_tail[list_id] = sess_id.session_index;

#ifdef FA_NODE_VERBOSE_DEBUG
  clib_warning
    ("FA-SESSION-DEBUG: add session id %d on thread %d sw_if_index %d",
     sess_id.session_index, thread_index, sess->sw_if_index);
#endif
  pw->serviced_sw_if_index_bitmap =
    clib_bitmap_set (pw->serviced_sw_if_index_bitmap, sess->sw_if_index, 1);

  if (~0 == pw->fa_conn_list_head[list_id])
    {
      pw->fa_conn_list_head[list_id] = sess_id.session_index;
    }
}

static int
acl_fa_conn_list_delete_session (acl_main_t * am,
				 fa_full_session_id_t sess_id)
{
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  if (thread_index != sess_id.thread_index)
    {
      /* If another thread attempts to delete the session, fail it. */
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("thread id in key %d != curr thread index, not deleting");
#endif
      return 0;
    }
  fa_session_t *sess =
    get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
  /* we should never try to delete the session with another thread index */
  ASSERT (sess->thread_index == thread_index);
  if (~0 != sess->link_prev_idx)
    {
      fa_session_t *prev_sess =
	get_session_ptr (am, thread_index, sess->link_prev_idx);
      /* the previous session must be in the same list as this one */
      ASSERT (prev_sess->link_list_id == sess->link_list_id);
      prev_sess->link_next_idx = sess->link_next_idx;
    }
  if (~0 != sess->link_next_idx)
    {
      fa_session_t *next_sess =
	get_session_ptr (am, thread_index, sess->link_next_idx);
      /* The next session must be in the same list as the one we are deleting */
      ASSERT (next_sess->link_list_id == sess->link_list_id);
      next_sess->link_prev_idx = sess->link_prev_idx;
    }
  if (pw->fa_conn_list_head[sess->link_list_id] == sess_id.session_index)
    {
      pw->fa_conn_list_head[sess->link_list_id] = sess->link_next_idx;
    }
  if (pw->fa_conn_list_tail[sess->link_list_id] == sess_id.session_index)
    {
      pw->fa_conn_list_tail[sess->link_list_id] = sess->link_prev_idx;
    }
  return 1;
}

always_inline int
acl_fa_restart_timer_for_session (acl_main_t * am, u64 now,
				  fa_full_session_id_t sess_id)
{
  if (acl_fa_conn_list_delete_session (am, sess_id))
    {
      acl_fa_conn_list_add_session (am, sess_id, now);
      return 1;
    }
  else
    {
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


always_inline u8
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


always_inline void
acl_fa_delete_session (acl_main_t * am, u32 sw_if_index,
		       fa_full_session_id_t sess_id)
{
  void *oldheap = clib_mem_set_heap (am->acl_mheap);
  fa_session_t *sess =
    get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
  ASSERT (sess->thread_index == os_get_thread_index ());
  clib_bihash_add_del_40_8 (&am->fa_sessions_hash, &sess->info.kv, 0);
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[sess_id.thread_index];
  pool_put_index (pw->fa_sessions_pool, sess_id.session_index);
  /* Deleting from timer structures not needed,
     as the caller must have dealt with the timers. */
  vec_validate (pw->fa_session_dels_by_sw_if_index, sw_if_index);
  clib_mem_set_heap (oldheap);
  pw->fa_session_dels_by_sw_if_index[sw_if_index]++;
  clib_smp_atomic_add (&am->fa_session_total_dels, 1);
}

always_inline int
acl_fa_can_add_session (acl_main_t * am, int is_input, u32 sw_if_index)
{
  u64 curr_sess_count;
  curr_sess_count = am->fa_session_total_adds - am->fa_session_total_dels;
  return (curr_sess_count < am->fa_conn_table_max_entries);
}


always_inline void
acl_fa_try_recycle_session (acl_main_t * am, int is_input, u16 thread_index,
			    u32 sw_if_index)
{
  /* try to recycle a TCP transient session */
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  u8 timeout_type = ACL_TIMEOUT_TCP_TRANSIENT;
  fa_full_session_id_t sess_id;
  sess_id.session_index = pw->fa_conn_list_head[timeout_type];
  if (~0 != sess_id.session_index)
    {
      sess_id.thread_index = thread_index;
      acl_fa_conn_list_delete_session (am, sess_id);
      acl_fa_delete_session (am, sw_if_index, sess_id);
    }
}

always_inline fa_session_t *
acl_fa_add_session (acl_main_t * am, int is_input, u32 sw_if_index, u64 now,
		    fa_5tuple_t * p5tuple, u16 current_policy_epoch)
{
  clib_bihash_kv_40_8_t *pkv = &p5tuple->kv;
  clib_bihash_kv_40_8_t kv;
  fa_full_session_id_t f_sess_id;
  uword thread_index = os_get_thread_index ();
  void *oldheap = clib_mem_set_heap (am->acl_mheap);
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  f_sess_id.thread_index = thread_index;
  fa_session_t *sess;

  pool_get_aligned (pw->fa_sessions_pool, sess, CLIB_CACHE_LINE_BYTES);
  f_sess_id.session_index = sess - pw->fa_sessions_pool;
  f_sess_id.intf_policy_epoch = current_policy_epoch;

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



  ASSERT (am->fa_sessions_hash_is_initialized == 1);
  clib_bihash_add_del_40_8 (&am->fa_sessions_hash, &kv, 1);
  acl_fa_conn_list_add_session (am, f_sess_id, now);

  vec_validate (pw->fa_session_adds_by_sw_if_index, sw_if_index);
  clib_mem_set_heap (oldheap);
  pw->fa_session_adds_by_sw_if_index[sw_if_index]++;
  clib_smp_atomic_add (&am->fa_session_total_adds, 1);
  return sess;
}

always_inline int
acl_fa_find_session (acl_main_t * am, u32 sw_if_index0, fa_5tuple_t * p5tuple,
		     clib_bihash_kv_40_8_t * pvalue_sess)
{
  return (clib_bihash_search_40_8
	  (&am->fa_sessions_hash, &p5tuple->kv, pvalue_sess) == 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
