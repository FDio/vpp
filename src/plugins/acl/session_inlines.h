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
  [ICMP4_echo_request] = ICMP4_echo_reply + 1,
  [ICMP4_timestamp_request] = ICMP4_timestamp_reply + 1,
  [ICMP4_information_request] = ICMP4_information_reply + 1,
  [ICMP4_address_mask_request] = ICMP4_address_mask_reply + 1
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
  [ICMP6_echo_request - 128] = ICMP6_echo_reply + 1,
  [ICMP6_node_information_request - 128] = ICMP6_node_information_response + 1
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

always_inline int
fa_session_get_timeout_type (acl_main_t * am, fa_session_t * sess)
{
  /* seen both SYNs and ACKs but not FINs means we are in established state */
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
  u64 timeout = (am->vlib_main->clib_time.clocks_per_second);
  if (sess->link_list_id == ACL_TIMEOUT_PURGATORY)
    {
      timeout /= (1000000 / SESSION_PURGATORY_TIMEOUT_USEC);
    }
  else
    {
      int timeout_type = fa_session_get_timeout_type (am, sess);
      timeout *= am->session_timeout_sec[timeout_type];
    }
  return timeout;
}

always_inline fa_session_t *
get_session_ptr_no_check (acl_main_t * am, u16 thread_index,
			  u32 session_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  return pool_elt_at_index (pw->fa_sessions_pool, session_index);
}


always_inline fa_session_t *
get_session_ptr (acl_main_t * am, u16 thread_index, u32 session_index)
{
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  if (PREDICT_FALSE (session_index >= vec_len (pw->fa_sessions_pool)))
    return 0;

  return pool_elt_at_index (pw->fa_sessions_pool, session_index);
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
  u8 list_id =
    sess->deleted ? ACL_TIMEOUT_PURGATORY : fa_session_get_timeout_type (am,
									 sess);
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  /* the retrieved session thread index must be necessarily the same as the one in the key */
  ASSERT (sess->thread_index == sess_id.thread_index);
  /* the retrieved session thread index must be the same as current thread */
  ASSERT (sess->thread_index == thread_index);
  sess->link_enqueue_time = now;
  sess->link_list_id = list_id;
  sess->link_next_idx = FA_SESSION_BOGUS_INDEX;
  sess->link_prev_idx = pw->fa_conn_list_tail[list_id];
  if (FA_SESSION_BOGUS_INDEX != pw->fa_conn_list_tail[list_id])
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

  if (FA_SESSION_BOGUS_INDEX == pw->fa_conn_list_head[list_id])
    {
      pw->fa_conn_list_head[list_id] = sess_id.session_index;
      /* set the head expiry time because it is the first element */
      pw->fa_conn_list_head_expiry_time[list_id] =
	now + fa_session_get_timeout (am, sess);
    }
}

static int
acl_fa_conn_list_delete_session (acl_main_t * am,
				 fa_full_session_id_t sess_id, u64 now)
{
  uword thread_index = sess_id.thread_index; // os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  //   if (thread_index != sess_id.thread_index)
  //     {
  //       /* If another thread attempts to delete the session, fail it. */
  // #ifdef FA_NODE_VERBOSE_DEBUG
  //       clib_warning ("thread id in key %d != curr thread index, not
  //       deleting");
  // #endif
  //       return 0;
  //     }
  fa_session_t *sess =
    get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
  u64 next_expiry_time = ~0ULL;
  /* we should never try to delete the session with another thread index */
  //  if (sess->thread_index != os_get_thread_index ())
  //    {
  //      clib_error
  // ("Attempting to delete session belonging to thread %d by thread %d",
  //  sess->thread_index, thread_index);
  //    }
  if (FA_SESSION_BOGUS_INDEX != sess->link_prev_idx)
    {
      fa_session_t *prev_sess =
	get_session_ptr (am, thread_index, sess->link_prev_idx);
      /* the previous session must be in the same list as this one */
      ASSERT (prev_sess->link_list_id == sess->link_list_id);
      prev_sess->link_next_idx = sess->link_next_idx;
    }
  if (FA_SESSION_BOGUS_INDEX != sess->link_next_idx)
    {
      fa_session_t *next_sess =
	get_session_ptr (am, thread_index, sess->link_next_idx);
      /* The next session must be in the same list as the one we are deleting */
      ASSERT (next_sess->link_list_id == sess->link_list_id);
      next_sess->link_prev_idx = sess->link_prev_idx;
      next_expiry_time = now + fa_session_get_timeout (am, next_sess);
    }
  if (pw->fa_conn_list_head[sess->link_list_id] == sess_id.session_index)
    {
      pw->fa_conn_list_head[sess->link_list_id] = sess->link_next_idx;
      pw->fa_conn_list_head_expiry_time[sess->link_list_id] =
	next_expiry_time;
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
  if (acl_fa_conn_list_delete_session (am, sess_id, now))
    {
      acl_fa_conn_list_add_session (am, sess_id, now);
      return 1;
    }
  else
    {
      /*
       * Our thread does not own this connection, so we can not requeue
       * The session. So we post the signal to the owner.
       */
      aclp_post_session_change_request (am, sess_id.thread_index,
					sess_id.session_index,
					ACL_FA_REQ_SESS_RESCHEDULE);
      return 0;
    }
}

always_inline int
is_ip6_5tuple (fa_5tuple_t * p5t)
{
  return (p5t->l3_zero_pad[0] | p5t->
	  l3_zero_pad[1] | p5t->l3_zero_pad[2] | p5t->l3_zero_pad[3] | p5t->
	  l3_zero_pad[4] | p5t->l3_zero_pad[5]) != 0;
}

always_inline u8
acl_fa_track_session (acl_main_t * am, int is_input, u32 sw_if_index, u64 now,
		      fa_session_t * sess, fa_5tuple_t * pkt_5tuple,
		      u32 pkt_len)
{
  sess->last_active_time = now;
  u8 old_flags = sess->tcp_flags_seen.as_u8[is_input];
  u8 new_flags = old_flags | pkt_5tuple->pkt.tcp_flags;

  int flags_need_update = pkt_5tuple->pkt.tcp_flags_valid
    && (old_flags != new_flags);
  if (PREDICT_FALSE (flags_need_update))
    {
      sess->tcp_flags_seen.as_u8[is_input] = new_flags;
    }
  return 3;
}

always_inline u64
reverse_l4_u64_fastpath (u64 l4, int is_ip6)
{
  fa_session_l4_key_t l4i = {.as_u64 = l4 };
  fa_session_l4_key_t l4o;

  l4o.port[1] = l4i.port[0];
  l4o.port[0] = l4i.port[1];

  l4o.non_port_l4_data = l4i.non_port_l4_data;
  l4o.l4_flags = l4i.l4_flags ^ FA_SK_L4_FLAG_IS_INPUT;
  return l4o.as_u64;
}

always_inline int
reverse_l4_u64_slowpath_valid (u64 l4, int is_ip6, u64 * out)
{
  fa_session_l4_key_t l4i = {.as_u64 = l4 };
  fa_session_l4_key_t l4o;

  if (l4i.proto == icmp_protos[is_ip6])
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
      int type = is_ip6 ? l4i.port[0] - 128 : l4i.port[0];

      l4o.non_port_l4_data = l4i.non_port_l4_data;
      l4o.port[0] = l4i.port[0];
      l4o.port[1] = l4i.port[1];


      /*
       * ONLY ICMP messages defined in icmp4_valid_new/icmp6_valid_new table
       * are allowed to create stateful ACL.
       * The other messages will be forwarded without creating a reverse session.
       */

      int valid_reverse_sess = (type >= 0
				&& (type <= icmp_valid_new_size[is_ip6])
				&& (icmp_valid_new[is_ip6][type])
				&& (type <= icmp_invmap_size[is_ip6])
				&& icmp_invmap[is_ip6][type]);
      if (valid_reverse_sess)
	{
	  l4o.l4_flags = l4i.l4_flags ^ FA_SK_L4_FLAG_IS_INPUT;
	  l4o.port[0] = icmp_invmap[is_ip6][type] - 1;
	}

      *out = l4o.as_u64;
      return valid_reverse_sess;
    }
  else
    *out = reverse_l4_u64_fastpath (l4, is_ip6);

  return 1;
}

always_inline void
reverse_session_add_del_ip6 (acl_main_t * am,
			     clib_bihash_kv_40_8_t * pkv, int is_add)
{
  clib_bihash_kv_40_8_t kv2;
  kv2.key[0] = pkv->key[2];
  kv2.key[1] = pkv->key[3];
  kv2.key[2] = pkv->key[0];
  kv2.key[3] = pkv->key[1];
  /* the last u64 needs special treatment (ports, etc.) so we do it last */
  kv2.value = pkv->value;
  if (PREDICT_FALSE (is_session_l4_key_u64_slowpath (pkv->key[4])))
    {
      if (reverse_l4_u64_slowpath_valid (pkv->key[4], 1, &kv2.key[4]))
	clib_bihash_add_del_40_8 (&am->fa_ip6_sessions_hash, &kv2, is_add);
    }
  else
    {
      kv2.key[4] = reverse_l4_u64_fastpath (pkv->key[4], 1);
      clib_bihash_add_del_40_8 (&am->fa_ip6_sessions_hash, &kv2, is_add);
    }
}

always_inline void
reverse_session_add_del_ip4 (acl_main_t * am,
			     clib_bihash_kv_16_8_t * pkv, int is_add)
{
  clib_bihash_kv_16_8_t kv2;
  kv2.key[0] =
    ((pkv->key[0] & 0xffffffff) << 32) | ((pkv->key[0] >> 32) & 0xffffffff);
  /* the last u64 needs special treatment (ports, etc.) so we do it last */
  kv2.value = pkv->value;
  if (PREDICT_FALSE (is_session_l4_key_u64_slowpath (pkv->key[1])))
    {
      if (reverse_l4_u64_slowpath_valid (pkv->key[1], 0, &kv2.key[1]))
	clib_bihash_add_del_16_8 (&am->fa_ip4_sessions_hash, &kv2, is_add);
    }
  else
    {
      kv2.key[1] = reverse_l4_u64_fastpath (pkv->key[1], 0);
      clib_bihash_add_del_16_8 (&am->fa_ip4_sessions_hash, &kv2, is_add);
    }
}

always_inline void
acl_fa_deactivate_session (acl_main_t * am, u32 sw_if_index,
			   fa_full_session_id_t sess_id)
{
  fa_session_t *sess =
    get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
  ASSERT (sess->thread_index == os_get_thread_index ());
  if (sess->is_ip6)
    {
      clib_bihash_add_del_40_8 (&am->fa_ip6_sessions_hash,
				&sess->info.kv_40_8, 0);
      reverse_session_add_del_ip6 (am, &sess->info.kv_40_8, 0);
    }
  else
    {
      clib_bihash_add_del_16_8 (&am->fa_ip4_sessions_hash,
				&sess->info.kv_16_8, 0);
      reverse_session_add_del_ip4 (am, &sess->info.kv_16_8, 0);
    }

  sess->deleted = 1;
  clib_atomic_fetch_add (&am->fa_session_total_deactivations, 1);
}

always_inline void
acl_fa_put_session (acl_main_t * am, u32 sw_if_index,
		    fa_full_session_id_t sess_id)
{
  if (sess_id.thread_index != os_get_thread_index ())
    {
      clib_error
	("Attempting to delete session belonging to thread %d by thread %d",
	 sess_id.thread_index, os_get_thread_index ());
    }
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[sess_id.thread_index];
  pool_put_index (pw->fa_sessions_pool, sess_id.session_index);
  /* Deleting from timer structures not needed,
     as the caller must have dealt with the timers. */
  vec_validate (pw->fa_session_dels_by_sw_if_index, sw_if_index);
  pw->fa_session_dels_by_sw_if_index[sw_if_index]++;
  clib_atomic_fetch_add (&am->fa_session_total_dels, 1);
}

always_inline int
acl_fa_two_stage_delete_session (acl_main_t * am, u32 sw_if_index,
				 fa_full_session_id_t sess_id, u64 now)
{
  fa_session_t *sess =
    get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
  if (sess->deleted)
    {
      acl_fa_put_session (am, sw_if_index, sess_id);
      return 1;
    }
  else
    {
      acl_fa_deactivate_session (am, sw_if_index, sess_id);
      acl_fa_conn_list_add_session (am, sess_id, now);
      return 0;
    }
}

always_inline int
acl_fa_can_add_session (acl_main_t * am, int is_input, u32 sw_if_index)
{
  u64 curr_sess_count;
  curr_sess_count = am->fa_session_total_adds - am->fa_session_total_dels;
  return (curr_sess_count + vlib_get_n_threads () <
	  am->fa_conn_table_max_entries);
}


always_inline void
acl_fa_try_recycle_session (acl_main_t * am, int is_input, u16 thread_index,
			    u32 sw_if_index, u64 now)
{
  /* try to recycle a TCP transient session */
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];
  fa_full_session_id_t volatile sess_id;
  int n_recycled = 0;

  /* clean up sessions from purgatory, if we can */
  sess_id.session_index = pw->fa_conn_list_head[ACL_TIMEOUT_PURGATORY];
  while ((FA_SESSION_BOGUS_INDEX != sess_id.session_index)
	 && n_recycled < am->fa_max_deleted_sessions_per_interval)
    {
      sess_id.thread_index = thread_index;
      fa_session_t *sess =
	get_session_ptr (am, sess_id.thread_index, sess_id.session_index);
      if (sess->link_enqueue_time + fa_session_get_timeout (am, sess) < now)
	{
	  acl_fa_conn_list_delete_session (am, sess_id, now);
	  /* interface that needs the sessions may not be the interface of the session. */
	  acl_fa_put_session (am, sess->sw_if_index, sess_id);
	  n_recycled++;
	}
      else
	break;			/* too early to try to recycle from here, bail out */
      sess_id.session_index = pw->fa_conn_list_head[ACL_TIMEOUT_PURGATORY];
    }
  sess_id.session_index = pw->fa_conn_list_head[ACL_TIMEOUT_TCP_TRANSIENT];
  if (FA_SESSION_BOGUS_INDEX != sess_id.session_index)
    {
      sess_id.thread_index = thread_index;
      acl_fa_conn_list_delete_session (am, sess_id, now);
      acl_fa_deactivate_session (am, sw_if_index, sess_id);
      /* this goes to purgatory list */
      acl_fa_conn_list_add_session (am, sess_id, now);
    }
}


always_inline fa_full_session_id_t
acl_fa_add_session (acl_main_t * am, int is_input, int is_ip6,
		    u32 sw_if_index, u64 now, fa_5tuple_t * p5tuple,
		    u16 current_policy_epoch)
{
  fa_full_session_id_t f_sess_id;
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  f_sess_id.thread_index = thread_index;
  fa_session_t *sess;

  if (f_sess_id.as_u64 == ~0)
    {
      clib_error ("Adding session with invalid value");
    }

  pool_get_aligned (pw->fa_sessions_pool, sess, CLIB_CACHE_LINE_BYTES);
  f_sess_id.session_index = sess - pw->fa_sessions_pool;
  f_sess_id.intf_policy_epoch = current_policy_epoch;

  if (is_ip6)
    {
      sess->info.kv_40_8.key[0] = p5tuple->kv_40_8.key[0];
      sess->info.kv_40_8.key[1] = p5tuple->kv_40_8.key[1];
      sess->info.kv_40_8.key[2] = p5tuple->kv_40_8.key[2];
      sess->info.kv_40_8.key[3] = p5tuple->kv_40_8.key[3];
      sess->info.kv_40_8.key[4] = p5tuple->kv_40_8.key[4];
      sess->info.kv_40_8.value = f_sess_id.as_u64;
    }
  else
    {
      sess->info.kv_16_8.key[0] = p5tuple->kv_16_8.key[0];
      sess->info.kv_16_8.key[1] = p5tuple->kv_16_8.key[1];
      sess->info.kv_16_8.value = f_sess_id.as_u64;
    }

  sess->last_active_time = now;
  sess->sw_if_index = sw_if_index;
  sess->tcp_flags_seen.as_u16 = 0;
  sess->thread_index = thread_index;
  sess->link_list_id = ACL_TIMEOUT_UNUSED;
  sess->link_prev_idx = FA_SESSION_BOGUS_INDEX;
  sess->link_next_idx = FA_SESSION_BOGUS_INDEX;
  sess->deleted = 0;
  sess->is_ip6 = is_ip6;

  acl_fa_conn_list_add_session (am, f_sess_id, now);

  ASSERT (am->fa_sessions_hash_is_initialized == 1);
  if (is_ip6)
    {
      reverse_session_add_del_ip6 (am, &sess->info.kv_40_8, 1);
      clib_bihash_add_del_40_8 (&am->fa_ip6_sessions_hash,
				&sess->info.kv_40_8, 1);
    }
  else
    {
      reverse_session_add_del_ip4 (am, &sess->info.kv_16_8, 1);
      clib_bihash_add_del_16_8 (&am->fa_ip4_sessions_hash,
				&sess->info.kv_16_8, 1);
    }

  vec_validate (pw->fa_session_adds_by_sw_if_index, sw_if_index);
  pw->fa_session_adds_by_sw_if_index[sw_if_index]++;
  clib_atomic_fetch_add (&am->fa_session_total_adds, 1);
  return f_sess_id;
}

always_inline int
acl_fa_find_session (acl_main_t * am, int is_ip6, u32 sw_if_index0,
		     fa_5tuple_t * p5tuple, u64 * pvalue_sess)
{
  int res = 0;
  if (is_ip6)
    {
      clib_bihash_kv_40_8_t kv_result;
      res = (clib_bihash_search_inline_2_40_8
	     (&am->fa_ip6_sessions_hash, &p5tuple->kv_40_8, &kv_result) == 0);
      *pvalue_sess = kv_result.value;
    }
  else
    {
      clib_bihash_kv_16_8_t kv_result;
      res = (clib_bihash_search_inline_2_16_8
	     (&am->fa_ip4_sessions_hash, &p5tuple->kv_16_8, &kv_result) == 0);
      *pvalue_sess = kv_result.value;
    }
  return res;
}

always_inline u64
acl_fa_make_session_hash (acl_main_t * am, int is_ip6, u32 sw_if_index0,
			  fa_5tuple_t * p5tuple)
{
  if (is_ip6)
    return clib_bihash_hash_40_8 (&p5tuple->kv_40_8);
  else
    return clib_bihash_hash_16_8 (&p5tuple->kv_16_8);
}

always_inline void
acl_fa_prefetch_session_bucket_for_hash (acl_main_t * am, int is_ip6,
					 u64 hash)
{
  if (is_ip6)
    clib_bihash_prefetch_bucket_40_8 (&am->fa_ip6_sessions_hash, hash);
  else
    clib_bihash_prefetch_bucket_16_8 (&am->fa_ip4_sessions_hash, hash);
}

always_inline void
acl_fa_prefetch_session_data_for_hash (acl_main_t * am, int is_ip6, u64 hash)
{
  if (is_ip6)
    clib_bihash_prefetch_data_40_8 (&am->fa_ip6_sessions_hash, hash);
  else
    clib_bihash_prefetch_data_16_8 (&am->fa_ip4_sessions_hash, hash);
}

always_inline int
acl_fa_find_session_with_hash (acl_main_t * am, int is_ip6, u32 sw_if_index0,
			       u64 hash, fa_5tuple_t * p5tuple,
			       u64 * pvalue_sess)
{
  int res = 0;
  if (is_ip6)
    {
      clib_bihash_kv_40_8_t kv_result;
      kv_result.value = ~0ULL;
      res = (clib_bihash_search_inline_2_with_hash_40_8
	     (&am->fa_ip6_sessions_hash, hash, &p5tuple->kv_40_8,
	      &kv_result) == 0);
      *pvalue_sess = kv_result.value;
    }
  else
    {
      clib_bihash_kv_16_8_t kv_result;
      kv_result.value = ~0ULL;
      res = (clib_bihash_search_inline_2_with_hash_16_8
	     (&am->fa_ip4_sessions_hash, hash, &p5tuple->kv_16_8,
	      &kv_result) == 0);
      *pvalue_sess = kv_result.value;
    }
  return res;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
