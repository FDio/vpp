/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/session/application_local.h>
#include <vnet/session/session.h>

typedef enum ct_segment_flags_
{
  CT_SEGMENT_F_CLIENT_DETACHED = 1 << 0,
  CT_SEGMENT_F_SERVER_DETACHED = 1 << 1,
} ct_segment_flags_t;

typedef struct ct_segment_
{
  u32 segment_index;
  u32 client_n_sessions;
  u32 server_n_sessions;
  ct_segment_flags_t flags;
} ct_segment_t;

typedef struct ct_segments_
{
  u32 sm_index;
  u32 server_wrk;
  u32 client_wrk;
  ct_segment_t *segments;
} ct_segments_ctx_t;

typedef struct ct_main_
{
  ct_connection_t **connections;	/**< Per-worker connection pools */
  u32 n_workers;			/**< Number of vpp workers */
  u32 n_sessions;			/**< Cumulative sessions counter */
  u32 *ho_reusable;			/**< Vector of reusable ho indices */
  clib_spinlock_t ho_reuseable_lock;	/**< Lock for reusable ho indices */
  clib_rwlock_t app_segs_lock;		/**< RW lock for seg contexts */
  uword *app_segs_ctxs_table;		/**< App handle to segment pool map */
  ct_segments_ctx_t *app_seg_ctxs;	/**< Pool of ct segment contexts */
} ct_main_t;

static ct_main_t ct_main;

static ct_connection_t *
ct_connection_alloc (u32 thread_index)
{
  ct_connection_t *ct;

  pool_get_zero (ct_main.connections[thread_index], ct);
  ct->c_c_index = ct - ct_main.connections[thread_index];
  ct->c_thread_index = thread_index;
  ct->client_wrk = ~0;
  ct->server_wrk = ~0;
  ct->seg_ctx_index = ~0;
  ct->ct_seg_index = ~0;
  return ct;
}

static ct_connection_t *
ct_connection_get (u32 ct_index, u32 thread_index)
{
  if (pool_is_free_index (ct_main.connections[thread_index], ct_index))
    return 0;
  return pool_elt_at_index (ct_main.connections[thread_index], ct_index);
}

static void
ct_connection_free (ct_connection_t * ct)
{
  if (CLIB_DEBUG)
    {
      u32 thread_index = ct->c_thread_index;
      memset (ct, 0xfc, sizeof (*ct));
      pool_put (ct_main.connections[thread_index], ct);
      return;
    }
  pool_put (ct_main.connections[ct->c_thread_index], ct);
}

static ct_connection_t *
ct_half_open_alloc (void)
{
  ct_main_t *cm = &ct_main;
  u32 *hip;

  clib_spinlock_lock (&cm->ho_reuseable_lock);
  vec_foreach (hip, cm->ho_reusable)
    pool_put_index (cm->connections[0], *hip);
  vec_reset_length (cm->ho_reusable);
  clib_spinlock_unlock (&cm->ho_reuseable_lock);

  return ct_connection_alloc (0);
}

void
ct_half_open_add_reusable (u32 ho_index)
{
  ct_main_t *cm = &ct_main;

  clib_spinlock_lock (&cm->ho_reuseable_lock);
  vec_add1 (cm->ho_reusable, ho_index);
  clib_spinlock_unlock (&cm->ho_reuseable_lock);
}

session_t *
ct_session_get_peer (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  ct = ct_connection_get (s->connection_index, s->thread_index);
  peer_ct = ct_connection_get (ct->peer_index, s->thread_index);
  return session_get (peer_ct->c_s_index, s->thread_index);
}

void
ct_session_endpoint (session_t * ll, session_endpoint_t * sep)
{
  ct_connection_t *ct;
  ct = (ct_connection_t *) session_get_transport (ll);
  sep->transport_proto = ct->actual_tp;
  sep->port = ct->c_lcl_port;
  sep->is_ip4 = ct->c_is_ip4;
  ip_copy (&sep->ip, &ct->c_lcl_ip, ct->c_is_ip4);
}

static void
ct_session_dealloc_fifos (ct_connection_t *ct, svm_fifo_t *rx_fifo,
			  svm_fifo_t *tx_fifo)
{
  ct_segments_ctx_t *seg_ctx;
  ct_main_t *cm = &ct_main;
  ct_segment_flags_t flags;
  segment_manager_t *sm;
  app_worker_t *app_wrk;
  ct_segment_t *ct_seg;
  fifo_segment_t *fs;
  u32 seg_index;
  u8 cnt;

  /*
   * Cleanup fifos
   */

  sm = segment_manager_get (rx_fifo->segment_manager);
  seg_index = rx_fifo->segment_index;

  fs = segment_manager_get_segment_w_lock (sm, seg_index);
  fifo_segment_free_fifo (fs, rx_fifo);
  fifo_segment_free_fifo (fs, tx_fifo);
  segment_manager_segment_reader_unlock (sm);

  /*
   * Update segment context
   */

  clib_rwlock_reader_lock (&cm->app_segs_lock);

  seg_ctx = pool_elt_at_index (cm->app_seg_ctxs, ct->seg_ctx_index);
  ct_seg = pool_elt_at_index (seg_ctx->segments, ct->ct_seg_index);

  if (ct->flags & CT_CONN_F_CLIENT)
    {
      cnt =
	__atomic_sub_fetch (&ct_seg->client_n_sessions, 1, __ATOMIC_RELAXED);
      if (!cnt)
	ct_seg->flags |= CT_SEGMENT_F_CLIENT_DETACHED;
    }
  else
    {
      cnt =
	__atomic_sub_fetch (&ct_seg->server_n_sessions, 1, __ATOMIC_RELAXED);
      if (!cnt)
	ct_seg->flags |= CT_SEGMENT_F_SERVER_DETACHED;
    }

  flags = ct_seg->flags;

  clib_rwlock_reader_unlock (&cm->app_segs_lock);

  /*
   * No need to do any app updates, return
   */
  if (cnt)
    return;

  if (ct->flags & CT_CONN_F_CLIENT)
    {
      app_wrk = app_worker_get_if_valid (ct->client_wrk);
      /* Determine if client app still needs notification, i.e., if it is
       * still attached. If client detached and this is the last ct session
       * on this segment, then its connects segment manager should also be
       * detached, so do not send notification */
      if (app_wrk)
	{
	  segment_manager_t *csm;
	  csm = app_worker_get_connect_segment_manager (app_wrk);
	  if (!segment_manager_app_detached (csm))
	    app_worker_del_segment_notify (app_wrk, ct->segment_handle);
	}
    }
  else if (!segment_manager_app_detached (sm))
    {
      app_wrk = app_worker_get (ct->server_wrk);
      app_worker_del_segment_notify (app_wrk, ct->segment_handle);
    }

  if (!(flags & CT_SEGMENT_F_CLIENT_DETACHED) ||
      !(flags & CT_SEGMENT_F_SERVER_DETACHED))
    return;

  /*
   * Remove segment context because both client and server detached
   */

  clib_rwlock_writer_lock (&cm->app_segs_lock);

  seg_ctx = pool_elt_at_index (cm->app_seg_ctxs, ct->seg_ctx_index);
  pool_put_index (seg_ctx->segments, ct->ct_seg_index);

  /*
   * No more segment indices left, remove the segments context
   */
  if (!pool_elts (seg_ctx->segments))
    {
      u64 table_handle = seg_ctx->client_wrk << 16 | seg_ctx->server_wrk;
      table_handle = (u64) seg_ctx->sm_index << 32 | table_handle;
      hash_unset (cm->app_segs_ctxs_table, table_handle);
      pool_free (seg_ctx->segments);
      pool_put_index (cm->app_seg_ctxs, ct->seg_ctx_index);
    }

  clib_rwlock_writer_unlock (&cm->app_segs_lock);

  segment_manager_lock_and_del_segment (sm, seg_index);

  /* Cleanup segment manager if needed. If server detaches there's a chance
   * the client's sessions will hold up segment removal */
  if (segment_manager_app_detached (sm) && !segment_manager_has_fifos (sm))
    segment_manager_free_safe (sm);
}

int
ct_session_connect_notify (session_t *ss)
{
  u32 ss_index, opaque, thread_index, cnt;
  ct_connection_t *sct, *cct;
  ct_segments_ctx_t *seg_ctx;
  app_worker_t *client_wrk;
  ct_main_t *cm = &ct_main;
  ct_segment_t *ct_seg;
  session_t *cs;
  int err = 0;

  ss_index = ss->session_index;
  thread_index = ss->thread_index;
  sct = (ct_connection_t *) session_get_transport (ss);
  client_wrk = app_worker_get (sct->client_wrk);
  opaque = sct->client_opaque;

  cct = ct_connection_get (sct->peer_index, thread_index);

  /* Client closed while waiting for reply from server */
  if (!cct)
    {
      session_transport_closing_notify (&sct->connection);
      session_transport_delete_notify (&sct->connection);
      ct_connection_free (sct);
      return 0;
    }

  session_half_open_delete_notify (&cct->connection);
  cct->flags &= ~CT_CONN_F_HALF_OPEN;

  /*
   * Update ct segment context
   */

  clib_rwlock_reader_lock (&cm->app_segs_lock);

  seg_ctx = pool_elt_at_index (cm->app_seg_ctxs, sct->seg_ctx_index);
  ct_seg = pool_elt_at_index (seg_ctx->segments, sct->ct_seg_index);

  cnt = __atomic_add_fetch (&ct_seg->client_n_sessions, 1, __ATOMIC_RELAXED);
  if (cnt == 1)
    {
      err = app_worker_add_segment_notify (client_wrk, cct->segment_handle);
      if (err)
	{
	  clib_rwlock_reader_unlock (&cm->app_segs_lock);
	  session_close (ss);
	  goto error;
	}
    }

  clib_rwlock_reader_unlock (&cm->app_segs_lock);

  /*
   * Alloc client session
   */

  cs = session_alloc (thread_index);
  ss = session_get (ss_index, thread_index);
  cs->session_type = ss->session_type;
  cs->listener_handle = SESSION_INVALID_HANDLE;
  cs->session_state = SESSION_STATE_CONNECTING;
  cs->app_wrk_index = client_wrk->wrk_index;
  cs->connection_index = cct->c_c_index;
  cct->seg_ctx_index = sct->seg_ctx_index;
  cct->ct_seg_index = sct->ct_seg_index;

  cct->c_s_index = cs->session_index;
  cct->client_rx_fifo = ss->tx_fifo;
  cct->client_tx_fifo = ss->rx_fifo;

  cct->client_rx_fifo->refcnt++;
  cct->client_tx_fifo->refcnt++;

  /* This will allocate fifos for the session. They won't be used for
   * exchanging data but they will be used to close the connection if
   * the segment manager/worker is freed */
  if ((err = app_worker_init_connected (client_wrk, cs)))
    {
      session_close (ss);
      session_free (cs);
      goto error;
    }

  cs->session_state = SESSION_STATE_CONNECTING;

  if (app_worker_connect_notify (client_wrk, cs, err, opaque))
    {
      session_close (ss);
      ct_session_dealloc_fifos (cct, cs->rx_fifo, cs->tx_fifo);
      session_free (cs);
      return -1;
    }

  cs = session_get (cct->c_s_index, cct->c_thread_index);
  cs->session_state = SESSION_STATE_READY;

  return 0;

error:
  app_worker_connect_notify (client_wrk, 0, err, opaque);
  return -1;
}

static ct_segment_t *
ct_lookup_free_segment (segment_manager_t *sm, ct_segments_ctx_t *seg_ctx,
			u32 pair_bytes)
{
  uword free_bytes, max_free_bytes;
  ct_segment_t *ct_seg, *res = 0;
  fifo_segment_t *fs;
  u32 max_fifos;

  max_free_bytes = pair_bytes;
  pool_foreach (ct_seg, seg_ctx->segments)
    {
      /* Client or server has detached so segment cannot be used */
      if ((ct_seg->flags & CT_SEGMENT_F_SERVER_DETACHED) ||
	  (ct_seg->flags & CT_SEGMENT_F_CLIENT_DETACHED))
	continue;
      fs = segment_manager_get_segment (sm, ct_seg->segment_index);
      free_bytes = fifo_segment_available_bytes (fs);
      max_fifos = fifo_segment_size (fs) / pair_bytes;
      if (free_bytes > max_free_bytes &&
	  fifo_segment_num_fifos (fs) / 2 < max_fifos)
	{
	  max_free_bytes = free_bytes;
	  res = ct_seg;
	}
    }

  return res;
}

static int
ct_init_accepted_session (app_worker_t *server_wrk, ct_connection_t *ct,
			  session_t *ls, session_t *ll)
{
  u32 sm_index, pair_bytes, seg_ctx_index = ~0, ct_seg_index = ~0;
  u64 seg_handle, table_handle, seg_size;
  segment_manager_props_t *props;
  const u32 margin = 16 << 10;
  ct_segments_ctx_t *seg_ctx;
  ct_main_t *cm = &ct_main;
  application_t *server;
  segment_manager_t *sm;
  ct_segment_t *ct_seg;
  fifo_segment_t *fs;
  int rv, fs_index;
  uword *spp;

  sm = app_worker_get_listen_segment_manager (server_wrk, ll);
  sm_index = segment_manager_index (sm);
  server = application_get (server_wrk->app_index);
  props = application_segment_manager_properties (server);

  table_handle = ct->client_wrk << 16 | server_wrk->wrk_index;
  table_handle = (u64) segment_manager_index (sm) << 32 | table_handle;

  /*
   * Check if we already have a segment that can hold the fifos
   */

  clib_rwlock_reader_lock (&cm->app_segs_lock);

  spp = hash_get (cm->app_segs_ctxs_table, table_handle);
  if (spp)
    {
      seg_ctx_index = *spp;
      seg_ctx = pool_elt_at_index (cm->app_seg_ctxs, seg_ctx_index);
      pair_bytes = props->rx_fifo_size + props->tx_fifo_size + margin;
      ct_seg = ct_lookup_free_segment (sm, seg_ctx, pair_bytes);
      if (ct_seg)
	{
	  ct_seg_index = ct_seg - seg_ctx->segments;
	  fs_index = ct_seg->segment_index;
	  __atomic_add_fetch (&ct_seg->server_n_sessions, 1, __ATOMIC_RELAXED);
	}
    }

  clib_rwlock_reader_unlock (&cm->app_segs_lock);

  /*
   * No segment, try to alloc one and notify the server
   */

  if (ct_seg_index == ~0)
    {
      seg_size = clib_max (props->segment_size, 128 << 20);
      fs_index = segment_manager_add_segment (sm, seg_size, 0);
      if (fs_index < 0)
	{
	  rv = -1;
	  goto failed;
	}

      /* Make sure the segment is not used for other fifos */
      fs = segment_manager_get_segment_w_lock (sm, fs_index);
      fifo_segment_flags (fs) |= FIFO_SEGMENT_F_CUSTOM_USE;
      segment_manager_segment_reader_unlock (sm);

      clib_rwlock_writer_lock (&cm->app_segs_lock);

      if (seg_ctx_index == ~0)
	{
	  pool_get_zero (cm->app_seg_ctxs, seg_ctx);
	  seg_ctx_index = seg_ctx - cm->app_seg_ctxs;
	  hash_set (cm->app_segs_ctxs_table, table_handle, seg_ctx_index);
	  seg_ctx->server_wrk = server_wrk->wrk_index;
	  seg_ctx->client_wrk = ct->client_wrk;
	  seg_ctx->sm_index = sm_index;
	}
      else
	seg_ctx = pool_elt_at_index (cm->app_seg_ctxs, seg_ctx_index);

      pool_get_zero (seg_ctx->segments, ct_seg);
      ct_seg->segment_index = fs_index;
      ct_seg->server_n_sessions += 1;
      ct_seg_index = ct_seg - seg_ctx->segments;

      clib_rwlock_writer_unlock (&cm->app_segs_lock);

      /* New segment, notify the server. Client notification sent after
       * server accepts the connection */
      seg_handle = segment_manager_make_segment_handle (sm_index, fs_index);
      if ((rv = app_worker_add_segment_notify (server_wrk, seg_handle)))
	{
	  segment_manager_lock_and_del_segment (sm, fs_index);

	  clib_rwlock_writer_lock (&cm->app_segs_lock);
	  pool_put_index (seg_ctx->segments, ct_seg_index);
	  clib_rwlock_writer_unlock (&cm->app_segs_lock);

	  goto failed_fix_count;
	}
    }

  /*
   * Allocate and initialize the fifos
   */
  fs = segment_manager_get_segment_w_lock (sm, fs_index);
  rv = segment_manager_try_alloc_fifos (
    fs, ls->thread_index, props->rx_fifo_size, props->tx_fifo_size,
    &ls->rx_fifo, &ls->tx_fifo);
  if (rv)
    {
      segment_manager_segment_reader_unlock (sm);
      goto failed_fix_count;
    }

  ls->rx_fifo->shr->master_session_index = ls->session_index;
  ls->tx_fifo->shr->master_session_index = ls->session_index;
  ls->rx_fifo->master_thread_index = ls->thread_index;
  ls->tx_fifo->master_thread_index = ls->thread_index;
  ls->rx_fifo->segment_manager = sm_index;
  ls->tx_fifo->segment_manager = sm_index;
  ls->rx_fifo->segment_index = fs_index;
  ls->tx_fifo->segment_index = fs_index;

  seg_handle = segment_manager_segment_handle (sm, fs);
  segment_manager_segment_reader_unlock (sm);

  ct->segment_handle = seg_handle;
  ct->seg_ctx_index = seg_ctx_index;
  ct->ct_seg_index = ct_seg_index;

  return 0;

failed_fix_count:

  clib_rwlock_reader_lock (&cm->app_segs_lock);

  seg_ctx = pool_elt_at_index (cm->app_seg_ctxs, seg_ctx_index);
  ct_seg = pool_elt_at_index (seg_ctx->segments, ct_seg_index);
  __atomic_sub_fetch (&ct_seg->server_n_sessions, 1, __ATOMIC_RELAXED);

  clib_rwlock_reader_unlock (&cm->app_segs_lock);

failed:
  return rv;
}

static void
ct_accept_rpc_wrk_handler (void *accept_args)
{
  u32 cct_index, ho_index, thread_index, ll_index;
  ct_connection_t *sct, *cct, *ho;
  transport_connection_t *ll_ct;
  app_worker_t *server_wrk;
  session_t *ss, *ll;

  /*
   * Alloc client ct and initialize from ho
   */
  thread_index = vlib_get_thread_index ();
  cct = ct_connection_alloc (thread_index);
  cct_index = cct->c_c_index;

  ho_index = pointer_to_uword (accept_args);
  ho = ct_connection_get (ho_index, 0);

  /* Unlikely but half-open session and transport could have been freed */
  if (PREDICT_FALSE (!ho))
    {
      ct_connection_free (cct);
      return;
    }

  clib_memcpy (cct, ho, sizeof (*ho));
  cct->c_c_index = cct_index;
  cct->c_thread_index = thread_index;
  cct->flags |= CT_CONN_F_HALF_OPEN;

  /* Notify session layer that half-open is on a different thread
   * and mark ho connection index reusable. Avoids another rpc
   */
  session_half_open_migrate_notify (&cct->connection);
  session_half_open_migrated_notify (&cct->connection);
  ct_half_open_add_reusable (ho_index);

  /*
   * Alloc and init server transport
   */

  ll_index = cct->peer_index;
  ll = listen_session_get (ll_index);
  sct = ct_connection_alloc (thread_index);
  /* Transport not necessarily ct but it might, so grab after sct alloc */
  ll_ct = listen_session_get_transport (ll);

  /* Make sure cct is valid after sct alloc */
  cct = ct_connection_get (cct_index, thread_index);

  sct->c_rmt_port = 0;
  sct->c_lcl_port = ll_ct->lcl_port;
  sct->c_is_ip4 = cct->c_is_ip4;
  clib_memcpy (&sct->c_lcl_ip, &ll_ct->lcl_ip, sizeof (ll_ct->lcl_ip));
  sct->client_wrk = cct->client_wrk;
  sct->c_proto = TRANSPORT_PROTO_NONE;
  sct->client_opaque = cct->client_opaque;
  sct->actual_tp = cct->actual_tp;

  sct->peer_index = cct->c_c_index;
  cct->peer_index = sct->c_c_index;

  /*
   * Accept server session. Client session is created only after
   * server confirms accept.
   */
  ss = session_alloc (thread_index);
  ll = listen_session_get (ll_index);
  ss->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE,
						     sct->c_is_ip4);
  ss->connection_index = sct->c_c_index;
  ss->listener_handle = listen_session_get_handle (ll);
  ss->session_state = SESSION_STATE_CREATED;

  server_wrk = application_listener_select_worker (ll);
  ss->app_wrk_index = server_wrk->wrk_index;

  sct->c_s_index = ss->session_index;
  sct->server_wrk = ss->app_wrk_index;

  if (ct_init_accepted_session (server_wrk, sct, ss, ll))
    {
      ct_connection_free (sct);
      session_free (ss);
      return;
    }

  ss->session_state = SESSION_STATE_ACCEPTING;
  if (app_worker_accept_notify (server_wrk, ss))
    {
      ct_session_dealloc_fifos (sct, ss->rx_fifo, ss->tx_fifo);
      ct_connection_free (sct);
      session_free (ss);
      return;
    }

  cct->segment_handle = sct->segment_handle;
}

static int
ct_connect (app_worker_t * client_wrk, session_t * ll,
	    session_endpoint_cfg_t * sep)
{
  u32 thread_index, ho_index;
  ct_main_t *cm = &ct_main;
  ct_connection_t *ho;

  /* Simple round-robin policy for spreading sessions over workers. We skip
   * thread index 0, i.e., offset the index by 1, when we have workers as it
   * is the one dedicated to main thread. Note that n_workers does not include
   * main thread */
  cm->n_sessions += 1;
  thread_index = cm->n_workers ? (cm->n_sessions % cm->n_workers) + 1 : 0;

  /*
   * Alloc and init client half-open transport
   */

  ho = ct_half_open_alloc ();
  ho_index = ho->c_c_index;
  ho->c_rmt_port = sep->port;
  ho->c_lcl_port = 0;
  ho->c_is_ip4 = sep->is_ip4;
  ho->client_opaque = sep->opaque;
  ho->client_wrk = client_wrk->wrk_index;
  ho->peer_index = ll->session_index;
  ho->c_proto = TRANSPORT_PROTO_NONE;
  ho->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  clib_memcpy (&ho->c_rmt_ip, &sep->ip, sizeof (sep->ip));
  ho->flags |= CT_CONN_F_CLIENT;
  ho->c_s_index = ~0;
  ho->actual_tp = sep->transport_proto;

  /*
   * Accept connection on thread selected above. Connected reply comes
   * after server accepts the connection.
   */

  session_send_rpc_evt_to_thread_force (thread_index,
					ct_accept_rpc_wrk_handler,
					uword_to_pointer (ho_index, void *));

  return ho_index;
}

static u32
ct_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  session_endpoint_cfg_t *sep;
  ct_connection_t *ct;

  sep = (session_endpoint_cfg_t *) tep;
  ct = ct_connection_alloc (0);
  ct->server_wrk = sep->app_wrk_index;
  ct->c_is_ip4 = sep->is_ip4;
  clib_memcpy (&ct->c_lcl_ip, &sep->ip, sizeof (sep->ip));
  ct->c_lcl_port = sep->port;
  ct->c_s_index = app_listener_index;
  ct->actual_tp = sep->transport_proto;
  return ct->c_c_index;
}

static u32
ct_stop_listen (u32 ct_index)
{
  ct_connection_t *ct;
  ct = ct_connection_get (ct_index, 0);
  ct_connection_free (ct);
  return 0;
}

static transport_connection_t *
ct_listener_get (u32 ct_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index, 0);
}

static transport_connection_t *
ct_half_open_get (u32 ct_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index, 0);
}

static void
ct_session_cleanup (u32 conn_index, u32 thread_index)
{
  ct_connection_t *ct, *peer_ct;

  ct = ct_connection_get (conn_index, thread_index);
  if (!ct)
    return;

  peer_ct = ct_connection_get (ct->peer_index, thread_index);
  if (peer_ct)
    peer_ct->peer_index = ~0;

  ct_connection_free (ct);
}

static void
ct_cleanup_ho (u32 ho_index)
{
  ct_connection_free (ct_connection_get (ho_index, 0));
}

static int
ct_session_connect (transport_endpoint_cfg_t * tep)
{
  session_endpoint_cfg_t *sep_ext;
  session_endpoint_t _sep, *sep = &_sep;
  app_worker_t *app_wrk;
  session_handle_t lh;
  application_t *app;
  app_listener_t *al;
  u32 table_index;
  session_t *ll;
  u8 fib_proto;

  sep_ext = (session_endpoint_cfg_t *) tep;
  _sep = *(session_endpoint_t *) tep;
  app_wrk = app_worker_get (sep_ext->app_wrk_index);
  app = application_get (app_wrk->app_index);

  sep->transport_proto = sep_ext->original_tp;
  table_index = application_local_session_table (app);
  lh = session_lookup_local_endpoint (table_index, sep);
  if (lh == SESSION_DROP_HANDLE)
    return SESSION_E_FILTERED;

  if (lh == SESSION_INVALID_HANDLE)
    goto global_scope;

  ll = listen_session_get_from_handle (lh);
  al = app_listener_get_w_session (ll);

  /*
   * Break loop if rule in local table points to connecting app. This
   * can happen if client is a generic proxy. Route connect through
   * global table instead.
   */
  if (al->app_index == app->app_index)
    goto global_scope;

  return ct_connect (app_wrk, ll, sep_ext);

  /*
   * If nothing found, check the global scope for locally attached
   * destinations. Make sure first that we're allowed to.
   */

global_scope:
  if (session_endpoint_is_local (sep))
    return SESSION_E_NOROUTE;

  if (!application_has_global_scope (app))
    return SESSION_E_SCOPE;

  fib_proto = session_endpoint_fib_proto (sep);
  table_index = session_lookup_get_index_for_fib (fib_proto, sep->fib_index);
  ll = session_lookup_listener_wildcard (table_index, sep);

  /* Avoid connecting app to own listener */
  if (ll && ll->app_index != app->app_index)
    return ct_connect (app_wrk, ll, sep_ext);

  /* Failed to connect but no error */
  return SESSION_E_LOCAL_CONNECT;
}

static void
ct_session_close (u32 ct_index, u32 thread_index)
{
  ct_connection_t *ct, *peer_ct;
  app_worker_t *app_wrk;
  session_t *s;

  ct = ct_connection_get (ct_index, thread_index);
  peer_ct = ct_connection_get (ct->peer_index, thread_index);
  if (peer_ct)
    {
      peer_ct->peer_index = ~0;
      /* Make sure session was allocated */
      if (peer_ct->flags & CT_CONN_F_HALF_OPEN)
	{
	  app_wrk = app_worker_get (peer_ct->client_wrk);
	  app_worker_connect_notify (app_wrk, 0, SESSION_E_REFUSED,
				     peer_ct->client_opaque);
	}
      else if (peer_ct->c_s_index != ~0)
	session_transport_closing_notify (&peer_ct->connection);
      else
	ct_connection_free (peer_ct);
    }

  s = session_get (ct->c_s_index, ct->c_thread_index);

  if (ct->flags & CT_CONN_F_CLIENT)
    {
      /* Normal free for client session as the fifos are allocated through
       * the connects segment manager in a segment that's not shared with
       * the server */
      session_free_w_fifos (s);
      ct_session_dealloc_fifos (ct, ct->client_rx_fifo, ct->client_tx_fifo);
    }
  else
    {
      /* Manual session and fifo segment cleanup to avoid implicit
       * segment manager cleanups and notifications */
      app_wrk = app_worker_get_if_valid (s->app_wrk_index);
      if (app_wrk)
	app_worker_cleanup_notify (app_wrk, s, SESSION_CLEANUP_SESSION);

      ct_session_dealloc_fifos (ct, s->rx_fifo, s->tx_fifo);
      session_free (s);
    }

  ct_connection_free (ct);
}

static transport_connection_t *
ct_session_get (u32 ct_index, u32 thread_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index,
						       thread_index);
}

static u8 *
format_ct_connection_id (u8 * s, va_list * args)
{
  ct_connection_t *ct = va_arg (*args, ct_connection_t *);
  if (!ct)
    return s;
  if (ct->c_is_ip4)
    {
      s = format (s, "[%d:%d][CT:%U] %U:%d->%U:%d", ct->c_thread_index,
		  ct->c_s_index, format_transport_proto_short, ct->actual_tp,
		  format_ip4_address, &ct->c_lcl_ip4,
		  clib_net_to_host_u16 (ct->c_lcl_port), format_ip4_address,
		  &ct->c_rmt_ip4, clib_net_to_host_u16 (ct->c_rmt_port));
    }
  else
    {
      s = format (s, "[%d:%d][CT:%U] %U:%d->%U:%d", ct->c_thread_index,
		  ct->c_s_index, format_transport_proto_short, ct->actual_tp,
		  format_ip6_address, &ct->c_lcl_ip6,
		  clib_net_to_host_u16 (ct->c_lcl_port), format_ip6_address,
		  &ct->c_rmt_ip6, clib_net_to_host_u16 (ct->c_rmt_port));
    }

  return s;
}

static int
ct_custom_tx (void *session, transport_send_params_t * sp)
{
  session_t *s = (session_t *) session;
  if (session_has_transport (s))
    return 0;
  /* If event enqueued towards peer, remove from scheduler and remove
   * session tx flag, i.e., accept new tx events. Unset fifo flag now to
   * avoid missing events if peer did not clear fifo flag yet, which is
   * interpreted as successful notification and session is descheduled. */
  svm_fifo_unset_event (s->tx_fifo);
  if (!ct_session_tx (s))
    sp->flags = TRANSPORT_SND_F_DESCHED;

  /* The scheduler uses packet count as a means of upper bounding the amount
   * of work done per dispatch. So make it look like we have sent something */
  return 1;
}

static int
ct_app_rx_evt (transport_connection_t * tc)
{
  ct_connection_t *ct = (ct_connection_t *) tc, *peer_ct;
  session_t *ps;

  peer_ct = ct_connection_get (ct->peer_index, tc->thread_index);
  if (!peer_ct)
    return -1;
  ps = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
  return session_dequeue_notify (ps);
}

static u8 *
format_ct_listener (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 __clib_unused verbose = va_arg (*args, u32);
  ct_connection_t *ct = ct_connection_get (tc_index, 0);
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_ct_connection_id, ct);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "s", "LISTEN");
  return s;
}

static u8 *
format_ct_half_open (u8 *s, va_list *args)
{
  u32 ho_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  ct_connection_t *ct = ct_connection_get (ho_index, 0);
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_ct_connection_id, ct);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "s", "HALF-OPEN");
  return s;
}

static u8 *
format_ct_connection (u8 * s, va_list * args)
{
  ct_connection_t *ct = va_arg (*args, ct_connection_t *);
  u32 verbose = va_arg (*args, u32);

  if (!ct)
    return s;
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_ct_connection_id, ct);
  if (verbose)
    {
      s = format (s, "%-" SESSION_CLI_STATE_LEN "s", "ESTABLISHED");
      if (verbose > 1)
	{
	  s = format (s, "\n");
	}
    }
  return s;
}

static u8 *
format_ct_session (u8 * s, va_list * args)
{
  u32 ct_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  ct_connection_t *ct;

  ct = ct_connection_get (ct_index, thread_index);
  if (!ct)
    {
      s = format (s, "empty\n");
      return s;
    }

  s = format (s, "%U", format_ct_connection, ct, verbose);
  return s;
}

clib_error_t *
ct_enable_disable (vlib_main_t * vm, u8 is_en)
{
  ct_main_t *cm = &ct_main;

  cm->n_workers = vlib_num_workers ();
  vec_validate (cm->connections, cm->n_workers);
  clib_spinlock_init (&cm->ho_reuseable_lock);
  clib_rwlock_init (&cm->app_segs_lock);
  return 0;
}

/* *INDENT-OFF* */
static const transport_proto_vft_t cut_thru_proto = {
  .enable = ct_enable_disable,
  .start_listen = ct_start_listen,
  .stop_listen = ct_stop_listen,
  .get_connection = ct_session_get,
  .get_listener = ct_listener_get,
  .get_half_open = ct_half_open_get,
  .cleanup = ct_session_cleanup,
  .cleanup_ho = ct_cleanup_ho,
  .connect = ct_session_connect,
  .close = ct_session_close,
  .custom_tx = ct_custom_tx,
  .app_rx_evt = ct_app_rx_evt,
  .format_listener = format_ct_listener,
  .format_half_open = format_ct_half_open,
  .format_connection = format_ct_session,
  .transport_options = {
    .name = "ct",
    .short_name = "C",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_VC,
  },
};
/* *INDENT-ON* */

int
ct_session_tx (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  session_t *peer_s;

  ct = (ct_connection_t *) session_get_transport (s);
  peer_ct = ct_connection_get (ct->peer_index, ct->c_thread_index);
  if (!peer_ct)
    return 0;
  peer_s = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
  if (peer_s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return 0;
  return session_enqueue_notify (peer_s);
}

static clib_error_t *
ct_transport_init (vlib_main_t * vm)
{
  transport_register_protocol (TRANSPORT_PROTO_NONE, &cut_thru_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_NONE, &cut_thru_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (ct_transport_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
