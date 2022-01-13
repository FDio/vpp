/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <http/http.h>
#include <vnet/session/session.h>

static http_main_t http_main;

static inline http_worker_t *
http_worker_get (u32 thread_index)
{
  return &http_main.wrk[thread_index];
}

static inline u32
http_conn_alloc_w_thread (u32 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  http_tc_t *hc;
  pool_get_zero (wrk->conn_pool, hc);
  hc->c_thread_index = thread_index;
  hc->h_hc_index = hc - wrk->conn_pool;
  hc->h_pa_session_handle = SESSION_INVALID_HANDLE;
  return hc->h_hc_index;
}

static inline http_tc_t *
http_conn_get_w_thread (u32 hc_index, u32 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);
  return pool_elt_at_index (wrk->conn_pool, hc_index);
}

void
http_conn_free (http_tc_t *hc)
{
  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  pool_put (wrk->conn_pool, hc);
}

static u32
http_listener_alloc (void)
{
  http_main_t *hm = &http_main;
  http_tc_t *ctx;

  pool_get_zero (hm->listener_ctx_pool, ctx);
  ctx->c_c_index = ctx - hm->listener_ctx_pool;
  return ctx->c_c_index;
}

http_tc_t *
http_listener_get (u32 ctx_index)
{
  return pool_elt_at_index (http_main.listener_ctx_pool, ctx_index);
}

void
http_disconnect_transport (http_tc_t *hc)
{
  vnet_disconnect_args_t a = {
    .handle = hc->h_tc_session_handle,
    .app_index = http_main.app_index,
  };

  hc->state = HTTP_CONN_STATE_CLOSED;

  if (vnet_disconnect_session (&a))
    clib_warning ("disconnect returned");
}

static int
http_conn_init_tx_buf (http_tc_t *hc, svm_fifo_t *f, u32 data_len)
{
  http_buffer_t *hb = &hc->tx_buf;
  int i, len, max_len;
  const int n_segs = 5;
  svm_fifo_seg_t fs[n_segs];

  hb->len = data_len;
  hb->offset = 0;
  hb->cur_seg = 0;

  max_len = hb->len;
  while (max_len)
    {
      len = svm_fifo_segments (f, 0, fs, n_segs, max_len);
      if (len <= 0)
	return -1;

      i = 0;
      max_len -= len;

      while (len && i < n_segs)
	{
	  vec_add1 (hb->segs, fs[i]);
	  len -= fs[i].len;
	  i += 1;
	}
    }

  //  if (hb->segs[0].len < sizeof (http_msg_t))
  //    {
  //      diff = sizeof (http_msg_t) - hb->segs[0].len;
  //      hb->cur_seg = 1;
  //    }
  //  else
  //    {
  //      diff = sizeof (http_msg_t);
  //    }
  //
  //  hb->segs[hb->cur_seg].data += diff;
  //  hb->segs[hb->cur_seg].len -= diff;

  return 0;
}

static void
http_conn_free_tx_buf (http_tc_t *hc)
{
  http_buffer_t *hb = &hc->tx_buf;

  vec_free (hb->segs);
}

#define HTTP_CONN_TIMEOUT 60

static void
http_connection_timer_start (http_tc_t *hc)
{
  http_main_t *hm = &http_main;
  u32 hs_handle;
  u64 timeout;

  timeout = HTTP_CONN_TIMEOUT;
  hs_handle = hc->c_thread_index << 24 | hc->c_c_index;

  clib_spinlock_lock (&hm->tw_lock);
  hc->timer_handle =
    tw_timer_start_2t_1w_2048sl (&hm->tw, hs_handle, 0, timeout);
  clib_spinlock_unlock (&hm->tw_lock);
}

static void
http_connection_timer_stop (http_tc_t *hc)
{
  http_main_t *hm = &http_main;
  if (hc->timer_handle == ~0)
    return;

  clib_spinlock_lock (&hm->tw_lock);
  tw_timer_stop_2t_1w_2048sl (&hm->tw, hc->timer_handle);
  hc->timer_handle = ~0;
  clib_spinlock_unlock (&hm->tw_lock);
}

static void
http_connection_timer_update (http_tc_t *hc)
{
  http_main_t *hm = &http_main;
  u64 timeout;

  if (hc->timer_handle == ~0)
    return;

  timeout = HTTP_CONN_TIMEOUT;

  clib_spinlock_lock (&hm->tw_lock);
  tw_timer_update_2t_1w_2048sl (&hm->tw, hc->timer_handle, timeout);
  clib_spinlock_unlock (&hm->tw_lock);
}

static void
http_session_close_cb (void *hc_handlep)
{
  http_main_t *hsm = &http_main;
  http_tc_t *hc;
  uword hs_handle;

  hs_handle = pointer_to_uword (hc_handlep);
  hc = http_conn_get_w_thread (hs_handle & 0x00FFFFFF, hs_handle >> 24);

  if (hsm->debug_level > 1)
    clib_warning ("terminate thread %d index %d hs %llx", hs_handle >> 24,
		  hs_handle & 0x00FFFFFF, hc);
  if (!hc)
    return;

  hc->timer_handle = ~0;
  session_transport_closing_notify (&hc->connection);
  http_disconnect_transport (hc);
}

static void
http_timer_process_expired_cb (u32 *expired_timers)
{
  u32 hs_handle;
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      hs_handle = expired_timers[i] & 0x7FFFFFFF;
      session_send_rpc_evt_to_thread (hs_handle >> 24, http_session_close_cb,
				      uword_to_pointer (hs_handle, void *));
    }
}

static uword
http_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  http_main_t *hm = &http_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);

      /* expire timers */
      clib_spinlock_lock (&hm->tw_lock);
      tw_timer_expire_timers_2t_1w_2048sl (&hm->tw, now);
      clib_spinlock_unlock (&hm->tw_lock);

      vec_reset_length (event_data);
    }
  return 0;
}

VLIB_REGISTER_NODE (http_timer_process_node) = {
  .function = http_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "http-timer-process",
  .state = VLIB_NODE_STATE_DISABLED,
};

static void
http_timers_init (vlib_main_t *vm)
{
  http_main_t *hm = &http_main;
  vlib_node_t *n;

  tw_timer_wheel_init_2t_1w_2048sl (&hm->tw, http_timer_process_expired_cb,
				    1.0 /* timer interval */, ~0);
  clib_spinlock_init (&hm->tw_lock);

  vlib_node_set_state (vm, http_timer_process_node.index,
		       VLIB_NODE_STATE_POLLING);
  n = vlib_get_node (vm, http_timer_process_node.index);
  vlib_start_process (vm, n->runtime_index);
}

int
http_ts_accept_callback (session_t *ts)
{
  session_t *ts_listener, *as, *asl;
  app_worker_t *app_wrk;
  http_tc_t *lhc, *hc;
  u32 hc_index;
  int rv;

  ts_listener = listen_session_get_from_handle (ts->listener_handle);
  lhc = http_listener_get (ts_listener->opaque);

  hc_index = http_conn_alloc_w_thread (ts->thread_index);
  hc = http_conn_get_w_thread (hc_index, ts->thread_index);
  clib_memcpy_fast (hc, lhc, sizeof (*lhc));
  hc->c_thread_index = vlib_get_thread_index ();
  hc->h_hc_index = hc_index;

  hc->h_tc_session_handle = session_handle (ts);
  hc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  hc->state = HTTP_CONN_STATE_ESTABLISHED;
  hc->req_state = HTTP_REQ_STATE_WAIT_METHOD;

  ts->session_state = SESSION_STATE_READY;
  ts->opaque = hc_index;

  /*
   * Alloc session and initialize
   */
  as = session_alloc (hc->c_thread_index);
  as->session_state = SESSION_STATE_CREATED;
  hc->c_s_index = as->session_index;

  as->app_wrk_index = hc->h_pa_wrk_index;
  as->connection_index = hc->c_c_index;
  as->session_state = SESSION_STATE_ACCEPTING;

  asl = listen_session_get_from_handle (lhc->h_pa_session_handle);
  as->session_type = asl->session_type;
  as->listener_handle = lhc->h_pa_session_handle;

  /*
   * Init session fifos and notify app
   */
  if ((rv = app_worker_init_accepted (as)))
    {
      HTTP_DBG (1, "failed to allocate fifos");
      session_free (as);
      return rv;
    }

  hc->h_pa_session_handle = session_handle (as);
  hc->h_pa_wrk_index = as->app_wrk_index;
  app_wrk = app_worker_get (as->app_wrk_index);

  HTTP_DBG (1, "Accepted on listener %u new connection [%u]%x",
	    ts_listener->opaque, vlib_get_thread_index (), hc_index);

  if ((rv = app_worker_accept_notify (app_wrk, as)))
    {
      HTTP_DBG (0, "app accept returned");
      session_free (as);
      return rv;
    }

  http_connection_timer_start (hc);

  return 0;
}

static int
http_ts_connected_callback (u32 http_app_index, u32 hc_index, session_t *ts,
			    session_error_t err)
{
  clib_warning ("not supported");
  return 0;
}

static void
http_ts_disconnect_callback (session_t *ts)
{
  http_tc_t *hc;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);

  if (hc->state < HTTP_CONN_STATE_TRANSPORT_CLOSED)
    hc->state = HTTP_CONN_STATE_TRANSPORT_CLOSED;

  if (!svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_transport_closing_notify (&hc->connection);
}

static void
http_ts_reset_callback (session_t *ts)
{
  http_tc_t *ctx;

  ctx = http_conn_get_w_thread (ts->opaque, ts->thread_index);

  if (ctx->state < HTTP_CONN_STATE_TRANSPORT_CLOSED)
    ctx->state = HTTP_CONN_STATE_TRANSPORT_CLOSED;

  if (!svm_fifo_max_dequeue_cons (ts->rx_fifo))
    session_transport_reset_notify (&ctx->connection);
}

/**
 * http error boilerplate
 */
static const char *http_error_template = "HTTP/1.1 %s\r\n"
					 "Date: %U GMT\r\n"
					 "Content-Type: text/html\r\n"
					 "Connection: close\r\n"
					 "Pragma: no-cache\r\n"
					 "Content-Length: 0\r\n\r\n";

/**
 * http response boilerplate
 */
static const char *http_response_template = "Date: %U GMT\r\n"
					    "Expires: %U GMT\r\n"
					    "Server: VPP Static\r\n"
					    "Content-Type: %U\r\n"
					    "Content-Length: %d\r\n\r\n";

static u32
send_data (http_tc_t *hc, u8 *data, u32 length, u32 offset)
{
  const u32 max_burst = 64 << 10;
  session_t *ts;
  u32 to_send;
  int sent;

  ts = session_get_from_handle (hc->h_tc_session_handle);

  to_send = clib_min (length - offset, max_burst);
  sent = svm_fifo_enqueue (ts->tx_fifo, to_send, data + offset);

  if (sent <= 0)
    return offset;

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

  return (offset + sent);
}

static void
send_error (http_tc_t *hc, char *str)
{
  http_main_t *hm = &http_main;
  u8 *data;
  f64 now;

  now = clib_timebase_now (&hm->timebase);
  data = format (0, http_error_template, str, format_clib_timebase_time, now);
  send_data (hc, data, vec_len (data), 0);
  vec_free (data);
}

static int
read_request (http_tc_t *hc)
{
  u32 max_deq, cursize;
  session_t *ts;
  int n_read;

  ts = session_get_from_handle (hc->h_tc_session_handle);

  cursize = vec_len (hc->rx_buf);
  max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
  if (PREDICT_FALSE (max_deq == 0))
    return -1;

  vec_validate (hc->rx_buf, cursize + max_deq - 1);
  n_read = svm_fifo_dequeue (ts->rx_fifo, max_deq, hc->rx_buf + cursize);
  ASSERT (n_read == max_deq);

  if (svm_fifo_is_empty (ts->rx_fifo))
    svm_fifo_unset_event (ts->rx_fifo);

  _vec_len (hc->rx_buf) = cursize + n_read;
  return 0;
}

// static char *
// parse_req_content_type (http_tc_t *hc)
//{
//  char *suffix, *content_type;
//
//  suffix = (char *) (hc->path + vec_len (hc->path) - 1);
//  while ((u8 *) suffix >= hc->path && *suffix != '.')
//    suffix--;
//  suffix++;
//  content_type = "text/html";
//  if (!clib_strcmp (suffix, "css"))
//    content_type = "text/css";
//  else if (!clib_strcmp (suffix, "js"))
//    content_type = "text/javascript";
//  else if (!clib_strcmp (suffix, "json"))
//    content_type = "application/json";
//
//  return content_type;
//}

static u8 *
format_content_type (u8 *s, va_list *args)
{
  http_content_type_t type = va_arg (*args, http_content_type_t);

  switch (type)
    {
    case HTTP_CONTENT_TEXT_HTML:
      format (s, "%s", "text/html");
      break;
    case HTTP_CONTENT_TEXT_CSS:
      format (s, "%s", "text/css");
      break;
    case HTTP_CONTENT_TEXT_JS:
      format (s, "%s", "text/javascript");
      break;
    case HTTP_CONTENT_TEXT_JSON:
      format (s, "%s", "application/json");
      break;
    }

  return s;
}

static int
v_find_index (u8 *vec, char *str)
{
  int start_index;
  u32 slen = (u32) strnlen_s_inline (str, 8);
  u32 vlen = vec_len (vec);

  ASSERT (slen > 0);

  if (vlen <= slen)
    return -1;

  for (start_index = 0; start_index < (vlen - slen); start_index++)
    {
      if (!memcmp (vec, str, slen))
	return start_index;
    }

  return -1;
}

int
http_find_data (http_tc_t *hc, http_req_method_t request_type, u8 *request)
{
  return 0;

  //  http_main_t *hm = &http_main;
  //  struct stat _sb, *sb = &_sb;
  //  uword *p, *builtin_table;
  //  clib_error_t *error;
  //  u8 *path, save_byte;
  //  int i;
  //
  //  /* Temporarily drop in a NULL byte for lookup purposes */
  //  for (i = 0; i < vec_len (request); i++)
  //    {
  //      if (request[i] == ' ' || request[i] == '?')
  //	{
  //	  save_byte = request[i];
  //	  request[i] = 0;
  //	  break;
  //	}
  //    }
  //
  //  /*
  //   * Now we can construct the file to open
  //   * Browsers are capable of sporadically including a leading '/'
  //   */
  //  if (request[0] == '/')
  //    path = format (0, "%s%s%c", hm->www_root, request, 0);
  //  else
  //    path = format (0, "%s/%s%c", hm->www_root, request, 0);
  //
  //  if (hm->debug_level > 0)
  //    clib_warning ("%s '%s'", (request_type) == HTTP_REQ_GET ?
  //		  "GET" : "POST", path);
  //
  //  /* Look for built-in GET / POST handlers */
  //  builtin_table = (request_type == HTTP_REQ_GET) ?
  //    hm->get_url_handlers : hm->post_url_handlers;
  //
  //  p = hash_get_mem (builtin_table, request);
  //
  //  if (save_byte != 0)
  //    request[i] = save_byte;
  //
  //  if (p)
  //    {
  //      int rv;
  //      int (*fp) (http_builtin_method_type_t, u8 *, http_session_t *);
  //      fp = (void *) p[0];
  //      hc->path = path;
  //      rv = (*fp) (request_type, request, hc);
  //      if (rv)
  //	{
  //	  clib_warning ("builtin handler %llx hit on %s '%s' but failed!",
  //			p[0], (request_type == HTTP_REQ_GET) ?
  //			"GET" : "POST", request);
  //	  send_error (hc, "404 Not Found");
  //	  close_session (hc);
  //	  return -1;
  //	}
  //      vec_reset_length (hc->rx_buf);
  //      goto send_ok;
  //    }
  //
  //  vec_reset_length (hc->rx_buf);
  //  /* poison request, it's not valid anymore */
  //  request = 0;
  //  /* The static server itself doesn't do POSTs */
  //  if (request_type == HTTP_REQ_POST)
  //    {
  //      send_error (hc, "404 Not Found");
  //      close_session (hc);
  //      return -1;
  //    }
  //
  //  /* Try to find the file. 2x special cases to find index.html */
  //  if (stat ((char *) path, sb) < 0	/* cant even stat the file */
  //      || sb->st_size < 20	/* file too small */
  //      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */ )
  //    {
  //      u32 save_length = vec_len (path) - 1;
  //      /* Try appending "index.html"... */
  //      _vec_len (path) -= 1;
  //      path = format (path, "index.html%c", 0);
  //      if (stat ((char *) path, sb) < 0	/* cant even stat the file */
  //	  || sb->st_size < 20	/* file too small */
  //	  || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */ )
  //	{
  //	  _vec_len (path) = save_length;
  //	  path = format (path, "/index.html%c", 0);
  //
  //	  /* Send a redirect, otherwise the browser will confuse itself */
  //	  if (stat ((char *) path, sb) < 0	/* cant even stat the file */
  //	      || sb->st_size < 20	/* file too small */
  //	      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */ )
  //	    {
  //	      vec_free (path);
  //	      send_error (hc, "404 Not Found");
  //	      close_session (hc);
  //	      return -1;
  //	    }
  //	  else
  //	    {
  //	      transport_endpoint_t endpoint;
  //	      transport_proto_t proto;
  //	      u16 local_port;
  //	      int print_port = 0;
  //	      u8 *port_str = 0;
  //	      session_t * s;
  //
  //	      /*
  //	       * To make this bit work correctly, we need to know our local
  //	       * IP address, etc. and send it in the redirect...
  //	       */
  //	      u8 *redirect;
  //
  //	      s = session_get_from_handle (hc->h_tc_session_handle);
  //
  //	      vec_delete (path, vec_len (hm->www_root) - 1, 0);
  //
  //	      session_get_endpoint (s, &endpoint, 1 /* is_local */ );
  //
  //	      local_port = clib_net_to_host_u16 (endpoint.port);
  //
  //	      proto = session_type_transport_proto (s->session_type);
  //
  //	      if ((proto == TRANSPORT_PROTO_TCP && local_port != 80)
  //		  || (proto == TRANSPORT_PROTO_TLS && local_port != 443))
  //		{
  //		  print_port = 1;
  //		  port_str = format (0, ":%u", (u32) local_port);
  //		}
  //
  //	      redirect = format (0, "HTTP/1.1 301 Moved Permanently\r\n"
  //				 "Location: http%s://%U%s%s\r\n\r\n",
  //				 proto == TRANSPORT_PROTO_TLS ? "s" : "",
  //				 format_ip46_address, &endpoint.ip,
  //				 endpoint.is_ip4,
  //				 print_port ? port_str : (u8 *) "", path);
  //	      if (hm->debug_level > 0)
  //		clib_warning ("redirect: %s", redirect);
  //
  //	      vec_free (port_str);
  //
  //	      static_send_data (hc, redirect, vec_len (redirect), 0);
  //	      hc->state = HTTP_CONN_STATE_CLOSED;
  //	      hc->path = 0;
  //	      vec_free (redirect);
  //	      vec_free (path);
  //	      close_session (hc);
  //	      return -1;
  //	    }
  //	}
  //    }
  //
  //  /* find or read the file if we haven't done so yet. */
  //  if (hc->tx_buf == 0)
  //    {
  //      BVT (clib_bihash_kv) kv;
  //      file_data_cache_t *dp;
  //
  //      hc->path = path;
  //
  //      /* First, try the cache */
  //      kv.key = (u64) hc->path;
  //      if (BV (clib_bihash_search) (&hm->name_to_data, &kv, &kv) == 0)
  //	{
  //	  if (hm->debug_level > 1)
  //	    clib_warning ("lookup '%s' returned %lld", kv.key, kv.value);
  //
  //	  /* found the data.. */
  //	  dp = pool_elt_at_index (hm->cache_pool, kv.value);
  //	  hc->tx_buf = dp->data;
  //	  /* Update the cache entry, mark it in-use */
  //	  lru_update (hm, dp, vlib_time_now (vlib_get_main ()));
  //	  hc->cache_pool_index = dp - hm->cache_pool;
  //	  dp->inuse++;
  //	  if (hm->debug_level > 1)
  //	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
  //			  dp->inuse);
  //	}
  //      else
  //	{
  //	  if (hm->debug_level > 1)
  //	    clib_warning ("lookup '%s' failed", kv.key, kv.value);
  //	  /* Need to recycle one (or more cache) entries? */
  //	  if (hm->cache_size > hm->cache_limit)
  //	    {
  //	      int free_index = hm->last_index;
  //
  //	      while (free_index != ~0)
  //		{
  //		  /* pick the LRU */
  //		  dp = pool_elt_at_index (hm->cache_pool, free_index);
  //		  free_index = dp->prev_index;
  //		  /* Which could be in use... */
  //		  if (dp->inuse)
  //		    {
  //		      if (hm->debug_level > 1)
  //			clib_warning ("index %d in use refcnt %d",
  //				      dp - hm->cache_pool, dp->inuse);
  //
  //		    }
  //		  kv.key = (u64) (dp->filename);
  //		  kv.value = ~0ULL;
  //		  if (BV (clib_bihash_add_del) (&hm->name_to_data, &kv,
  //						0 /* is_add */ ) < 0)
  //		    {
  //		      clib_warning ("LRU delete '%s' FAILED!", dp->filename);
  //		    }
  //		  else if (hm->debug_level > 1)
  //		    clib_warning ("LRU delete '%s' ok", dp->filename);
  //
  //		  lru_remove (hm, dp);
  //		  hm->cache_size -= vec_len (dp->data);
  //		  hm->cache_evictions++;
  //		  vec_free (dp->filename);
  //		  vec_free (dp->data);
  //		  if (hm->debug_level > 1)
  //		    clib_warning ("pool put index %d", dp - hm->cache_pool);
  //		  pool_put (hm->cache_pool, dp);
  //		  if (hm->cache_size < hm->cache_limit)
  //		    break;
  //		}
  //	    }
  //
  //	  /* Read the file */
  //	  error = clib_file_contents ((char *) (hc->path), &hc->tx_buf);
  //	  if (error)
  //	    {
  //	      clib_warning ("Error reading '%s'", hs->path);
  //	      clib_error_report (error);
  //	      vec_free (hc->path);
  //	      close_session (hc);
  //	      return -1;
  //	    }
  //	  /* Create a cache entry for it */
  //	  pool_get (hm->cache_pool, dp);
  //	  memset (dp, 0, sizeof (*dp));
  //	  dp->filename = vec_dup (hc->path);
  //	  dp->data = hc->tx_buf;
  //	  hc->cache_pool_index = dp - hm->cache_pool;
  //	  dp->inuse++;
  //	  if (hm->debug_level > 1)
  //	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
  //			  dp->inuse);
  //	  lru_add (hm, dp, vlib_time_now (vlib_get_main ()));
  //	  kv.key = (u64) vec_dup (hc->path);
  //	  kv.value = dp - hm->cache_pool;
  //	  /* Add to the lookup table */
  //	  if (hm->debug_level > 1)
  //	    clib_warning ("add '%s' value %lld", kv.key, kv.value);
  //
  //	  if (BV (clib_bihash_add_del) (&hm->name_to_data, &kv,
  //					1 /* is_add */ ) < 0)
  //	    {
  //	      clib_warning ("BUG: add failed!");
  //	    }
  //	  hm->cache_size += vec_len (dp->data);
  //	}
  //      hc->tx_buf_offset = 0;
  //    }
}

/**
 * waiting for request method from peer - parse request method and data
 */
static int
state_wait_method (http_tc_t *hc)
{
  http_main_t *hm = &http_main;
  app_worker_t *app_wrk;
  http_msg_t msg;
  session_t *as;
  int i, rv;
  u32 len;
  u8 *buf;

  rv = read_request (hc);

  /* Nothing yet, wait for data or timer expire */
  if (rv)
    return 0;

  if (vec_len (hc->rx_buf) < 8)
    {
      send_error (hc, "400 Bad Request");
      http_disconnect_transport (hc);
      return -1;
    }

  if ((i = v_find_index (hc->rx_buf, "GET ")) >= 0)
    {
      hc->method = HTTP_REQ_GET;
      hc->rx_buf_offset = i + 5;
    }
  else if ((i = v_find_index (hc->rx_buf, "POST ")) >= 0)
    {
      hc->method = HTTP_REQ_POST;
      hc->rx_buf_offset = i + 6;
    }
  else
    {
      if (hm->debug_level > 1)
	clib_warning ("Unknown http method");

      send_error (hc, "405 Method Not Allowed");
      http_disconnect_transport (hc);
      return -1;
    }

  buf = &hc->rx_buf[hc->rx_buf_offset];
  len = vec_len (hc->rx_buf) - hc->rx_buf_offset;

  msg.type = HTTP_MSG_REQUEST;
  msg.data.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.len = len;
  msg.data.offset = 0;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) }, { buf, len } };

  as = session_get_from_handle (hc->h_pa_session_handle);
  rv = svm_fifo_enqueue_segments (as->rx_fifo, segs, 2, 0 /* allow partial */);
  if (rv < 0 || rv != sizeof (msg) + len)
    {
      clib_warning ("failed app enqueue");
      /* TODO reschedule */
      return -1;
    }

  vec_free (hc->rx_buf);
  hc->req_state = HTTP_REQ_STATE_WAIT_APP;

  app_wrk = app_worker_get_if_valid (as->app_wrk_index);
  app_worker_lock_and_send_event (app_wrk, as, SESSION_IO_EVT_RX);

  return 0;
}

/**
 * waiting for data from app
 */
static int
state_wait_app (http_tc_t *hc)
{
  http_main_t *hm = &http_main;
  http_msg_t msg;
  session_t *as;
  u8 *header;
  u32 offset;
  f64 now;
  int rv;

  as = session_get_from_handle (hc->h_pa_session_handle);

  rv = svm_fifo_dequeue (as->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REPLY)
    {
      clib_warning ("unexpected msg type from app %u", msg.type);
      goto error;
    }

  if (http_conn_init_tx_buf (hc, as->tx_fifo, msg.data.len))
    {
      clib_warning ("failed to init tx buf");
      goto error;
    }

  /* Add 200 OK first */
  header = format (0, "HTTP/1.1 200 OK\r\n");

  /*
   * Add headers. For now:
   * - current time
   * - expiration time
   * - content type
   * - data length
   */
  now = clib_timebase_now (&hm->timebase);
  header = format (header, http_response_template,
		   /* Date */
		   format_clib_timebase_time, now,
		   /* Expires */
		   format_clib_timebase_time, now + 600.0,
		   /* Content type */
		   format_content_type, msg.data.content_type,
		   /* Length */
		   msg.data.len);

  clib_warning ("data len %u", msg.data.len);
  offset = send_data (hc, header, vec_len (header), 0);
  if (offset != vec_len (header))
    {
      clib_warning ("couldn't send response header!");
      goto error;
    }
  vec_free (header);

  /* Start sending the actual data */
  hc->req_state = HTTP_REQ_STATE_SEND_MORE_DATA;

  return 1;

error:

  send_error (hc, "500 Internal Server Error");
  hc->req_state = HTTP_REQ_STATE_WAIT_METHOD;
  http_disconnect_transport (hc);

  /* stop state machine processing */
  return 0;
}

// static int
// state_sent_ok (http_tc_t *hc)
//{
//  http_main_t *hm = &http_main;
//  u8 *header;
//  u32 offset;
//  f64 now;
//
//  if (PREDICT_FALSE (!hc->tx_buf))
//    {
//      clib_warning ("BUG: hs->data not set for conn %d", hc->c_c_index);
//      http_disconnect_transport (hc);
//      return 0;
//    }
//
//  /*
//   * Send an http response, which needs the current time,
//   * the expiration time, and the data length
//   */
//  now = clib_timebase_now (&hm->timebase);
//  header = format (0, http_response_template,
//		   /* Date */
//		   format_clib_timebase_time, now,
//		   /* Expires */
//		   format_clib_timebase_time, now + 600.0,
//		   parse_req_content_type (hc), vec_len (hc->tx_buf));
//
//  offset = send_data (hc, header, vec_len (header), 0);
//  if (offset != vec_len (header))
//    {
//      clib_warning ("BUG: couldn't send response header!");
//      http_disconnect_transport (hc);
//      return 0;
//    }
//  vec_free (header);
//
//  /* Start sending the actual data */
//  hc->tx_buf_offset = 0;
//  hc->req_state = HTTP_REQ_STATE_SEND_MORE_DATA;
//
//  return 1;
//}

static int
state_send_more_data (http_tc_t *hc)
{
  u32 max_send = 64 << 10, si, n_segs, seg_send = 0;
  http_buffer_t *hb = &hc->tx_buf;
  svm_fifo_seg_t *seg;
  session_t *ts, *as;
  int sent;

  max_send = clib_max (hb->len - hb->offset, max_send);
  si = hb->cur_seg;

  while (si < vec_len (hb->segs) && seg_send < max_send)
    {
      seg_send += hb->segs[si].len;
      si += 1;
    }

  seg = &hb->segs[hb->cur_seg];
  n_segs = si == hb->cur_seg ? 1 : si - hb->cur_seg;

  ts = session_get_from_handle (hc->h_tc_session_handle);
  sent = svm_fifo_enqueue_segments (ts->tx_fifo, seg, n_segs,
				    1 /* allow partial */);

  if (sent < 0)
    return 0;

  clib_warning ("sent %u n_segs %u out of %u to tcp %u:%u max deq %u", sent,
		n_segs, seg_send, ts->thread_index, ts->session_index,
		svm_fifo_max_dequeue (ts->tx_fifo));

  as = session_get_from_handle (hc->h_pa_session_handle);
  svm_fifo_dequeue_drop (as->tx_fifo, sent);
  if (svm_fifo_needs_deq_ntf (as->tx_fifo, sent))
    session_dequeue_notify (as);

  hb->offset += sent;

  /* Find partially sent segment, if any, and update */
  if (sent < seg_send)
    {
      clib_warning ("this???");
      seg = &hb->segs[si];
      while (seg_send - seg->len > sent)
	{
	  seg -= 1;
	  seg_send -= seg->len;
	}
      sent = seg_send - sent;
      seg->data += sent;
      seg->len -= sent;

      hb->cur_seg = seg - hb->segs;
    }
  else
    {
      hb->cur_seg = si;
    }

  clib_warning ("offset %u buf len %u", hb->offset, hb->len);
  /* Not finished sending all data */
  if (hb->offset < hb->len)
    {
      if (svm_fifo_set_event (ts->tx_fifo))
	session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

      os_panic ();
      return 0;
    }
  else
    {
      if (svm_fifo_set_event (ts->tx_fifo))
	session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX_FLUSH);
    }

  /* Finished transaction, back to HTTP_REQ_STATE_WAIT_METHOD */
  hc->req_state = HTTP_REQ_STATE_WAIT_METHOD;
  http_conn_free_tx_buf (hc);

  return 0;
}

typedef int (*http_sm_handler) (http_tc_t *);

static http_sm_handler req_state_funcs[HTTP_REQ_N_STATES] = {
  /* Waiting for GET, POST, etc. */
  state_wait_method,
  /* Wait for data from app */
  state_wait_app,
  /* Send more data */
  state_send_more_data,
};

static void
http_req_run_state_machine (http_tc_t *hc)
{
  int rv;

  do
    {
      rv = req_state_funcs[hc->req_state](hc);
      if (rv < 0)
	return;
    }
  while (rv);

  /* Reset the session expiration timer */
  http_connection_timer_update (hc);
}

static int
http_ts_rx_callback (session_t *ts)
{
  http_tc_t *hc;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);

  if (hc->req_state != HTTP_REQ_STATE_WAIT_METHOD)
    {
      clib_warning ("tcp data in req state %u", hc->req_state);
      return 0;
    }

  http_req_run_state_machine (hc);

  if (hc->state == HTTP_CONN_STATE_TRANSPORT_CLOSED)
    {
      if (!svm_fifo_max_dequeue_cons (ts->rx_fifo))
	session_transport_closing_notify (&hc->connection);
    }
  return 0;
}

int
http_ts_builtin_tx_callback (session_t *ts)
{
  clib_warning ("called?");
  return 0;
}

static void
http_ts_cleanup_callback (session_t *ts, session_cleanup_ntf_t ntf)
{
  http_tc_t *hc;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hc = http_conn_get_w_thread (ts->opaque, ts->thread_index);
  if (!hc)
    {
      clib_warning ("no http connection for %u", ts->session_index);
      return;
    }

  vec_free (hc->rx_buf);

  http_conn_free_tx_buf (hc);
  http_connection_timer_stop (hc);

  session_transport_delete_notify (&hc->connection);
  http_conn_free (hc);
}

int
http_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* No-op for builtin */
  return 0;
}

int
http_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t http_app_cb_vft = {
  .session_accept_callback = http_ts_accept_callback,
  .session_disconnect_callback = http_ts_disconnect_callback,
  .session_connected_callback = http_ts_connected_callback,
  .session_reset_callback = http_ts_reset_callback,
  .session_cleanup_callback = http_ts_cleanup_callback,
  .add_segment_callback = http_add_segment_callback,
  .del_segment_callback = http_del_segment_callback,
  .builtin_app_rx_callback = http_ts_rx_callback,
  .builtin_app_tx_callback = http_ts_builtin_tx_callback,
};

static clib_error_t *
http_transport_enable (vlib_main_t *vm, u8 is_en)
{
  u32 add_segment_size = 256 << 20, first_seg_size = 32 << 20;
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  http_main_t *hm = &http_main;
  u32 fifo_size = 128 << 12;

  if (!is_en)
    {
      da->app_index = hm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  vec_validate (hm->wrk, vlib_num_workers ());

  first_seg_size = hm->first_seg_size ? hm->first_seg_size : first_seg_size;
  fifo_size = hm->fifo_size ? hm->fifo_size : fifo_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &http_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "http");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    return clib_error_return (0, "failed to attach http app");

  hm->app_index = a->app_index;
  vec_free (a->name);

  clib_timebase_init (&hm->timebase, 0 /* GMT */, CLIB_TIMEBASE_DAYLIGHT_NONE,
		      &vm->clib_time /* share the system clock */);

  http_timers_init (vm);

  return 0;
}

static int
http_transport_connect (transport_endpoint_cfg_t *tep)
{
  return -1;
}

static u32
http_start_listen (u32 app_listener_index, transport_endpoint_t *tep)
{
  vnet_listen_args_t _args = {}, *args = &_args;
  session_t *tc_listener, *app_listener;
  http_main_t *hm = &http_main;
  session_endpoint_cfg_t *sep;
  app_worker_t *app_wrk;
  transport_proto_t tp;
  app_listener_t *al;
  application_t *app;
  http_tc_t *lhc;
  u32 lhc_index;

  sep = (session_endpoint_cfg_t *) tep;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  args->app_index = hm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  tp = sep->ext_cfg ? TRANSPORT_PROTO_TLS : TRANSPORT_PROTO_TCP;
  args->sep_ext.transport_proto = tp;

  if (vnet_listen (args))
    return SESSION_INVALID_INDEX;

  lhc_index = http_listener_alloc ();
  lhc = http_listener_get (lhc_index);

  /* Grab transport connection listener and link to http listener */
  lhc->h_tc_session_handle = args->handle;
  al = app_listener_get_w_handle (lhc->h_tc_session_handle);
  tc_listener = app_listener_get_session (al);
  tc_listener->opaque = lhc_index;

  /* Grab application listener and link to http listener */
  app_listener = listen_session_get (app_listener_index);
  lhc->h_pa_wrk_index = sep->app_wrk_index;
  lhc->h_pa_session_handle = listen_session_get_handle (app_listener);
  lhc->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  return lhc_index;
}

static void
http_transport_close (u32 hc_index, u32 thread_index)
{
  session_t *as;
  http_tc_t *hc;

  HTTP_DBG (1, "App disconnecting %x", hc_index);

  hc = http_conn_get_w_thread (hc_index, thread_index);
  as = session_get_from_handle (hc->h_pa_session_handle);

  /* Nothing more to send, confirm close */
  if (!svm_fifo_max_dequeue_cons (as->tx_fifo))
    {
      session_transport_closed_notify (&hc->connection);
      http_disconnect_transport (hc);
    }
  else
    {
      /* Wait for all data to be written to ts */
      hc->state = HTTP_CONN_STATE_APP_CLOSED;
    }
}

static transport_connection_t *
http_transport_get_connection (u32 hc_index, u32 thread_index)
{
  http_tc_t *hc = http_conn_get_w_thread (hc_index, thread_index);
  return &hc->connection;
}

static transport_connection_t *
http_transport_get_listener (u32 listener_index)
{
  http_tc_t *lhc = http_listener_get (listener_index);
  return &lhc->connection;
}

static int
http_app_tx_callback (void *session, transport_send_params_t *sp)
{
  session_t *as = (session_t *) session, *ts;
  http_tc_t *hc;

  hc = http_conn_get_w_thread (as->connection_index, as->thread_index);
  if (hc->req_state < HTTP_REQ_STATE_WAIT_APP)
    {
      clib_warning ("app data in req state %u", hc->req_state);
      return 0;
    }

  http_req_run_state_machine (hc);

  if (hc->req_state == HTTP_REQ_STATE_SEND_MORE_DATA)
    {
      clib_warning ("more data?");
      ts = session_get_from_handle (hc->h_tc_session_handle);
      if (svm_fifo_max_enqueue (ts->tx_fifo) < 16 << 10)
	{
	  /* Deschedule and wait for deq notification if fifo almost full */
	  svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  transport_connection_deschedule (&hc->connection);
	  sp->flags |= TRANSPORT_SND_F_DESCHED;
	}
      else
	{
	  /* Request tx reschedule of the app session */
	  as->flags |= SESSION_F_CUSTOM_TX;
	}
    }

  if (hc->state == HTTP_CONN_STATE_CLOSED)
    {
      if (!svm_fifo_max_dequeue_cons (as->rx_fifo))
	http_disconnect_transport (hc);
    }
  return 0;
}

static u8 *
format_http_connection (u8 *s, va_list *args)
{
  http_tc_t *hc = va_arg (*args, http_tc_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->h_tc_session_handle);
  s = format (s, "[%d:%d][H] app_wrk %u ts %d:%d", hc->c_thread_index,
	      hc->c_s_index, hc->h_pa_wrk_index, ts->thread_index,
	      ts->session_index);

  return s;
}

static u8 *
format_http_listener (u8 *s, va_list *args)
{
  http_tc_t *lhc = va_arg (*args, http_tc_t *);
  app_listener_t *al;
  session_t *lts;

  al = app_listener_get_w_handle (lhc->h_tc_session_handle);
  lts = app_listener_get_session (al);
  s = format (s, "[%d:%d][H] app_wrk %u ts %d:%d", lhc->c_thread_index,
	      lhc->c_s_index, lhc->h_pa_wrk_index, lts->thread_index,
	      lts->session_index);

  return s;
}

static u8 *
format_http_conn_state (u8 *s, va_list *args)
{
  http_tc_t *hc = va_arg (*args, http_tc_t *);

  switch (hc->state)
    {
    case HTTP_CONN_STATE_LISTEN:
      s = format (s, "LISTEN");
      break;
    case HTTP_CONN_STATE_CONNECTING:
      s = format (s, "CONNECTING");
      break;
    case HTTP_CONN_STATE_ESTABLISHED:
      s = format (s, "ESTABLISHED");
      break;
    case HTTP_CONN_STATE_TRANSPORT_CLOSED:
      s = format (s, "TRANSPORT_CLOSED");
      break;
    case HTTP_CONN_STATE_APP_CLOSED:
      s = format (s, "APP_CLOSED");
      break;
    case HTTP_CONN_STATE_CLOSED:
      s = format (s, "CLOSED");
      break;
    }

  return s;
}

static u8 *
format_http_transport_connection (u8 *s, va_list *args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  http_tc_t *hc;

  hc = http_conn_get_w_thread (tc_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http_connection, hc);
  if (verbose)
    {
      s =
	format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, hc);
      if (verbose > 1)
	s = format (s, "\n");
    }

  return s;
}

static u8 *
format_http_transport_listener (u8 *s, va_list *args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 __clib_unused verbose = va_arg (*args, u32);
  http_tc_t *lhc = http_listener_get (tc_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http_listener, lhc);
  if (verbose)
    s =
      format (s, "%-" SESSION_CLI_STATE_LEN "U", format_http_conn_state, lhc);
  return s;
}

static const transport_proto_vft_t http_proto = {
  .enable = http_transport_enable,
  .connect = http_transport_connect,
  .start_listen = http_start_listen,
  .close = http_transport_close,
  .custom_tx = http_app_tx_callback,
  .get_connection = http_transport_get_connection,
  .get_listener = http_transport_get_listener,
  .format_connection = format_http_transport_connection,
  .format_listener = format_http_transport_listener,
  .transport_options = {
    .name = "http",
    .short_name = "H",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static clib_error_t *
http_transport_init (vlib_main_t *vm)
{
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_HTTP, &http_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (http_transport_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Hypertext Transfer Protocol (HTTP)",
  .default_disabled = 0,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
