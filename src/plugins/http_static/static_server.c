/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/unix.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <http_static/http_static.h>

#include <vppinfra/bihash_template.c>
#include <http/http.h>

/** @file static_server.c
 *  Static http server, sufficient to
 *  serve .html / .css / .js content.
 */
/*? %%clicmd:group_label Static HTTP Server %% ?*/

#define HSS_FIFO_THRESH (16 << 10)

http_static_server_main_t hss_main;

///** \brief Format the called-from enum
// */
//
//static u8 *
//format_state_machine_called_from (u8 * s, va_list * args)
//{
//  http_state_machine_called_from_t cf =
//    va_arg (*args, http_state_machine_called_from_t);
//  char *which = "bogus!";
//
//  switch (cf)
//    {
//    case CALLED_FROM_RX:
//      which = "from rx";
//      break;
//    case CALLED_FROM_TX:
//      which = "from tx";
//      break;
//    case CALLED_FROM_TIMER:
//      which = "from timer";
//      break;
//
//    default:
//      break;
//    }
//
//  s = format (s, "%s", which);
//  return s;
//}


static void
hss_cache_lock (void)
{
  clib_spinlock_lock (&hss_main.cache_lock);
}

static void
hss_cache_unlock (void)
{
  clib_spinlock_unlock (&hss_main.cache_lock);
}

///** \brief Start a session cleanup timer
// */
//static void
//http_static_server_session_timer_start (http_session_t * hs)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  u32 hs_handle;
//
//  /* The session layer may fire a callback at a later date... */
//  if (!pool_is_free (hsm->sessions[hs->thread_index], hs))
//    {
//      hs_handle = hs->thread_index << 24 | hs->session_index;
//      clib_spinlock_lock (&http_static_server_main.tw_lock);
//      hs->timer_handle = tw_timer_start_2t_1w_2048sl
//	(&http_static_server_main.tw, hs_handle, 0, 60);
//      clib_spinlock_unlock (&http_static_server_main.tw_lock);
//    }
//}
//
///** \brief stop a session cleanup timer
// */
//static void
//http_static_server_session_timer_stop (http_session_t * hs)
//{
//  if (hs->timer_handle == ~0)
//    return;
//  clib_spinlock_lock (&http_static_server_main.tw_lock);
//  tw_timer_stop_2t_1w_2048sl (&http_static_server_main.tw, hs->timer_handle);
//  clib_spinlock_unlock (&http_static_server_main.tw_lock);
//}
//
/** \brief Allocate an http session
 */
static http_session_t *
hss_session_alloc (u32 thread_index)
{
  http_static_server_main_t *hsm = &hss_main;
  http_session_t *hs;
  pool_get_aligned_zero_numa (hsm->sessions[thread_index], hs,
			      0 /* not aligned */ ,
			      1 /* zero */ ,
			      os_get_numa_index ());
  hs->session_index = hs - hsm->sessions[thread_index];
  hs->thread_index = thread_index;
  hs->timer_handle = ~0;
  hs->cache_pool_index = ~0;
  return hs;
}

/** \brief Get an http session by index
 */
static http_session_t *
hss_session_get (u32 thread_index, u32 hs_index)
{
  http_static_server_main_t *hsm = &hss_main;
  if (pool_is_free_index (hsm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hsm->sessions[thread_index], hs_index);
}

/** \brief Free an http session
 */
static void
hss_session_free (http_session_t * hs)
{
  http_static_server_main_t *hsm = &hss_main;

//  /* Make sure the timer is stopped... */
//  http_static_server_session_timer_stop (hs);
  pool_put (hsm->sessions[hs->thread_index], hs);

  if (CLIB_DEBUG)
    {
      u32 save_thread_index;
      save_thread_index = hs->thread_index;
      /* Poison the entry, preserve timer state and thread index */
      memset (hs, 0xfa, sizeof (*hs));
      hs->timer_handle = ~0;
      hs->thread_index = save_thread_index;
    }
}
//
///** \brief add a session to the vpp < -- > http session index map
// */
//static void
//http_static_server_session_lookup_add (u32 thread_index, u32 s_index,
//				       u32 hs_index)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  vec_validate (hsm->session_to_http_session[thread_index], s_index);
//  hsm->session_to_http_session[thread_index][s_index] = hs_index;
//}

///** \brief Remove a session from the vpp < -- > http session index map
// */
//static void
//http_static_server_session_lookup_del (u32 thread_index, u32 s_index)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  hsm->session_to_http_session[thread_index][s_index] = ~0;
//}
//
///** \brief lookup a session in the vpp < -- > http session index map
// */
//static http_session_t *
//http_static_server_session_lookup (u32 thread_index, u32 s_index)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  u32 hs_index;
//
//  if (s_index < vec_len (hsm->session_to_http_session[thread_index]))
//    {
//      hs_index = hsm->session_to_http_session[thread_index][s_index];
//      return hss_session_get (thread_index, hs_index);
//    }
//  return 0;
//}

/** \brief Detach cache entry from session
 */
static void
hss_detach_cache_entry (http_session_t * hs)
{
  http_static_server_main_t *hsm = &hss_main;
  file_data_cache_t *ep;

  /*
   * Decrement cache pool entry reference count
   * Note that if e.g. a file lookup fails, the cache pool index
   * won't be set
   */
  if (hs->cache_pool_index != ~0)
    {
      ep = pool_elt_at_index (hsm->cache_pool, hs->cache_pool_index);
      ep->inuse--;
      if (hsm->debug_level > 1)
	clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
		      ep->inuse);
    }
  hs->cache_pool_index = ~0;
  if (hs->free_data)
    vec_free (hs->data);
  hs->data = 0;
  hs->data_offset = 0;
  hs->free_data = 0;
  vec_free (hs->path);
}

/** \brief Disconnect a session
 */
static void
hss_transport_session_disconnect (http_session_t * hs)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = hs->vpp_session_handle;
  a->app_index = hss_main.app_index;
  vnet_disconnect_session (a);
}

///** \brief http error boilerplate
// */
//static const char *http_error_template =
//    "HTTP/1.1 %s\r\n"
//    "Date: %U GMT\r\n"
//    "Content-Type: text/html\r\n"
//    "Connection: close\r\n"
//    "Pragma: no-cache\r\n"
//    "Content-Length: 0\r\n\r\n";
//
///** \brief http response boilerplate
// */
//static const char *http_response_template =
//    "Date: %U GMT\r\n"
//    "Expires: %U GMT\r\n"
//    "Server: VPP Static\r\n"
//    "Content-Type: %s\r\n"
//    "Content-Length: %d\r\n\r\n";


///** \brief send http data
//    @param hs - http session
//    @param data - the data vector to transmit
//    @param length - length of data
//    @param offset - transmit offset for this operation
//    @return offset for next transmit operation, may be unchanged w/ full fifo
//*/
//
//static u32
//static_send_data (http_session_t * hs, u8 * data, u32 length, u32 offset)
//{
//  u32 bytes_to_send;
//  http_static_server_main_t *hsm = &hss_main;
//
//  bytes_to_send = length - offset;
//
//  while (bytes_to_send > 0)
//    {
//      int actual_transfer;
//
//      actual_transfer = svm_fifo_enqueue (
//	hs->tx_fifo, clib_min (bytes_to_send, 4 << 20), data + offset);
//
//      /* Made any progress? */
//      if (actual_transfer <= 0)
//	{
//	  if (hsm->debug_level > 0 && bytes_to_send > 0)
//	    clib_warning ("WARNING: still %d bytes to send", bytes_to_send);
//	  return offset;
//	}
//      else
//	{
//	  offset += actual_transfer;
//	  bytes_to_send -= actual_transfer;
//
//	  if (hsm->debug_level && bytes_to_send > 0)
//	    clib_warning ("WARNING: still %d bytes to send", bytes_to_send);
//
//	  if (svm_fifo_set_event (hs->tx_fifo))
//	    session_send_io_evt_to_thread (hs->tx_fifo,
//					   SESSION_IO_EVT_TX_FLUSH);
//	  return offset;
//	}
//    }
//  /* NOTREACHED */
//  return ~0;
//}

///** \brief Send an http error string
//    @param hs - the http session
//    @param str - the error string, e.g. "404 Not Found"
//*/
//static void
//send_error (http_session_t * hs, char *str)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  u8 *data;
//  f64 now;
//
//  now = clib_timebase_now (&hsm->timebase);
//  data = format (0, http_error_template, str, format_clib_timebase_time, now);
//  static_send_data (hs, data, vec_len (data), 0);
//  vec_free (data);
//}
//
///** \brief Retrieve data from the application layer
// */
//static int
//session_rx_request (http_session_t * hs)
//{
//  u32 max_dequeue, cursize;
//  int n_read;
//
//  cursize = vec_len (hs->rx_buf);
//  max_dequeue = svm_fifo_max_dequeue (hs->rx_fifo);
//  if (PREDICT_FALSE (max_dequeue == 0))
//    return -1;
//
//  vec_validate (hs->rx_buf, cursize + max_dequeue - 1);
//  n_read = app_recv_stream_raw (hs->rx_fifo, hs->rx_buf + cursize,
//				max_dequeue, 0, 0 /* peek */ );
//  ASSERT (n_read == max_dequeue);
//  if (svm_fifo_is_empty (hs->rx_fifo))
//    svm_fifo_unset_event (hs->rx_fifo);
//
//  _vec_len (hs->rx_buf) = cursize + n_read;
//  return 0;
//}

/** \brief Sanity-check the forward and reverse LRU lists
 */
static inline void
lru_validate (http_static_server_main_t * hsm)
{
#if CLIB_DEBUG > 0
  f64 last_timestamp;
  u32 index;
  int i;
  file_data_cache_t *ep;

  last_timestamp = 1e70;
  for (i = 1, index = hsm->first_index; index != ~0;)
    {
      ep = pool_elt_at_index (hsm->cache_pool, index);
      index = ep->next_index;
      /* Timestamps should be smaller (older) as we walk the fwd list */
      if (ep->last_used > last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f",
			ep - hsm->cache_pool, i,
			ep->last_used, last_timestamp);
	}
      last_timestamp = ep->last_used;
      i++;
    }

  last_timestamp = 0.0;
  for (i = 1, index = hsm->last_index; index != ~0;)
    {
      ep = pool_elt_at_index (hsm->cache_pool, index);
      index = ep->prev_index;
      /* Timestamps should be larger (newer) as we walk the rev list */
      if (ep->last_used < last_timestamp)
	{
	  clib_warning ("%d[%d]: last used %.6f, last_timestamp %.6f",
			ep - hsm->cache_pool, i,
			ep->last_used, last_timestamp);
	}
      last_timestamp = ep->last_used;
      i++;
    }
#endif
}

/** \brief Remove a data cache entry from the LRU lists
 */
static inline void
lru_remove (http_static_server_main_t * hsm, file_data_cache_t * ep)
{
  file_data_cache_t *next_ep, *prev_ep;
  u32 ep_index;

  lru_validate (hsm);

  ep_index = ep - hsm->cache_pool;

  /* Deal with list heads */
  if (ep_index == hsm->first_index)
    hsm->first_index = ep->next_index;
  if (ep_index == hsm->last_index)
    hsm->last_index = ep->prev_index;

  /* Fix next->prev */
  if (ep->next_index != ~0)
    {
      next_ep = pool_elt_at_index (hsm->cache_pool, ep->next_index);
      next_ep->prev_index = ep->prev_index;
    }
  /* Fix prev->next */
  if (ep->prev_index != ~0)
    {
      prev_ep = pool_elt_at_index (hsm->cache_pool, ep->prev_index);
      prev_ep->next_index = ep->next_index;
    }
  lru_validate (hsm);
}

/** \brief Add an entry to the LRU lists, tag w/ supplied timestamp
 */

static inline void
lru_add (http_static_server_main_t * hsm, file_data_cache_t * ep, f64 now)
{
  file_data_cache_t *next_ep;
  u32 ep_index;

  lru_validate (hsm);

  ep_index = ep - hsm->cache_pool;

  /*
   * Re-add at the head of the forward LRU list,
   * tail of the reverse LRU list
   */
  if (hsm->first_index != ~0)
    {
      next_ep = pool_elt_at_index (hsm->cache_pool, hsm->first_index);
      next_ep->prev_index = ep_index;
    }

  ep->prev_index = ~0;

  /* ep now the new head of the LRU forward list */
  ep->next_index = hsm->first_index;
  hsm->first_index = ep_index;

  /* single session case: also the tail of the reverse LRU list */
  if (hsm->last_index == ~0)
    hsm->last_index = ep_index;
  ep->last_used = now;

  lru_validate (hsm);
}

/** \brief Remove and re-add a cache entry from/to the LRU lists
 */

static inline void
lru_update (http_static_server_main_t * hsm, file_data_cache_t * ep, f64 now)
{
  lru_remove (hsm, ep);
  lru_add (hsm, ep, now);
}

///** \brief Session-layer (main) data rx callback.
//    Parse the http request, and reply to it.
//    Future extensions might include POST processing, active content, etc.
//*/
//
///* svm_fifo_add_want_deq_ntf (tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL)
//get shoulder-tap when transport dequeues something, set in
//xmit routine. */

///** \brief closed state - should never really get here
// */
//static int
//state_closed (session_t * s, http_session_t * hs,
//	      http_state_machine_called_from_t cf)
//{
//  clib_warning ("WARNING: http session %d, called from %U",
//		hs->session_index, format_state_machine_called_from, cf);
//  return -1;
//}

//static void
//close_session (http_session_t * hs)
//{
//  hss_transport_session_disconnect (hs);
//}

/** \brief Register a builtin GET or POST handler
 */
__clib_export void http_static_server_register_builtin_handler
  (void *fp, char *url, int request_type)
{
  http_static_server_main_t *hsm = &hss_main;
  uword *p, *builtin_table;

  builtin_table = (request_type == HTTP_BUILTIN_METHOD_GET)
    ? hsm->get_url_handlers : hsm->post_url_handlers;

  p = hash_get_mem (builtin_table, url);

  if (p)
    {
      clib_warning ("WARNING: attempt to replace handler for %s '%s' ignored",
		    (request_type == HTTP_BUILTIN_METHOD_GET) ?
		    "GET" : "POST", url);
      return;
    }

  hash_set_mem (builtin_table, url, (uword) fp);

  /*
   * Need to update the hash table pointer in http_static_server_main
   * in case we just expanded it...
   */
  if (request_type == HTTP_BUILTIN_METHOD_GET)
    hsm->get_url_handlers = builtin_table;
  else
    hsm->post_url_handlers = builtin_table;
}

//static int
//v_find_index (u8 * vec, char *str)
//{
//  int start_index;
//  u32 slen = (u32) strnlen_s_inline (str, 8);
//  u32 vlen = vec_len (vec);
//
//  ASSERT (slen > 0);
//
//  if (vlen <= slen)
//    return -1;
//
//  for (start_index = 0; start_index < (vlen - slen); start_index++)
//    {
//      if (!memcmp (vec, str, slen))
//	return start_index;
//    }
//
//  return -1;
//}

static void
start_send_data (http_session_t *hs, http_status_code_t status)
{
  http_msg_t msg;
  session_t *ts;
  int rv;

  msg.type = HTTP_MSG_REPLY;
  msg.code = status;
  msg.content_type = HTTP_CONTENT_TEXT_HTML;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = vec_len (hs->data);

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (!msg.data.len)
    goto done;

  rv = svm_fifo_enqueue (ts->tx_fifo, vec_len (hs->data), hs->data);

  if (rv != vec_len (hs->data))
    {
      hs->data_offset = rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }
  else
    {
      vec_free (hs->data);
    }

done:

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);
}

static int
find_data (http_session_t *hs, http_req_method_t rt, u8 *request)
{
  http_static_server_main_t *hsm = &hss_main;
  u8 *path;
//  int i, rv;
  struct stat _sb, *sb = &_sb;
  clib_error_t *error;
  u8 request_type = HTTP_BUILTIN_METHOD_GET;
//  u8 save_byte = 0;
  uword *p, *builtin_table;
  http_status_code_t sc = HTTP_STATUS_OK;

  request_type = rt == HTTP_REQ_GET ? request_type : HTTP_BUILTIN_METHOD_POST;

  /*
   * Construct the file to open
   * Browsers are capable of sporadically including a leading '/'
   */
  if (request[0] == '/')
    path = format (0, "%s%s%c", hsm->www_root, request, 0);
  else
    path = format (0, "%s/%s%c", hsm->www_root, request, 0);

  if (hsm->debug_level > 0)
    clib_warning ("%s '%s'", (request_type) == HTTP_BUILTIN_METHOD_GET ?
		  "GET" : "POST", path);

  /* Look for built-in GET / POST handlers */
  builtin_table = (request_type == HTTP_BUILTIN_METHOD_GET) ?
    hsm->get_url_handlers : hsm->post_url_handlers;

  p = hash_get_mem (builtin_table, request);

  if (p)
    {
      int rv;
      int (*fp) (http_builtin_method_type_t, u8 *, http_session_t *);
      fp = (void *) p[0];
      hs->path = path;
      rv = (*fp) (request_type, request, hs);
      if (rv)
	{
	  clib_warning ("builtin handler %llx hit on %s '%s' but failed!",
			p[0], (request_type == HTTP_BUILTIN_METHOD_GET) ?
			"GET" : "POST", request);

	  sc = HTTP_STATUS_NOT_FOUND;
	  goto done;

//	  start_send_data (hs, HTTP_STATUS_NOT_FOUND);
//	  send_error (hs, "404 Not Found");
//	  close_session (hs);
//	  return -1;
	}
//      vec_reset_length (hs->rx_buf);
//      goto send_ok;
//      start_send_data (hs, HTTP_STATUS_OK);

      goto done;
    }
//  vec_reset_length (hs->rx_buf);
//  /* poison request, it's not valid anymore */
//  request = 0;
//  /* The static server itself doesn't do POSTs */
//  if (request_type == HTTP_BUILTIN_METHOD_POST)
//    {
//      send_error (hs, "404 Not Found");
//      close_session (hs);
//      return -1;
//    }

  /* Try to find the file. 2x special cases to find index.html */
  if (stat ((char *) path, sb) < 0	/* cant even stat the file */
      || sb->st_size < 20	/* file too small */
      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */ )
    {
      u32 save_length = vec_len (path) - 1;
      /* Try appending "index.html"... */
      _vec_len (path) -= 1;
      path = format (path, "index.html%c", 0);
      if (stat ((char *) path, sb) < 0	/* cant even stat the file */
	  || sb->st_size < 20	/* file too small */
	  || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */ )
	{
	  _vec_len (path) = save_length;
	  path = format (path, "/index.html%c", 0);

	  /* Send a redirect, otherwise the browser will confuse itself */
	  if (stat ((char *) path, sb) < 0	/* cant even stat the file */
	      || sb->st_size < 20	/* file too small */
	      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */ )
	    {
	      sc = HTTP_STATUS_NOT_FOUND;
	      goto done;
//	      vec_free (path);
//	      start_send_data (hs, HTTP_STATUS_NOT_FOUND);
//	      send_error (hs, "404 Not Found");
//	      close_session (hs);
//	      return -1;
	    }
	  else
	    {
	      transport_endpoint_t endpoint;
	      transport_proto_t proto;
	      u16 local_port;
	      int print_port = 0;
	      u8 *port_str = 0;
	      session_t *ts;

	      /*
	       * To make this bit work correctly, we need to know our local
	       * IP address, etc. and send it in the redirect...
	       */
	      u8 *redirect;

	      vec_delete (path, vec_len (hsm->www_root) - 1, 0);

	      ts = session_get (hs->vpp_session_index, hs->thread_index);
	      session_get_endpoint (ts, &endpoint, 1 /* is_local */ );

	      local_port = clib_net_to_host_u16 (endpoint.port);

	      proto = session_type_transport_proto (ts->session_type);

	      if ((proto == TRANSPORT_PROTO_TCP && local_port != 80)
		  || (proto == TRANSPORT_PROTO_TLS && local_port != 443))
		{
		  print_port = 1;
		  port_str = format (0, ":%u", (u32) local_port);
		}

	      redirect = format (0, "HTTP/1.1 301 Moved Permanently\r\n"
				 "Location: http%s://%U%s%s\r\n\r\n",
				 proto == TRANSPORT_PROTO_TLS ? "s" : "",
				 format_ip46_address, &endpoint.ip,
				 endpoint.is_ip4,
				 print_port ? port_str : (u8 *) "", path);
	      if (hsm->debug_level > 0)
		clib_warning ("redirect: %s", redirect);

	      vec_free (port_str);

	      hs->data = redirect;
	      goto done;

//	      start_send_data (hs, HTTP_STATUS_OK);
////	      static_send_data (hs, redirect, vec_len (redirect), 0);
//	      hs->session_state = HTTP_STATE_CLOSED;
//	      hs->path = 0;
//	      vec_free (redirect);
//	      vec_free (path);
//	      close_session (hs);
//	      return -1;
	    }
	}
    }

  /* find or read the file if we haven't done so yet. */
  if (hs->data == 0)
    {
      BVT (clib_bihash_kv) kv;
      file_data_cache_t *dp;

      hs->path = path;

      /* First, try the cache */
      kv.key = (u64) hs->path;
      if (BV (clib_bihash_search) (&hsm->name_to_data, &kv, &kv) == 0)
	{
	  if (hsm->debug_level > 1)
	    clib_warning ("lookup '%s' returned %lld", kv.key, kv.value);

	  hss_cache_lock ();

	  /* found the data.. */
	  dp = pool_elt_at_index (hsm->cache_pool, kv.value);
	  hs->data = dp->data;
	  /* Update the cache entry, mark it in-use */
	  lru_update (hsm, dp, vlib_time_now (vlib_get_main ()));
	  hs->cache_pool_index = dp - hsm->cache_pool;
	  dp->inuse++;
	  if (hsm->debug_level > 1)
	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
			  dp->inuse);

	  hss_cache_unlock ();
	}
      else
	{
	  hss_cache_lock ();

	  if (hsm->debug_level > 1)
	    clib_warning ("lookup '%s' failed", kv.key, kv.value);
	  /* Need to recycle one (or more cache) entries? */
	  if (hsm->cache_size > hsm->cache_limit)
	    {
	      int free_index = hsm->last_index;

	      while (free_index != ~0)
		{
		  /* pick the LRU */
		  dp = pool_elt_at_index (hsm->cache_pool, free_index);
		  free_index = dp->prev_index;
		  /* Which could be in use... */
		  if (dp->inuse)
		    {
		      if (hsm->debug_level > 1)
			clib_warning ("index %d in use refcnt %d",
				      dp - hsm->cache_pool, dp->inuse);

		    }
		  kv.key = (u64) (dp->filename);
		  kv.value = ~0ULL;
		  if (BV (clib_bihash_add_del) (&hsm->name_to_data, &kv,
						0 /* is_add */ ) < 0)
		    {
		      clib_warning ("LRU delete '%s' FAILED!", dp->filename);
		    }
		  else if (hsm->debug_level > 1)
		    clib_warning ("LRU delete '%s' ok", dp->filename);

		  lru_remove (hsm, dp);
		  hsm->cache_size -= vec_len (dp->data);
		  hsm->cache_evictions++;
		  vec_free (dp->filename);
		  vec_free (dp->data);
		  if (hsm->debug_level > 1)
		    clib_warning ("pool put index %d", dp - hsm->cache_pool);
		  pool_put (hsm->cache_pool, dp);
		  if (hsm->cache_size < hsm->cache_limit)
		    break;
		}
	    }

	  /* Read the file */
	  error = clib_file_contents ((char *) (hs->path), &hs->data);
	  if (error)
	    {
	      clib_warning ("Error reading '%s'", hs->path);
	      clib_error_report (error);
	      sc = HTTP_STATUS_INTERNAL_ERROR;
	      hss_cache_unlock ();
	      goto done;
//	      vec_free (hs->path);
//	      start_send_data (hs, HTTP_STATUS_INTERNAL_ERROR);
//	      close_session (hs);
//	      return -1;
	    }
	  /* Create a cache entry for it */
	  pool_get_zero (hsm->cache_pool, dp);
	  dp->filename = vec_dup (hs->path);
	  dp->data = hs->data;
	  hs->cache_pool_index = dp - hsm->cache_pool;
	  dp->inuse++;
	  if (hsm->debug_level > 1)
	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
			  dp->inuse);
	  lru_add (hsm, dp, vlib_time_now (vlib_get_main ()));
	  kv.key = (u64) vec_dup (hs->path);
	  kv.value = dp - hsm->cache_pool;
	  /* Add to the lookup table */
	  if (hsm->debug_level > 1)
	    clib_warning ("add '%s' value %lld", kv.key, kv.value);

	  if (BV (clib_bihash_add_del) (&hsm->name_to_data, &kv,
					1 /* is_add */ ) < 0)
	    {
	      clib_warning ("BUG: add failed!");
	    }
	  hsm->cache_size += vec_len (dp->data);

	  hss_cache_unlock ();
	}
      hs->data_offset = 0;
    }
//  /* send 200 OK first */
//send_ok:
//  static_send_data (hs, (u8 *) "HTTP/1.1 200 OK\r\n", 17, 0);
//  hs->session_state = HTTP_STATE_OK_SENT;
//  return 1;

done:

  vec_free (path);

  return sc;
}

//static int
//state_send_more_data (session_t * s, http_session_t * hs,
//		      http_state_machine_called_from_t cf)
//{
//
//  /* Start sending data */
//  hs->data_offset = static_send_data (hs, hs->data, vec_len (hs->data),
//				      hs->data_offset);
//
//  /* Did we finish? */
//  if (hs->data_offset < vec_len (hs->data))
//    {
//      /* No: ask for a shoulder-tap when the tx fifo has space */
//      svm_fifo_add_want_deq_ntf (hs->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
//      hs->session_state = HTTP_STATE_SEND_MORE_DATA;
//      return 0;
//    }
//  /* Finished with this transaction, back to HTTP_STATE_ESTABLISHED */
//
//  /* Let go of the file cache entry */
//  hss_detach_cache_entry (hs);
//  hs->session_state = HTTP_STATE_ESTABLISHED;
//  return 0;
//}

//static int
//state_sent_ok (session_t * s, http_session_t * hs,
//	       http_state_machine_called_from_t cf)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  char *suffix;
//  char *http_type;
//  u8 *http_response;
//  f64 now;
//  u32 offset;
//
//  /* What kind of dog food are we serving? */
//  suffix = (char *) (hs->path + vec_len (hs->path) - 1);
//  while ((u8 *) suffix >= hs->path && *suffix != '.')
//    suffix--;
//  suffix++;
//  http_type = "text/html";
//  if (!clib_strcmp (suffix, "css"))
//    http_type = "text/css";
//  else if (!clib_strcmp (suffix, "js"))
//    http_type = "text/javascript";
//  else if (!clib_strcmp (suffix, "json"))
//    http_type = "application/json";
//
//  if (hs->data == 0)
//    {
//      clib_warning ("BUG: hs->data not set for session %d",
//		    hs->session_index);
//      close_session (hs);
//      return 0;
//    }
//
//  /*
//   * Send an http response, which needs the current time,
//   * the expiration time, and the data length
//   */
//  now = clib_timebase_now (&hsm->timebase);
//  http_response = format (0, http_response_template,
//			  /* Date */
//			  format_clib_timebase_time, now,
//			  /* Expires */
//			  format_clib_timebase_time, now + 600.0,
//			  http_type, vec_len (hs->data));
//  offset = static_send_data (hs, http_response, vec_len (http_response), 0);
//  if (offset != vec_len (http_response))
//    {
//      clib_warning ("BUG: couldn't send response header!");
//      close_session (hs);
//      return 0;
//    }
//  vec_free (http_response);
//
//  /* Send data from the beginning... */
//  hs->data_offset = 0;
//  hs->session_state = HTTP_STATE_SEND_MORE_DATA;
//  return 1;
//}

//static void *state_funcs[HTTP_STATE_N_STATES] = {
//  state_closed,
//  /* Waiting for GET, POST, etc. */
//  state_established,
//  /* Sent OK */
//  state_sent_ok,
//  /* Send more data */
//  state_send_more_data,
//};

//static inline int
//hss_ts_rx_tx_callback (session_t * s,
//				   http_state_machine_called_from_t cf)
//{
//  http_session_t *hs;
//  int (*fp) (session_t *, http_session_t *, http_state_machine_called_from_t);
//  int rv;
//
//  /* Acquire a reader lock on the session table */
////  http_static_server_sessions_reader_lock ();
//  hs = hss_session_get (s->thread_index, s->opaque);
//
//  if (!hs)
//    {
//      clib_warning ("No http session for thread %d session_index %d",
//		    s->thread_index, s->session_index);
//      http_static_server_sessions_reader_unlock ();
//      return 0;
//    }
//
//  /* Execute state machine for this session */
//  do
//    {
//      fp = state_funcs[hs->session_state];
//      rv = (*fp) (s, hs, cf);
//      if (rv < 0)
//	goto session_closed;
//    }
//  while (rv);
//
//  /* Reset the session expiration timer */
//  http_static_server_session_timer_stop (hs);
//  http_static_server_session_timer_start (hs);
//
//session_closed:
//  http_static_server_sessions_reader_unlock ();
//  return 0;
//}

static int
hss_ts_rx_callback (session_t * ts)
{
  http_session_t *hs;
  u8 *request = 0;
  http_msg_t msg;
  int rv;
  http_status_code_t sc;

  hs = hss_session_get (ts->thread_index, ts->opaque);

  /* Read the http message header */
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REQUEST
      || (msg.method_type != HTTP_REQ_GET
	  && msg.method_type != HTTP_REQ_POST))
    {
      hs->data = 0;
      start_send_data (hs, HTTP_STATUS_METHOD_NOT_ALLOWED);
      return 0;
    }

  vec_validate (request, msg.data.len - 1);
  rv = svm_fifo_dequeue (ts->rx_fifo, msg.data.len, request);
  ASSERT (rv == msg.data.len);

  sc = find_data (hs, msg.method_type, request);
  start_send_data (hs, sc);

  vec_free (request);
  if (!hs->data)
    hss_transport_session_disconnect (hs);

  return 0;
}

static int
hss_ts_tx_callback (session_t * ts)
{
//  return hss_ts_rx_tx_callback (s, CALLED_FROM_TX);
  http_session_t *hs;
  u32 to_send;
  int rv;

  hs = hss_session_get (ts->thread_index, ts->opaque);
  if (!hs || !hs->data)
    return 0;

  to_send = vec_len (hs->data) - hs->data_offset;
  rv = svm_fifo_enqueue (ts->tx_fifo, to_send, hs->data + hs->data_offset);

  if (rv <= 0)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  if (rv < to_send)
    {
      hs->data_offset += rv;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }
  else
    {
      vec_free (hs->data);
    }

  if (svm_fifo_set_event (ts->tx_fifo))
    session_send_io_evt_to_thread (ts->tx_fifo, SESSION_IO_EVT_TX);

  return 0;
}


/** \brief Session accept callback
 */

static int
hss_ts_accept_callback (session_t * ts)
{
//  http_static_server_main_t *hsm = &http_static_server_main;
  http_session_t *hs;
  u32 thresh;

//  hsm->vpp_queue[s->thread_index] =
//    session_main_get_vpp_event_queue (s->thread_index);

//  http_static_server_sessions_writer_lock ();

  hs = hss_session_alloc (ts->thread_index);
//  http_static_server_session_lookup_add (ts->thread_index, ts->session_index,
//					 hs->session_index);
  hs->rx_fifo = ts->rx_fifo;
  hs->tx_fifo = ts->tx_fifo;
  hs->vpp_session_index = ts->session_index;
  hs->vpp_session_handle = session_handle (ts);
  hs->session_state = HTTP_STATE_ESTABLISHED;
//  http_static_server_session_timer_start (hs);

//  http_static_server_sessions_writer_unlock ();

  /* The application sets a threshold for it's fifo to get notified when
   * additional data can be enqueued. We want to keep the TX fifo reasonably
   * full, however avoid entering a state where the
   * fifo is full all the time and small chunks of data are being enqueued
   * each time. If the fifo is small (under 16K) we set
   * the threshold to it's size, meaning a notification will be given when the
   * fifo empties.
   */
  thresh = clib_min (svm_fifo_size (ts->tx_fifo), HSS_FIFO_THRESH);
  svm_fifo_set_deq_thresh (ts->tx_fifo, thresh);

  ts->opaque = hs->session_index;
  ts->session_state = SESSION_STATE_READY;
  return 0;
}

static void
hss_ts_disconnect_callback (session_t * ts)
{
  http_static_server_main_t *hsm = &hss_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (ts);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static void
hss_ts_reset_callback (session_t * ts)
{
  http_static_server_main_t *hsm = &hss_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (ts);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static int
hss_ts_connected_callback (u32 app_index, u32 api_context, session_t *ts,
                           session_error_t err)
{
  clib_warning ("called...");
  return -1;
}

static int
hss_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
hss_ts_cleanup (session_t * s, session_cleanup_ntf_t ntf)
{
  http_session_t *hs;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

//  http_static_server_sessions_writer_lock ();

  hs = hss_session_get (s->thread_index, s->opaque);
//  hs = http_static_server_session_lookup (s->thread_index, s->session_index);
  if (!hs)
    return;
//    goto done;

  hss_detach_cache_entry (hs);
//  http_static_server_session_lookup_del (hs->thread_index,
//					 hs->vpp_session_index);
  vec_free (hs->rx_buf);
  hss_session_free (hs);

//done:
//  http_static_server_sessions_writer_unlock ();
}

/** \brief Session-layer virtual function table
 */
static session_cb_vft_t hss_cb_vft = {
  .session_accept_callback = hss_ts_accept_callback,
  .session_disconnect_callback = hss_ts_disconnect_callback,
  .session_connected_callback = hss_ts_connected_callback,
  .add_segment_callback = hss_add_segment_callback,
  .builtin_app_rx_callback = hss_ts_rx_callback,
  .builtin_app_tx_callback = hss_ts_tx_callback,
  .session_reset_callback = hss_ts_reset_callback,
  .session_cleanup_callback = hss_ts_cleanup,
};

static int
http_static_server_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  http_static_server_main_t *hsm = &hss_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "test_http_static_server");
  a->session_cb_vft = &hss_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hsm->app_index = a->app_index;

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  hsm->ckpair_index = ck_pair->index;

  return 0;
}

static int
hs_transport_needs_crypto (transport_proto_t proto)
{
  return proto == TRANSPORT_PROTO_TLS || proto == TRANSPORT_PROTO_DTLS ||
	 proto == TRANSPORT_PROTO_QUIC;
}

static int
http_static_server_listen ()
{
  http_static_server_main_t *hsm = &hss_main;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_listen_args_t _a, *a = &_a;
  char *uri = "tcp://0.0.0.0/80";
  u8 need_crypto;
  int rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;

  if (hsm->uri)
    uri = (char *) hsm->uri;

  if (parse_uri (uri, &sep))
    return -1;

  need_crypto = hs_transport_needs_crypto (a->sep_ext.transport_proto);

  sep.transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));

  if (need_crypto)
    {
      session_endpoint_alloc_ext_cfg (&a->sep_ext,
				      TRANSPORT_ENDPT_EXT_CFG_CRYPTO);
      a->sep_ext.ext_cfg->crypto.ckpair_index = hsm->ckpair_index;
    }

  rv = vnet_listen (a);

  if (need_crypto)
    clib_mem_free (a->sep_ext.ext_cfg);

  return rv;
}

//static void
//http_static_server_session_close_cb (void *hs_handlep)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  http_session_t *hs;
//  uword hs_handle;
//  hs_handle = pointer_to_uword (hs_handlep);
//  hs =
//    http_static_server_session_get (hs_handle >> 24, hs_handle & 0x00FFFFFF);
//
//  if (hsm->debug_level > 1)
//    clib_warning ("terminate thread %d index %d hs %llx",
//		  hs_handle >> 24, hs_handle & 0x00FFFFFF, hs);
//  if (!hs)
//    return;
//  hs->timer_handle = ~0;
//  http_static_server_session_disconnect (hs);
//}

///** \brief Expired session timer-wheel callback
// */
//static void
//http_expired_timers_dispatch (u32 * expired_timers)
//{
//  u32 hs_handle;
//  int i;
//
//  for (i = 0; i < vec_len (expired_timers); i++)
//    {
//      /* Get session handle. The first bit is the timer id */
//      hs_handle = expired_timers[i] & 0x7FFFFFFF;
//      session_send_rpc_evt_to_thread (hs_handle >> 24,
//				      http_static_server_session_close_cb,
//				      uword_to_pointer (hs_handle, void *));
//    }
//}

///** \brief Timer-wheel expiration process
// */
//static uword
//http_static_server_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
//			    vlib_frame_t * f)
//{
//  http_static_server_main_t *hsm = &http_static_server_main;
//  f64 now, timeout = 1.0;
//  uword *event_data = 0;
//  uword __clib_unused event_type;
//
//  while (1)
//    {
//      vlib_process_wait_for_event_or_clock (vm, timeout);
//      now = vlib_time_now (vm);
//      event_type = vlib_process_get_events (vm, (uword **) & event_data);
//
//      /* expire timers */
//      clib_spinlock_lock (&http_static_server_main.tw_lock);
//      tw_timer_expire_timers_2t_1w_2048sl (&hsm->tw, now);
//      clib_spinlock_unlock (&http_static_server_main.tw_lock);
//
//      vec_reset_length (event_data);
//    }
//  return 0;
//}
//
//VLIB_REGISTER_NODE (http_static_server_process_node) =
//{
//  .function = http_static_server_process,
//  .type = VLIB_NODE_TYPE_PROCESS,
//  .name = "static-http-server-process",
//  .state = VLIB_NODE_STATE_DISABLED,
//};

static int
http_static_server_create (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  http_static_server_main_t *hsm = &hss_main;
  u32 num_threads;
//  vlib_node_t *n;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hsm->vpp_queue, num_threads - 1);
  vec_validate (hsm->sessions, num_threads - 1);
  vec_validate (hsm->session_to_http_session, num_threads - 1);

  clib_spinlock_init (&hsm->cache_lock);
//  clib_spinlock_init (&hsm->tw_lock);

  if (http_static_server_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }
  if (http_static_server_listen ())
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  /* Init path-to-cache hash table */
  BV (clib_bihash_init) (&hsm->name_to_data, "http cache", 128, 32 << 20);

  hsm->get_url_handlers = hash_create_string (0, sizeof (uword));
  hsm->post_url_handlers = hash_create_string (0, sizeof (uword));

  /* Init timer wheel and process */
//  tw_timer_wheel_init_2t_1w_2048sl (&hsm->tw, http_expired_timers_dispatch,
//				    1.0 /* timer interval */ , ~0);
//  vlib_node_set_state (vm, http_static_server_process_node.index,
//		       VLIB_NODE_STATE_POLLING);
//  n = vlib_get_node (vm, http_static_server_process_node.index);
//  vlib_start_process (vm, n->runtime_index);

  return 0;
}

/** \brief API helper function for vl_api_http_static_enable_t messages
 */
int
http_static_server_enable_api (u32 fifo_size, u32 cache_limit,
			       u32 prealloc_fifos,
			       u32 private_segment_size,
			       u8 * www_root, u8 * uri)
{
  http_static_server_main_t *hsm = &hss_main;
  int rv;

  hsm->fifo_size = fifo_size;
  hsm->cache_limit = cache_limit;
  hsm->prealloc_fifos = prealloc_fifos;
  hsm->private_segment_size = private_segment_size;
  hsm->www_root = format (0, "%s%c", www_root, 0);
  hsm->uri = format (0, "%s%c", uri, 0);

  if (vec_len (hsm->www_root) < 2)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hsm->app_index != ~0)
    return VNET_API_ERROR_APP_ALREADY_ATTACHED;

  vnet_session_enable_disable (hsm->vlib_main, 1 /* turn on TCP, etc. */ );

  rv = http_static_server_create (hsm->vlib_main);
  switch (rv)
    {
    case 0:
      break;
    default:
      vec_free (hsm->www_root);
      vec_free (hsm->uri);
      return VNET_API_ERROR_INIT_FAILED;
    }
  return 0;
}

static clib_error_t *
http_static_server_create_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  http_static_server_main_t *hsm = &hss_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u64 seg_size;
  u8 *www_root = 0;
  int rv;

  hsm->prealloc_fifos = 0;
  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;
  /* 10mb cache limit, before LRU occurs */
  hsm->cache_limit = 10 << 20;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_wwwroot;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "www-root %s", &www_root))
	;
      else
	if (unformat (line_input, "prealloc-fifos %d", &hsm->prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &seg_size))
	{
	  if (seg_size >= 0x100000000ULL)
	    {
	      vlib_cli_output (vm, "private segment size %llu, too large",
			       seg_size);
	      return 0;
	    }
	  hsm->private_segment_size = seg_size;
	}
      else if (unformat (line_input, "fifo-size %d", &hsm->fifo_size))
	hsm->fifo_size <<= 10;
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &hsm->cache_limit))
	{
	  if (hsm->cache_limit < (128 << 10))
	    {
	      return clib_error_return (0,
					"cache-size must be at least 128kb");
	    }
	}

      else if (unformat (line_input, "uri %s", &hsm->uri))
	;
      else if (unformat (line_input, "debug %d", &hsm->debug_level))
	;
      else if (unformat (line_input, "debug"))
	hsm->debug_level = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (www_root == 0)
    {
    no_wwwroot:
      return clib_error_return (0, "Must specify www-root <path>");
    }

  if (hsm->app_index != (u32) ~ 0)
    {
      vec_free (www_root);
      return clib_error_return (0, "http server already running...");
    }

  hsm->www_root = www_root;

  vnet_session_enable_disable (vm, 1 /* turn on TCP, etc. */ );

  rv = http_static_server_create (vm);
  switch (rv)
    {
    case 0:
      break;
    default:
      vec_free (hsm->www_root);
      return clib_error_return (0, "server_create returned %d", rv);
    }
  return 0;
}

/*?
 * Enable the static http server
 *
 * @cliexpar
 * This command enables the static http server. Only the www-root
 * parameter is required
 * @clistart
 * http static server www-root /tmp/www uri tcp://0.0.0.0/80 cache-size 2m
 * @cliend
 * @cliexcmd{http static server www-root <path> [prealloc-fios <nn>]
 *   [private-segment-size <nnMG>] [fifo-size <nbytes>] [uri <uri>]}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (http_static_server_create_command, static) =
{
  .path = "http static server",
  .short_help = "http static server www-root <path> [prealloc-fifos <nn>]\n"
  "[private-segment-size <nnMG>] [fifo-size <nbytes>] [uri <uri>]\n"
  "[debug [nn]]\n",
  .function = http_static_server_create_command_fn,
};
/* *INDENT-ON* */

/** \brief format a file cache entry
 */
u8 *
format_hsm_cache_entry (u8 * s, va_list * args)
{
  file_data_cache_t *ep = va_arg (*args, file_data_cache_t *);
  f64 now = va_arg (*args, f64);

  /* Header */
  if (ep == 0)
    {
      s = format (s, "%40s%12s%20s", "File", "Size", "Age");
      return s;
    }
  s = format (s, "%40s%12lld%20.2f", ep->filename, vec_len (ep->data),
	      now - ep->last_used);
  return s;
}

u8 *
format_http_session_state (u8 * s, va_list * args)
{
  http_session_state_t state = va_arg (*args, http_session_state_t);
  char *state_string = "bogus!";

  switch (state)
    {
    case HTTP_STATE_CLOSED:
      state_string = "closed";
      break;
    case HTTP_STATE_ESTABLISHED:
      state_string = "established";
      break;
    case HTTP_STATE_OK_SENT:
      state_string = "ok sent";
      break;
    case HTTP_STATE_SEND_MORE_DATA:
      state_string = "send more data";
      break;
    default:
      break;
    }

  return format (s, "%s", state_string);
}

u8 *
format_http_session (u8 * s, va_list * args)
{
  http_session_t *hs = va_arg (*args, http_session_t *);
  int verbose = va_arg (*args, int);

  s = format (s, "[%d]: state %U", hs->session_index,
	      format_http_session_state, hs->session_state);
  if (verbose > 0)
    {
      s = format (s, "\n path %s, data length %u, data_offset %u",
		  hs->path ? hs->path : (u8 *) "[none]",
		  vec_len (hs->data), hs->data_offset);
    }
  return s;
}

static clib_error_t *
http_show_static_server_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  http_static_server_main_t *hsm = &hss_main;
  file_data_cache_t *ep, **entries = 0;
  int verbose = 0;
  int show_cache = 0;
  int show_sessions = 0;
  u32 index;
  f64 now;

  if (hsm->www_root == 0)
    return clib_error_return (0, "Static server disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "cache"))
	show_cache = 1;
      else if (unformat (input, "sessions"))
	show_sessions = 1;
      else
	break;
    }

  if ((show_cache + show_sessions) == 0)
    return clib_error_return (0, "specify one or more of cache, sessions");

  if (show_cache)
    {
      if (verbose == 0)
	{
	  vlib_cli_output
	    (vm, "www_root %s, cache size %lld bytes, limit %lld bytes, "
	     "evictions %lld",
	     hsm->www_root, hsm->cache_size, hsm->cache_limit,
	     hsm->cache_evictions);
	  return 0;
	}

      now = vlib_time_now (vm);

      vlib_cli_output (vm, "%U", format_hsm_cache_entry, 0 /* header */ ,
		       now);

      for (index = hsm->first_index; index != ~0;)
	{
	  ep = pool_elt_at_index (hsm->cache_pool, index);
	  index = ep->next_index;
	  vlib_cli_output (vm, "%U", format_hsm_cache_entry, ep, now);
	}

      vlib_cli_output (vm, "%40s%12lld", "Total Size", hsm->cache_size);

      vec_free (entries);
    }

  if (show_sessions)
    {
      u32 *session_indices = 0;
      http_session_t *hs;
      int i, j;

      hss_cache_lock ();

      for (i = 0; i < vec_len (hsm->sessions); i++)
	{
          /* *INDENT-OFF* */
	  pool_foreach (hs, hsm->sessions[i])
           {
            vec_add1 (session_indices, hs - hsm->sessions[i]);
          }
          /* *INDENT-ON* */

	  for (j = 0; j < vec_len (session_indices); j++)
	    {
	      vlib_cli_output (vm, "%U", format_http_session,
			       pool_elt_at_index
			       (hsm->sessions[i], session_indices[j]),
			       verbose);
	    }
	  vec_reset_length (session_indices);
	}
      hss_cache_unlock ();
      vec_free (session_indices);
    }
  return 0;
}

/*?
 * Display static http server cache statistics
 *
 * @cliexpar
 * This command shows the contents of the static http server cache
 * @clistart
 * show http static server
 * @cliend
 * @cliexcmd{show http static server sessions cache [verbose [nn]]}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (http_show_static_server_command, static) =
{
  .path = "show http static server",
  .short_help = "show http static server sessions cache [verbose [<nn>]]",
  .function = http_show_static_server_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
http_clear_static_cache_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  http_static_server_main_t *hsm = &hss_main;
  file_data_cache_t *dp;
  u32 free_index;
  u32 busy_items = 0;
  BVT (clib_bihash_kv) kv;

  if (hsm->www_root == 0)
    return clib_error_return (0, "Static server disabled");

  hss_cache_lock ();

  /* Walk the LRU list to find active entries */
  free_index = hsm->last_index;
  while (free_index != ~0)
    {
      dp = pool_elt_at_index (hsm->cache_pool, free_index);
      free_index = dp->prev_index;
      /* Which could be in use... */
      if (dp->inuse)
	{
	  busy_items++;
	  free_index = dp->next_index;
	  continue;
	}
      kv.key = (u64) (dp->filename);
      kv.value = ~0ULL;
      if (BV (clib_bihash_add_del) (&hsm->name_to_data, &kv,
				    0 /* is_add */ ) < 0)
	{
	  clib_warning ("BUG: cache clear delete '%s' FAILED!", dp->filename);
	}

      lru_remove (hsm, dp);
      hsm->cache_size -= vec_len (dp->data);
      hsm->cache_evictions++;
      vec_free (dp->filename);
      vec_free (dp->data);
      if (hsm->debug_level > 1)
	clib_warning ("pool put index %d", dp - hsm->cache_pool);
      pool_put (hsm->cache_pool, dp);
      free_index = hsm->last_index;
    }
  hss_cache_unlock ();
  if (busy_items > 0)
    vlib_cli_output (vm, "Note: %d busy items still in cache...", busy_items);
  else
    vlib_cli_output (vm, "Cache cleared...");
  return 0;
}

/*?
 * Clear the static http server cache, to force the server to
 * reload content from backing files
 *
 * @cliexpar
 * This command clear the static http server cache
 * @clistart
 * clear http static cache
 * @cliend
 * @cliexcmd{clear http static cache}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_http_static_cache_command, static) =
{
  .path = "clear http static cache",
  .short_help = "clear http static cache",
  .function = http_clear_static_cache_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
http_static_server_main_init (vlib_main_t * vm)
{
  http_static_server_main_t *hsm = &hss_main;

//  hsm->my_client_index = ~0;
  hsm->app_index = ~0;
  hsm->vlib_main = vm;
  hsm->first_index = hsm->last_index = ~0;

//  clib_timebase_init (&hsm->timebase, 0 /* GMT */ ,
//		      CLIB_TIMEBASE_DAYLIGHT_NONE,
//		      &vm->clib_time /* share the system clock */ );

  return 0;
}

VLIB_INIT_FUNCTION (http_static_server_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
