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
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vppinfra/unix.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <http_static/http_static.h>
#include <vppinfra/bihash_vec8_8.h>

#include <vppinfra/bihash_template.c>

/** @file
    Simple Static http server, sufficient to
    serve .html / .css / .js content.
*/
/*? %%clicmd:group_label Static HTTP Server %% ?*/

/** \brief Session States
 */

typedef enum
{
  /** Session is closed */
  HTTP_STATE_CLOSED,
  /** Session is established */
  HTTP_STATE_ESTABLISHED,
  /** Session has sent an OK response */
  HTTP_STATE_OK_SENT,
  /** Session has sent an HTML response */
  HTTP_STATE_RESPONSE_SENT,
} http_session_state_t;

/** \brief Application session
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /** Base class instance variables */
#define _(type, name) type name;
  foreach_app_session_field
#undef _
  /** rx thread index */
  u32 thread_index;
  /** rx buffer */
  u8 *rx_buf;
  /** vpp session index, handle */
  u32 vpp_session_index;
  u64 vpp_session_handle;
  /** Timeout timer handle */
  u32 timer_handle;
  /** Fully-resolved file path */
  u8 *path;
  /** File data, a vector */
  u8 *data;
  /** Current data send offset */
  u32 data_offset;
  /** File cache pool index */
  u32 cache_pool_index;
} http_session_t;

/** \brief In-memory file data cache entry
 */
typedef struct
{
  /** Name of the file */
  u8 *filename;
  /** Contents of the file, as a u8 * vector */
  u8 *data;
  /** Last time the cache entry was used */
  f64 last_used;
  /** Cache LRU links */
  u32 next_index;
  u32 prev_index;
  /** Reference count, so we don't recycle while referenced */
  int inuse;
} file_data_cache_t;

/** \brief Main data structure
 */

typedef struct
{
  /** Per thread vector of session pools */
  http_session_t **sessions;
  /** Session pool reader writer lock */
  clib_rwlock_t sessions_lock;
  /** vpp session to http session index map */
  u32 **session_to_http_session;

  /** vpp message/event queue */
  svm_msg_q_t **vpp_queue;

  /** Unified file data cache pool */
  file_data_cache_t *cache_pool;
  /** Hash table which maps file name to file data */
    BVT (clib_bihash) name_to_data;

  /** Current cache size */
  u64 cache_size;
  /** Max cache size in bytes */
  u64 cache_limit;
  /** Number of cache evictions */
  u64 cache_evictions;

  /** Cache LRU listheads */
  u32 first_index;
  u32 last_index;

  /** root path to be served */
  u8 *www_root;

  /** Server's event queue */
  svm_queue_t *vl_input_queue;

  /** API client handle */
  u32 my_client_index;

  /** Application index */
  u32 app_index;

  /** Process node index for event scheduling */
  u32 node_index;

  /** Session cleanup timer wheel */
  tw_timer_wheel_2t_1w_2048sl_t tw;
  clib_spinlock_t tw_lock;

  /** Time base, so we can generate browser cache control http spew */
  clib_timebase_t timebase;

  /** Number of preallocated fifos, usually 0 */
  u32 prealloc_fifos;
  /** Private segment size, usually 0 */
  u32 private_segment_size;
  /** Size of the allocated rx, tx fifos, roughly 8K or so */
  u32 fifo_size;
  /** The bind URI, defaults to tcp://0.0.0.0/80 */
  u8 *uri;
  vlib_main_t *vlib_main;
} http_static_server_main_t;

http_static_server_main_t http_static_server_main;

/** \brief Acquire reader lock on the sessions pools
 */
static void
http_static_server_sessions_reader_lock (void)
{
  clib_rwlock_reader_lock (&http_static_server_main.sessions_lock);
}

/** \brief Drop reader lock on the sessions pools
 */
static void
http_static_server_sessions_reader_unlock (void)
{
  clib_rwlock_reader_unlock (&http_static_server_main.sessions_lock);
}

/** \brief Acquire writer lock on the sessions pools
 */
static void
http_static_server_sessions_writer_lock (void)
{
  clib_rwlock_writer_lock (&http_static_server_main.sessions_lock);
}

/** \brief Drop writer lock on the sessions pools
 */
static void
http_static_server_sessions_writer_unlock (void)
{
  clib_rwlock_writer_unlock (&http_static_server_main.sessions_lock);
}

/** \brief Allocate an http session
 */
static http_session_t *
http_static_server_session_alloc (u32 thread_index)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  http_session_t *hs;
  pool_get (hsm->sessions[thread_index], hs);
  memset (hs, 0, sizeof (*hs));
  hs->session_index = hs - hsm->sessions[thread_index];
  hs->thread_index = thread_index;
  hs->timer_handle = ~0;
  hs->cache_pool_index = ~0;
  return hs;
}

/** \brief Get an http session by index
 */
static http_session_t *
http_static_server_session_get (u32 thread_index, u32 hs_index)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  if (pool_is_free_index (hsm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hsm->sessions[thread_index], hs_index);
}

/** \brief Free an http session
 */
static void
http_static_server_session_free (http_session_t * hs)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  pool_put (hsm->sessions[hs->thread_index], hs);
  if (CLIB_DEBUG)
    memset (hs, 0xfa, sizeof (*hs));
}

/** \brief add a session to the vpp < -- > http session index map
 */
static void
http_static_server_session_lookup_add (u32 thread_index, u32 s_index,
				       u32 hs_index)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  vec_validate (hsm->session_to_http_session[thread_index], s_index);
  hsm->session_to_http_session[thread_index][s_index] = hs_index;
}

/** \brief Remove a session from the vpp < -- > http session index map
 */
static void
http_static_server_session_lookup_del (u32 thread_index, u32 s_index)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  hsm->session_to_http_session[thread_index][s_index] = ~0;
}

/** \brief lookup a session in the vpp < -- > http session index map
 */

static http_session_t *
http_static_server_session_lookup (u32 thread_index, u32 s_index)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  u32 hs_index;

  if (s_index < vec_len (hsm->session_to_http_session[thread_index]))
    {
      hs_index = hsm->session_to_http_session[thread_index][s_index];
      return http_static_server_session_get (thread_index, hs_index);
    }
  return 0;
}

/** \brief Start a session cleanup timer
 */

static void
http_static_server_session_timer_start (http_session_t * hs)
{
  u32 hs_handle;
  hs_handle = hs->thread_index << 24 | hs->session_index;
  clib_spinlock_lock (&http_static_server_main.tw_lock);
  hs->timer_handle = tw_timer_start_2t_1w_2048sl (&http_static_server_main.tw,
						  hs_handle, 0, 60);
  clib_spinlock_unlock (&http_static_server_main.tw_lock);
}

/** \brief stop a session cleanup timer
 */
static void
http_static_server_session_timer_stop (http_session_t * hs)
{
  if (hs->timer_handle == ~0)
    return;
  clib_spinlock_lock (&http_static_server_main.tw_lock);
  tw_timer_stop_2t_1w_2048sl (&http_static_server_main.tw, hs->timer_handle);
  clib_spinlock_unlock (&http_static_server_main.tw_lock);
}

/** \brief Clean up an http session
 */

static void
http_static_server_session_cleanup (http_session_t * hs)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  file_data_cache_t *ep;

  if (!hs)
    return;

  /*
   * Decrement cache pool entry reference count
   * Note that if e.g. a file lookup fails, the cache pool index
   * won't be set
   */
  if (hs->cache_pool_index != ~0)
    {
      ep = pool_elt_at_index (hsm->cache_pool, hs->cache_pool_index);
      ep->inuse--;
      if (0)
	clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
		      ep->inuse);
    }

  http_static_server_session_lookup_del (hs->thread_index,
					 hs->vpp_session_index);
  vec_free (hs->rx_buf);
  vec_free (hs->path);
  http_static_server_session_timer_stop (hs);
  http_static_server_session_free (hs);
}

/** \brief Disconnect a session
 */

static void
http_static_server_session_disconnect (http_session_t * hs)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = hs->vpp_session_handle;
  a->app_index = http_static_server_main.app_index;
  vnet_disconnect_session (a);
}

/* *INDENT-OFF* */
/** \brief http error boilerplate
 */
static const char *http_error_template =
    "HTTP/1.1 %s\r\n"
    "Date: %U GMT\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "Pragma: no-cache\r\n"
    "Content-Length: 0\r\n\r\n";

/** \brief http response boilerplate
 */
static const char *http_response_template =
    "Date: %U GMT\r\n"
    "Expires: %U GMT\r\n"
    "Server: VPP Static\r\n"
    "Content-Type: text/%s\r\n"
    "Connection: close \r\n"
    "Content-Length: %d\r\n\r\n";

/* *INDENT-ON* */

/** \brief send http data
    @param hs - http session
    @param data - the data vector to transmit
    @param offset - transmit offset for this operation
    @return offset for next transmit operation, may be unchanged w/ full fifo
*/

static u32
static_send_data (http_session_t * hs, u8 * data, u32 length, u32 offset)
{
  u32 bytes_to_send;

  bytes_to_send = length - offset;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer = svm_fifo_enqueue_nowait
	(hs->tx_fifo, bytes_to_send, data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
	return offset;
      else
	{
	  offset += actual_transfer;
	  bytes_to_send -= actual_transfer;

	  if (svm_fifo_set_event (hs->tx_fifo))
	    session_send_io_evt_to_thread (hs->tx_fifo,
					   SESSION_IO_EVT_TX_FLUSH);
	  return offset;
	}
    }
  /* NOTREACHED */
  return ~0;
}

/** \brief Send an http error string
    @param hs - the http session
    @param str - the error string, e.g. "404 Not Found"
*/
static void
send_error (http_session_t * hs, char *str)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  u8 *data;
  f64 now;

  now = clib_timebase_now (&hsm->timebase);
  data = format (0, http_error_template, str, format_clib_timebase_time, now);
  static_send_data (hs, data, vec_len (data), 0);
  vec_free (data);
}

/** \brief Retrieve data from the application layer
 */
static int
session_rx_request (http_session_t * hs)
{
  u32 max_dequeue, cursize;
  int n_read;

  cursize = vec_len (hs->rx_buf);
  max_dequeue = svm_fifo_max_dequeue (hs->rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return -1;

  vec_validate (hs->rx_buf, cursize + max_dequeue - 1);
  n_read = app_recv_stream_raw (hs->rx_fifo, hs->rx_buf + cursize,
				max_dequeue, 0, 0 /* peek */ );
  ASSERT (n_read == max_dequeue);
  if (svm_fifo_is_empty (hs->rx_fifo))
    svm_fifo_unset_event (hs->rx_fifo);

  _vec_len (hs->rx_buf) = cursize + n_read;
  return 0;
}

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

/** \brief Session-layer (main) data rx callback.
    Parse the http request, and reply to it.
    Future extensions might include POST processing, active content, etc.
*/

static int
http_static_server_rx_callback (session_t * s)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  u32 request_len;
  u8 *request = 0;
  u8 *path;
  http_session_t *hs;
  int i, rv;
  struct stat _sb, *sb = &_sb;
  u8 *http_response;
  f64 now;
  clib_error_t *error;
  char *suffix;
  char *http_type;

  /* Acquire a reader lock on the session table */
  http_static_server_sessions_reader_lock ();
  hs = http_static_server_session_lookup (s->thread_index, s->session_index);

  /* No such session? Say goodnight, Gracie... */
  if (!hs || hs->session_state == HTTP_STATE_CLOSED)
    {
      http_static_server_sessions_reader_unlock ();
      return 0;
    }

  /* If this session has already sent "OK 200" */
  if (hs->session_state == HTTP_STATE_OK_SENT)
    goto static_send_response;

  /* If this session has already sent a response (needs to send more data)  */
  if (hs->session_state == HTTP_STATE_RESPONSE_SENT)
    goto static_send_data;

  /* Read data from the sesison layer */
  rv = session_rx_request (hs);
  if (rv)
    goto wait_for_data;

  /* Process the client request */
  request = hs->rx_buf;
  request_len = vec_len (request);
  if (vec_len (request) < 7)
    {
      send_error (hs, "400 Bad Request");
      goto close_session;
    }

  /* We only handle GET requests at the moment */
  for (i = 0; i < request_len - 4; i++)
    {
      if (request[i] == 'G' &&
	  request[i + 1] == 'E' &&
	  request[i + 2] == 'T' && request[i + 3] == ' ')
	goto find_end;
    }
  send_error (hs, "400 Bad Request");
  goto close_session;

find_end:

  /* Lose "GET " */
  vec_delete (request, i + 5, 0);

  /* Lose stuff to the right of the path */
  for (i = 0; i < vec_len (request); i++)
    {
      if (request[i] == ' ' || request[i] == '?')
	{
	  request[i] = 0;
	  break;
	}
    }

  /*
   * Now we can construct the file to open
   * Browsers are capable of sporadically including a leading '/'
   */
  if (request[0] == '/')
    path = format (0, "%s%s%c", hsm->www_root, request, 0);
  else
    path = format (0, "%s/%s%c", hsm->www_root, request, 0);

  if (0)
    clib_warning ("GET '%s'", path);

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
	      vec_free (path);
	      send_error (hs, "404 Not Found");
	      goto close_session;
	    }
	  else
	    {
	      transport_connection_t *tc;
	      /*
	       * To make this bit work correctly, we need to know our local
	       * IP address, etc. and send it in the redirect...
	       */
	      u8 *redirect;

	      vec_delete (path, vec_len (hsm->www_root) - 1, 0);


	      tc = session_get_transport (s);
	      redirect = format (0, "HTTP/1.1 301 Moved Permanently\r\n"
				 "Location: http://%U%s\r\n"
				 "Connection: close\r\n",
				 format_ip46_address, &tc->lcl_ip, tc->is_ip4,
				 path);
	      if (0)
		clib_warning ("redirect: %s", redirect);

	      static_send_data (hs, redirect, vec_len (redirect), 0);
	      hs->session_state = HTTP_STATE_RESPONSE_SENT;
	      hs->path = 0;
	      vec_free (redirect);
	      vec_free (path);
	      goto close_session;
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
	  if (0)
	    clib_warning ("lookup '%s' returned %lld", kv.key, kv.value);

	  /* found the data.. */
	  dp = pool_elt_at_index (hsm->cache_pool, kv.value);
	  hs->data = dp->data;
	  /* Update the cache entry, mark it in-use */
	  lru_update (hsm, dp, vlib_time_now (hsm->vlib_main));
	  hs->cache_pool_index = dp - hsm->cache_pool;
	  dp->inuse++;
	  if (0)
	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
			  dp->inuse);
	}
      else
	{
	  if (0)
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
		      if (0)
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
		  else if (0)
		    clib_warning ("LRU delete '%s' ok", dp->filename);

		  lru_remove (hsm, dp);
		  hsm->cache_size -= vec_len (dp->data);
		  hsm->cache_evictions++;
		  vec_free (dp->filename);
		  vec_free (dp->data);
		  if (0)
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
	      vec_free (hs->path);
	      goto close_session;
	    }
	  /* Create a cache entry for it */
	  pool_get (hsm->cache_pool, dp);
	  memset (dp, 0, sizeof (*dp));
	  dp->filename = vec_dup (hs->path);
	  dp->data = hs->data;
	  hs->cache_pool_index = dp - hsm->cache_pool;
	  dp->inuse++;
	  if (0)
	    clib_warning ("index %d refcnt now %d", hs->cache_pool_index,
			  dp->inuse);
	  lru_add (hsm, dp, vlib_time_now (hsm->vlib_main));
	  kv.key = (u64) vec_dup (hs->path);
	  kv.value = dp - hsm->cache_pool;
	  /* Add to the lookup table */
	  if (0)
	    clib_warning ("add '%s' value %lld", kv.key, kv.value);

	  if (BV (clib_bihash_add_del) (&hsm->name_to_data, &kv,
					1 /* is_add */ ) < 0)
	    {
	      clib_warning ("BUG: add failed!");
	    }
	  hsm->cache_size += vec_len (dp->data);
	}
      hs->data_offset = 0;
    }

  /* send 200 OK first */
  static_send_data (hs, (u8 *) "HTTP/1.1 200 OK\r\n", 17, 0);
  hs->session_state = HTTP_STATE_OK_SENT;
  goto postpone;

static_send_response:

  /* What kind of dog food are we serving? */
  suffix = (char *) (hs->path + vec_len (hs->path) - 1);
  while (*suffix != '.')
    suffix--;
  suffix++;
  http_type = "html";
  if (!clib_strcmp (suffix, "css"))
    http_type = "css";
  else if (!clib_strcmp (suffix, "js"))
    http_type = "javascript";

  /*
   * Send an http response, which needs the current time,
   * the expiration time, and the data length
   */
  now = clib_timebase_now (&hsm->timebase);
  http_response = format (0, http_response_template,
			  /* Date */
			  format_clib_timebase_time, now,
			  /* Expires */
			  format_clib_timebase_time, now + 600.0,
			  http_type, vec_len (hs->data));
  static_send_data (hs, http_response, vec_len (http_response), 0);
  vec_free (http_response);
  hs->session_state = HTTP_STATE_RESPONSE_SENT;
  /* NOTE FALLTHROUGH */

static_send_data:

  /*
   * Try to send data. Ideally, the fifos will be large
   * enough to send the entire file in one motion.
   */

  hs->data_offset = static_send_data (hs, hs->data, vec_len (hs->data),
				      hs->data_offset);
  if (hs->data_offset < vec_len (hs->data))
    goto postpone;

close_session:
  http_static_server_session_disconnect (hs);
  http_static_server_session_cleanup (hs);
  http_static_server_sessions_reader_unlock ();
  return 0;

postpone:
  (void) svm_fifo_set_event (hs->rx_fifo);
  session_send_io_evt_to_thread (hs->rx_fifo, SESSION_IO_EVT_BUILTIN_RX);
  http_static_server_sessions_reader_unlock ();
  return 0;

wait_for_data:
  http_static_server_sessions_reader_unlock ();
  return 0;
}

/** \brief Session accept callback
 */

static int
http_static_server_session_accept_callback (session_t * s)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  http_session_t *hs;

  hsm->vpp_queue[s->thread_index] =
    session_main_get_vpp_event_queue (s->thread_index);

  http_static_server_sessions_writer_lock ();

  hs = http_static_server_session_alloc (s->thread_index);
  http_static_server_session_lookup_add (s->thread_index, s->session_index,
					 hs->session_index);
  hs->rx_fifo = s->rx_fifo;
  hs->tx_fifo = s->tx_fifo;
  hs->vpp_session_index = s->session_index;
  hs->vpp_session_handle = session_handle (s);
  hs->session_state = HTTP_STATE_ESTABLISHED;
  http_static_server_session_timer_start (hs);

  http_static_server_sessions_writer_unlock ();

  s->session_state = SESSION_STATE_READY;
  return 0;
}

/** \brief Session disconnect callback
 */

static void
http_static_server_session_disconnect_callback (session_t * s)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  http_session_t *hs;

  http_static_server_sessions_writer_lock ();

  hs = http_static_server_session_lookup (s->thread_index, s->session_index);
  http_static_server_session_cleanup (hs);

  http_static_server_sessions_writer_unlock ();

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

/** \brief Session reset callback
 */

static void
http_static_server_session_reset_callback (session_t * s)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  http_session_t *hs;

  http_static_server_sessions_writer_lock ();

  hs = http_static_server_session_lookup (s->thread_index, s->session_index);
  http_static_server_session_cleanup (hs);

  http_static_server_sessions_writer_unlock ();

  a->handle = session_handle (s);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static int
http_static_server_session_connected_callback (u32 app_index, u32 api_context,
					       session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}

static int
http_static_server_add_segment_callback (u32 client_index, u64 segment_handle)
{
  clib_warning ("called...");
  return -1;
}

/** \brief Session-layer virtual function table
 */
static session_cb_vft_t http_static_server_session_cb_vft = {
  .session_accept_callback = http_static_server_session_accept_callback,
  .session_disconnect_callback =
    http_static_server_session_disconnect_callback,
  .session_connected_callback = http_static_server_session_connected_callback,
  .add_segment_callback = http_static_server_add_segment_callback,
  .builtin_app_rx_callback = http_static_server_rx_callback,
  .session_reset_callback = http_static_server_session_reset_callback
};

static int
http_static_server_attach ()
{
  vnet_app_add_tls_cert_args_t _a_cert, *a_cert = &_a_cert;
  vnet_app_add_tls_key_args_t _a_key, *a_key = &_a_key;
  http_static_server_main_t *hsm = &http_static_server_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u32 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "test_http_static_server");
  a->session_cb_vft = &http_static_server_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 8 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] =
    hsm->fifo_size ? hsm->fifo_size : 32 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hsm->prealloc_fifos;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("failed to attach server");
      return -1;
    }
  vec_free (a->name);
  hsm->app_index = a->app_index;

  clib_memset (a_cert, 0, sizeof (*a_cert));
  a_cert->app_index = a->app_index;
  vec_validate (a_cert->cert, test_srv_crt_rsa_len);
  clib_memcpy_fast (a_cert->cert, test_srv_crt_rsa, test_srv_crt_rsa_len);
  vnet_app_add_tls_cert (a_cert);

  clib_memset (a_key, 0, sizeof (*a_key));
  a_key->app_index = a->app_index;
  vec_validate (a_key->key, test_srv_key_rsa_len);
  clib_memcpy_fast (a_key->key, test_srv_key_rsa, test_srv_key_rsa_len);
  vnet_app_add_tls_key (a_key);

  return 0;
}

static int
http_static_server_listen ()
{
  http_static_server_main_t *hsm = &http_static_server_main;
  vnet_listen_args_t _a, *a = &_a;
  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;
  a->uri = "tcp://0.0.0.0/80";
  if (hsm->uri)
    a->uri = (char *) hsm->uri;
  return vnet_bind_uri (a);
}

static void
http_static_server_session_cleanup_cb (void *hs_handlep)
{
  http_session_t *hs;
  uword hs_handle;
  hs_handle = pointer_to_uword (hs_handlep);
  hs =
    http_static_server_session_get (hs_handle >> 24, hs_handle & 0x00FFFFFF);
  if (!hs)
    return;
  hs->timer_handle = ~0;
  http_static_server_session_disconnect (hs);
  http_static_server_session_cleanup (hs);
}

/** \brief Expired session timer-wheel callback
 */
static void
http_expired_timers_dispatch (u32 * expired_timers)
{
  u32 hs_handle;
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      hs_handle = expired_timers[i] & 0x7FFFFFFF;
      session_send_rpc_evt_to_thread (hs_handle >> 24,
				      http_static_server_session_cleanup_cb,
				      uword_to_pointer (hs_handle, void *));
    }
}

/** \brief Timer-wheel expiration process
 */
static uword
http_static_server_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			    vlib_frame_t * f)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      /* expire timers */
      clib_spinlock_lock (&http_static_server_main.tw_lock);
      tw_timer_expire_timers_2t_1w_2048sl (&hsm->tw, now);
      clib_spinlock_unlock (&http_static_server_main.tw_lock);

      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (http_static_server_process_node) =
{
  .function = http_static_server_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "static-http-server-process",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static int
http_static_server_create (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  http_static_server_main_t *hsm = &http_static_server_main;
  u32 num_threads;
  vlib_node_t *n;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hsm->vpp_queue, num_threads - 1);
  vec_validate (hsm->sessions, num_threads - 1);
  vec_validate (hsm->session_to_http_session, num_threads - 1);

  clib_rwlock_init (&hsm->sessions_lock);
  clib_spinlock_init (&hsm->tw_lock);

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

  /* Init timer wheel and process */
  tw_timer_wheel_init_2t_1w_2048sl (&hsm->tw, http_expired_timers_dispatch,
				    1 /* timer interval */ , ~0);
  vlib_node_set_state (vm, http_static_server_process_node.index,
		       VLIB_NODE_STATE_POLLING);
  n = vlib_get_node (vm, http_static_server_process_node.index);
  vlib_start_process (vm, n->runtime_index);

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
  http_static_server_main_t *hsm = &http_static_server_main;
  int rv;

  hsm->fifo_size = fifo_size;
  hsm->cache_limit = cache_limit;
  hsm->prealloc_fifos = prealloc_fifos;
  hsm->private_segment_size = private_segment_size;
  hsm->www_root = format (0, "%s%c", www_root, 0);
  hsm->uri = format (0, "%s%c", uri, 0);

  if (vec_len (hsm->www_root) < 2)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hsm->my_client_index != ~0)
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
  http_static_server_main_t *hsm = &http_static_server_main;
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

  if (hsm->my_client_index != (u32) ~ 0)
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
  .short_help = "http static server www-root <path> [prealloc-fios <nn>]\n"
  "[private-segment-size <nnMG>] [fifo-size <nbytes>] [uri <uri>]\n",
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

static clib_error_t *
http_show_static_server_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  http_static_server_main_t *hsm = &http_static_server_main;
  file_data_cache_t *ep, **entries = 0;
  int verbose = 0;
  u32 index;
  f64 now;

  if (hsm->www_root == 0)
    return clib_error_return (0, "Static server disabled");

  if (unformat (input, "verbose %d", &verbose))
    ;
  else if (unformat (input, "verbose"))
    verbose = 1;

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
 * @cliexcmd{show http static server [verbose]}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (http_show_static_server_command, static) =
{
  .path = "show http static server",
  .short_help = "show http static server [verbose]",
  .function = http_show_static_server_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
http_static_server_main_init (vlib_main_t * vm)
{
  http_static_server_main_t *hsm = &http_static_server_main;

  hsm->my_client_index = ~0;
  hsm->vlib_main = vm;
  hsm->first_index = hsm->last_index = ~0;

  clib_timebase_init (&hsm->timebase, 0 /* GMT */ ,
		      CLIB_TIMEBASE_DAYLIGHT_NONE);

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
