/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2022 Cisco and/or its affiliates.
 */

#include <http_static/http_static.h>
#include <vnet/session/application.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <http/http_content_types.h>
#include <http/http_status_codes.h>

/** @file static_server.c
 *  Static http server, sufficient to serve .html / .css / .js content.
 */
/*? %%clicmd:group_label Static HTTP Server %% ?*/

#define HSS_FIFO_THRESH (16 << 10)
#define HSS_HEADER_BUF_MAX_SIZE 16192
hss_main_t hss_main;

static int file_handler_discard_body (hss_session_t *hs, session_t *ts);
static int url_handler_read_body (hss_session_t *hs, session_t *ts);

static int
hss_add_header (hss_session_t *hs, http_header_name_t name, const char *value,
		uword value_len)
{
  u32 needed_size = 0;
  while (http_add_header (&hs->resp_headers, name, value, value_len) == -1)
    {
      if (needed_size)
	{
	  http_truncate_headers_list (&hs->resp_headers);
	  hs->data_len = 0;
	  return -1;
	}
      else
	needed_size = hs->resp_headers.tail_offset +
		      sizeof (http_app_header_t) + value_len;
      if (needed_size < HSS_HEADER_BUF_MAX_SIZE)
	{
	  vec_resize (hs->headers_buf, sizeof (http_app_header_t) + value_len);
	  hs->resp_headers.len = needed_size;
	  hs->resp_headers.buf = hs->headers_buf;
	}
      else
	{
	  http_truncate_headers_list (&hs->resp_headers);
	  hs->data_len = 0;
	  return -1;
	}
    }
  return 0;
}

static_always_inline void
hss_confirm_data_read (hss_session_t *hs, u32 n_last_deq)
{
  session_t *ts;

  ts = session_get (hs->vpp_session_index, hs->thread_index);
  if (svm_fifo_needs_deq_ntf (ts->rx_fifo, n_last_deq))
    {
      svm_fifo_clear_deq_ntf (ts->rx_fifo);
      session_program_transport_io_evt (ts->handle, SESSION_IO_EVT_RX);
    }
}

static hss_session_t *
hss_session_alloc (clib_thread_index_t thread_index)
{
  hss_main_t *hsm = &hss_main;
  hss_session_t *hs;

  pool_get_zero (hsm->sessions[thread_index], hs);
  hs->session_index = hs - hsm->sessions[thread_index];
  hs->thread_index = thread_index;
  hs->cache_pool_index = ~0;
  /* 1kB for headers should be enough for now */
  vec_validate (hs->headers_buf, 1023);
  return hs;
}

__clib_export hss_session_t *
hss_session_get (clib_thread_index_t thread_index, u32 hs_index)
{
  hss_main_t *hsm = &hss_main;
  if (pool_is_free_index (hsm->sessions[thread_index], hs_index))
    return 0;
  return pool_elt_at_index (hsm->sessions[thread_index], hs_index);
}

static void
hss_session_free (hss_session_t *hs)
{
  hss_main_t *hsm = &hss_main;

  if (CLIB_DEBUG)
    {
      u32 save_thread_index;
      save_thread_index = hs->thread_index;
      /* Poison the entry, preserve timer state and thread index */
      memset (hs, 0xfa, sizeof (*hs));
      hs->thread_index = save_thread_index;
    }

  pool_put (hsm->sessions[hs->thread_index], hs);
}

/** \brief Disconnect a session
 */
static void
hss_session_disconnect_transport (hss_session_t *hs)
{
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  a->handle = hs->vpp_session_handle;
  a->app_index = hss_main.app_index;
  vnet_disconnect_session (a);
}

static void
start_send_data (hss_session_t *hs, http_status_code_t status)
{
  hss_main_t *hsm = &hss_main;
  http_msg_t msg;
  session_t *ts;
  u32 n_enq;
  u64 to_send;
  int rv;

  ts = session_get (hs->vpp_session_index, hs->thread_index);

  if (hsm->debug_level > 0)
    clib_warning ("status code: %U", format_http_status_code, status);

  msg.type = HTTP_MSG_REPLY;
  msg.code = status;
  msg.data.body_len = hs->data_len;
  msg.data.headers_offset = 0;
  msg.data.headers_len = hs->resp_headers.tail_offset;
  msg.data.len = msg.data.body_len + msg.data.headers_len;

  if (msg.data.len > hs->use_ptr_thresh)
    {
      msg.data.type = HTTP_MSG_DATA_PTR;
      rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
      ASSERT (rv == sizeof (msg));

      if (msg.data.headers_len)
	{
	  uword headers = pointer_to_uword (hs->headers_buf);
	  rv =
	    svm_fifo_enqueue (ts->tx_fifo, sizeof (headers), (u8 *) &headers);
	  ASSERT (rv == sizeof (headers));
	}

      if (!msg.data.body_len)
	goto done;

      uword data = pointer_to_uword (hs->data);
      rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (data), (u8 *) &data);
      ASSERT (rv == sizeof (data));

      goto done;
    }

  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.body_offset = msg.data.headers_len;

  rv = svm_fifo_enqueue (ts->tx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.data.headers_len)
    {
      rv =
	svm_fifo_enqueue (ts->tx_fifo, msg.data.headers_len, hs->headers_buf);
      ASSERT (rv == msg.data.headers_len);
    }

  if (!msg.data.body_len)
    goto done;

  to_send = hs->data_len;
  n_enq = clib_min (svm_fifo_size (ts->tx_fifo), to_send);

  rv = svm_fifo_enqueue (ts->tx_fifo, n_enq, hs->data);

  if (rv < to_send)
    {
      hs->data_offset = (rv > 0) ? rv : 0;
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
    }

done:

  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);
}

__clib_export void
hss_session_send_data (hss_url_handler_args_t *args)
{
  hss_session_t *hs;

  hs = hss_session_get (args->sh.thread_index, args->sh.session_index);
  if (!hs)
    return;

  if (hs->data && hs->free_data)
    vec_free (hs->data);

  hs->data = args->data;
  hs->data_len = args->data_len;
  hs->free_data = args->free_vec_data;

  /* Set content type only if we have some response data */
  if (hs->data_len)
    if (hss_add_header (hs, HTTP_HEADER_CONTENT_TYPE,
			http_content_type_token (args->ct)))
      args->sc = HTTP_STATUS_INTERNAL_ERROR;

  start_send_data (hs, args->sc);
}

/*
 * path_has_known_suffix()
 * Returns 1 if the request ends with a known suffix, like .htm or .ico
 * Used to avoid looking for "/favicon.ico/index.html" or similar.
 */

static int
path_has_known_suffix (u8 *request)
{
  u8 *ext;
  uword *p;

  if (vec_len (request) == 0)
    {
      return 0;
    }

  ext = request + vec_len (request) - 1;

  while (ext > request && ext[0] != '.')
    ext--;

  if (ext == request)
    return 0;

  p = hash_get_mem (hss_main.mime_type_indices_by_file_extensions, ext);
  if (p)
    return 1;

  return 0;
}

/*
 * content_type_from_request
 * Returns the index of the request's suffix in the
 * http-layer http_content_type_str[] array.
 */

static http_content_type_t
content_type_from_request (u8 *request)
{
  u8 *ext;
  uword *p;
  /* default to text/html */
  http_content_type_t rv = HTTP_CONTENT_TEXT_HTML;

  ASSERT (vec_len (request) > 0);

  ext = request + vec_len (request) - 1;

  while (ext > request && ext[0] != '.')
    ext--;

  if (ext == request)
    return rv;

  p = hash_get_mem (hss_main.mime_type_indices_by_file_extensions, ext);

  if (p == 0)
    return rv;

  rv = p[0];
  return rv;
}

static int
try_url_handler (hss_session_t *hs)
{
  hss_main_t *hsm = &hss_main;
  http_status_code_t sc = HTTP_STATUS_OK;
  hss_url_handler_args_t args = {};
  uword *p, *url_table;
  session_t *ts;
  u32 max_deq;
  u8 *target_path;
  int rv;

  target_path = hs->target_path;

  if (!target_path)
    return -1;

  /* zero-length? try "index.html" */
  if (vec_len (target_path) == 0)
    {
      target_path = format (target_path, "index.html");
    }

  /* Look for built-in GET / POST handlers */
  url_table =
    (hs->rt == HTTP_REQ_GET) ? hsm->get_url_handlers : hsm->post_url_handlers;

  p = hash_get_mem (url_table, target_path);
  if (!p)
    return -1;

  hs->rx_buff = 0;

  /* Read request body */
  if (hs->left_recv)
    {
      hss_listener_t *l = hss_listener_get (hs->listener_index);
      if (hs->left_recv > l->rx_buff_thresh)
	{
	  /* TODO: large body (not buffered in memory) */
	  clib_warning ("data length %u above threshold %u", hs->left_recv,
			l->rx_buff_thresh);
	  hs->left_recv = 0;
	  start_send_data (hs, HTTP_STATUS_INTERNAL_ERROR);
	  hss_session_disconnect_transport (hs);
	  return 0;
	}
      hs->rx_buff_offset = 0;
      vec_validate (hs->rx_buff, hs->left_recv - 1);
      ts = session_get (hs->vpp_session_index, hs->thread_index);
      max_deq = svm_fifo_max_dequeue (ts->rx_fifo);
      if (max_deq < hs->left_recv)
	{
	  hs->read_body_handler = url_handler_read_body;
	  if (max_deq == 0)
	    return 0;
	  rv = svm_fifo_dequeue (ts->rx_fifo, max_deq, hs->rx_buff);
	  ASSERT (rv == max_deq);
	  hs->rx_buff_offset = max_deq;
	  hs->left_recv -= max_deq;
	  hss_confirm_data_read (hs, max_deq);
	  return 0;
	}
      rv = svm_fifo_dequeue (ts->rx_fifo, hs->left_recv,
			     hs->rx_buff + hs->rx_buff_offset);
      ASSERT (rv == hs->left_recv);
      hss_confirm_data_read (hs, hs->left_recv);
      hs->left_recv = 0;
    }

  hs->path = 0;
  hs->data_offset = 0;
  hs->cache_pool_index = ~0;

  if (hsm->debug_level > 0)
    clib_warning ("%s '%s'", (hs->rt == HTTP_REQ_GET) ? "GET" : "POST",
		  target_path);

  args.req_type = hs->rt;
  args.query = hs->target_query;
  args.req_data = hs->rx_buff;
  args.sh.thread_index = hs->thread_index;
  args.sh.session_index = hs->session_index;

  rv = ((hss_url_handler_fn) p[0]) (&args);

  vec_free (hs->rx_buff);

  /* Wait for data from handler */
  if (rv == HSS_URL_HANDLER_ASYNC)
    return 0;

  if (rv == HSS_URL_HANDLER_ERROR)
    {
      clib_warning ("builtin handler %llx hit on %s '%s' but failed!", p[0],
		    (hs->rt == HTTP_REQ_GET) ? "GET" : "POST", target_path);
      sc = HTTP_STATUS_BAD_GATEWAY;
    }

  hs->data = args.data;
  hs->data_len = args.data_len;
  hs->free_data = args.free_vec_data;

  /* Set content type only if we have some response data */
  if (hs->data_len)
    if (hss_add_header (hs, HTTP_HEADER_CONTENT_TYPE,
			http_content_type_token (args.ct)))
      sc = HTTP_STATUS_INTERNAL_ERROR;

  start_send_data (hs, sc);

  if (!hs->data_len)
    hss_session_disconnect_transport (hs);

  return 0;
}

static u8
file_path_is_valid (u8 *path)
{
  struct stat _sb, *sb = &_sb;

  if (stat ((char *) path, sb) < 0 /* can't stat the file */
      || (sb->st_mode & S_IFMT) != S_IFREG /* not a regular file */)
    return 0;

  return 1;
}

static u32
try_index_file (hss_listener_t *l, hss_session_t *hs, u8 *path)
{
  hss_main_t *hsm = &hss_main;
  u8 *redirect;
  u32 plen;

  /* Remove the trailing space */
  vec_dec_len (path, 1);
  plen = vec_len (path);

  /* Append "index.html" */
  if (path[plen - 1] != '/')
    path = format (path, "/index.html%c", 0);
  else
    path = format (path, "index.html%c", 0);

  if (hsm->debug_level > 0)
    clib_warning ("trying to find index: %s", path);

  if (!file_path_is_valid (path))
    return HTTP_STATUS_NOT_FOUND;

  /*
   * We found an index.html file, build a redirect
   */
  vec_delete (path, vec_len (l->www_root) - 1, 0);

  redirect = format (0, "http%s://%s%s",
		     l->flags & HSS_LISTENER_F_NEED_CRYPTO ? "s" : "",
		     hs->authority, path);

  if (hsm->debug_level > 0)
    clib_warning ("redirect: %s", redirect);

  if (hss_add_header (hs, HTTP_HEADER_LOCATION, (const char *) redirect,
		      vec_len (redirect)))
    return HTTP_STATUS_INTERNAL_ERROR;

  vec_free (redirect);
  hs->data_len = 0;
  hs->free_data = 1;

  return HTTP_STATUS_MOVED;
}

static int
try_file_handler (hss_session_t *hs)
{
  hss_main_t *hsm = &hss_main;
  http_status_code_t sc = HTTP_STATUS_OK;
  u8 *path, *sanitized_path;
  u32 ce_index, max_dequeue;
  http_content_type_t type;
  u8 *last_modified;
  hss_listener_t *l;
  session_t *ts;

  l = hss_listener_get (hs->listener_index);

  /* Feature not enabled */
  if (!l->www_root)
    return -1;

  /* Discard request body */
  if (hs->left_recv)
    {
      ts = session_get (hs->vpp_session_index, hs->thread_index);
      max_dequeue = svm_fifo_max_dequeue (ts->rx_fifo);
      if (max_dequeue < hs->left_recv)
	{
	  svm_fifo_dequeue_drop (ts->rx_fifo, max_dequeue);
	  hs->left_recv -= max_dequeue;
	  hs->read_body_handler = file_handler_discard_body;
	  hss_confirm_data_read (hs, max_dequeue);
	  return 0;
	}
      svm_fifo_dequeue_drop (ts->rx_fifo, hs->left_recv);
      hss_confirm_data_read (hs, hs->left_recv);
      hs->left_recv = 0;
    }

  /* Sanitize received path */
  sanitized_path = http_path_sanitize (hs->target_path);

  /*
   * Construct the file to open
   */
  if (!sanitized_path)
    path = format (0, "%s%c", l->www_root, 0);
  else
    path = format (0, "%s/%s%c", l->www_root, sanitized_path, 0);

  if (hsm->debug_level > 0)
    clib_warning ("%s '%s'", (hs->rt == HTTP_REQ_GET) ? "GET" : "POST", path);

  if (hs->data && hs->free_data)
    vec_free (hs->data);

  hs->data_offset = 0;

  ce_index = hss_cache_lookup_and_attach (&l->cache, path, &hs->data,
					  &hs->data_len, &last_modified);
  if (ce_index == ~0)
    {
      if (!file_path_is_valid (path))
	{
	  /*
	   * Generate error 404 right now if we can't find a path with
	   * a known file extension. It's silly to look for
	   * "favicon.ico/index.html" if you can't find
	   * "favicon.ico"; realistic example which used to happen.
	   */
	  if (path_has_known_suffix (path))
	    {
	      sc = HTTP_STATUS_NOT_FOUND;
	      goto done;
	    }
	  sc = try_index_file (l, hs, path);
	  goto done;
	}
      ce_index = hss_cache_add_and_attach (&l->cache, path, &hs->data,
					   &hs->data_len, &last_modified);
      if (ce_index == ~0)
	{
	  sc = HTTP_STATUS_INTERNAL_ERROR;
	  goto done;
	}
    }

  hs->path = path;
  hs->cache_pool_index = ce_index;

  /* Set following headers only for happy path:
   * Content-Type
   * Cache-Control max-age
   * Last-Modified
   */
  type = content_type_from_request (sanitized_path);
  if (hss_add_header (hs, HTTP_HEADER_CONTENT_TYPE,
		      http_content_type_token (type)) ||
      hss_add_header (hs, HTTP_HEADER_CACHE_CONTROL,
		      (const char *) l->max_age_formatted,
		      vec_len (l->max_age_formatted)) ||
      hss_add_header (hs, HTTP_HEADER_LAST_MODIFIED,
		      (const char *) last_modified, vec_len (last_modified)))
    {
      sc = HTTP_STATUS_INTERNAL_ERROR;
    }

done:
  vec_free (sanitized_path);
  start_send_data (hs, sc);
  if (!hs->data_len)
    hss_session_disconnect_transport (hs);

  return 0;
}

static void
handle_request (hss_session_t *hs)
{
  hss_listener_t *l;

  l = hss_listener_get (hs->listener_index);

  if (hs->left_recv > l->max_req_body_size)
    {
      start_send_data (hs, HTTP_STATUS_CONTENT_TOO_LARGE);
      hss_session_disconnect_transport (hs);
      return;
    }

  if (l->enable_url_handlers && !try_url_handler (hs))
    return;

  if (!try_file_handler (hs))
    return;

  /* Handler did not find anything return 404 */
  start_send_data (hs, HTTP_STATUS_NOT_FOUND);
  hss_session_disconnect_transport (hs);
}

static int
file_handler_discard_body (hss_session_t *hs, session_t *ts)
{
  u32 max_dequeue, to_discard;

  max_dequeue = svm_fifo_max_dequeue (ts->rx_fifo);
  to_discard = clib_min (max_dequeue, hs->left_recv);
  svm_fifo_dequeue_drop (ts->rx_fifo, to_discard);
  hs->left_recv -= to_discard;
  hss_confirm_data_read (hs, to_discard);
  if (hs->left_recv == 0)
    return try_file_handler (hs);
  return 0;
}

static int
url_handler_read_body (hss_session_t *hs, session_t *ts)
{
  u32 max_dequeue, to_read;
  int rv;

  max_dequeue = svm_fifo_max_dequeue (ts->rx_fifo);
  to_read = clib_min (max_dequeue, hs->left_recv);
  rv =
    svm_fifo_dequeue (ts->rx_fifo, to_read, hs->rx_buff + hs->rx_buff_offset);
  ASSERT (rv == to_read);
  hs->rx_buff_offset += to_read;
  hs->left_recv -= to_read;
  hss_confirm_data_read (hs, to_read);
  if (hs->left_recv == 0)
    return try_url_handler (hs);
  return 0;
}

static int
hss_ts_rx_callback (session_t *ts)
{
  hss_session_t *hs;
  http_msg_t msg;
  int rv;

  hs = hss_session_get (ts->thread_index, ts->opaque);
  if (hs->left_recv != 0)
    {
      ASSERT (hs->read_body_handler);
      return hs->read_body_handler (hs, ts);
    }

  if (hs->free_data)
    vec_free (hs->data);

  hs->data = 0;
  hs->data_len = 0;
  vec_free (hs->target_path);
  vec_free (hs->target_query);
  vec_free (hs->authority);
  http_init_headers_ctx (&hs->resp_headers, hs->headers_buf,
			 vec_len (hs->headers_buf));

  /* Read the http message header */
  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REQUEST ||
      (msg.method_type != HTTP_REQ_GET && msg.method_type != HTTP_REQ_POST))
    {
      if (hss_add_header (hs, HTTP_HEADER_ALLOW, http_token_lit ("GET, POST")))
	start_send_data (hs, HTTP_STATUS_INTERNAL_ERROR);
      else
	start_send_data (hs, HTTP_STATUS_METHOD_NOT_ALLOWED);
      goto err_done;
    }

  hs->rt = msg.method_type;

  /* Read authority */
  if (msg.data.target_authority_len)
    {
      vec_validate (hs->authority, msg.data.target_authority_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_authority_offset,
			  msg.data.target_authority_len, hs->authority);
      ASSERT (rv == msg.data.target_authority_len);
    }
  else
    {
      /* Mandatory Host header was missing in HTTP/1.1 request */
      start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
      vec_add1 (hs->authority, 0);
      goto err_done;
    }
  /* Read target path */
  if (msg.data.target_path_len)
    {
      vec_validate (hs->target_path, msg.data.target_path_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_path_offset,
			  msg.data.target_path_len, hs->target_path);
      ASSERT (rv == msg.data.target_path_len);
      if (http_validate_abs_path_syntax (hs->target_path, 0))
	{
	  start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
	  goto err_done;
	}
      /* Target path must be a proper C-string in addition to a vector */
      vec_add1 (hs->target_path, 0);
    }

  /* Read target query */
  if (msg.data.target_query_len)
    {
      vec_validate (hs->target_query, msg.data.target_query_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_query_offset,
			  msg.data.target_query_len, hs->target_query);
      ASSERT (rv == msg.data.target_query_len);
      if (http_validate_query_syntax (hs->target_query, 0))
	{
	  start_send_data (hs, HTTP_STATUS_BAD_REQUEST);
	  goto err_done;
	}
    }

  if (msg.data.body_len && msg.method_type == HTTP_REQ_POST)
    {
      hs->left_recv = msg.data.body_len;
      /* drop everything up to body */
      svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.body_offset);
    }

  /* Find and send data */
  handle_request (hs);
  goto done;

err_done:
  hss_session_disconnect_transport (hs);
done:
  svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.len);
  return 0;
}

static int
hss_ts_tx_callback (session_t *ts)
{
  hss_session_t *hs;
  u32 n_enq;
  u64 to_send;
  int rv;

  hs = hss_session_get (ts->thread_index, ts->opaque);
  if (!hs || !hs->data)
    return 0;

  to_send = hs->data_len - hs->data_offset;
  n_enq = clib_min (svm_fifo_size (ts->tx_fifo), to_send);

  rv = svm_fifo_enqueue (ts->tx_fifo, n_enq, hs->data + hs->data_offset);

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

  if (svm_fifo_set_event (ts->tx_fifo))
    session_program_tx_io_evt (ts->handle, SESSION_IO_EVT_TX);

  return 0;
}

/** \brief Session accept callback
 */
static int
hss_ts_accept_callback (session_t *ts)
{
  hss_session_t *hs;
  session_t *ls;
  u32 thresh;

  hs = hss_session_alloc (ts->thread_index);

  hs->vpp_session_index = ts->session_index;
  hs->vpp_session_handle = session_handle (ts);

  /* Link to listener context */
  if (ts->flags & SESSION_F_STREAM)
    ls = listen_session_get_from_handle (
      session_get_from_handle (ts->listener_handle)->listener_handle);
  else
    ls = listen_session_get_from_handle (ts->listener_handle);
  hs->listener_index = ls->opaque;
  hs->use_ptr_thresh = hss_listener_get (hs->listener_index)->use_ptr_thresh;

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
hss_ts_disconnect_callback (session_t *ts)
{
  hss_main_t *hsm = &hss_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;

  a->handle = session_handle (ts);
  a->app_index = hsm->app_index;
  vnet_disconnect_session (a);
}

static void
hss_ts_reset_callback (session_t *ts)
{
  hss_main_t *hsm = &hss_main;
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

static int
hss_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
hss_ts_cleanup (session_t *s, session_cleanup_ntf_t ntf)
{
  hss_session_t *hs;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hs = hss_session_get (s->thread_index, s->opaque);
  if (!hs)
    return;

  if (hs->cache_pool_index != ~0)
    {
      hss_listener_t *l = hss_listener_get (hs->listener_index);
      if (l)
	hss_cache_detach_entry (&l->cache, hs->cache_pool_index);
      hs->cache_pool_index = ~0;
    }

  if (hs->free_data)
    vec_free (hs->data);
  hs->data = 0;
  hs->data_offset = 0;
  hs->free_data = 0;
  vec_free (hs->headers_buf);
  vec_free (hs->path);
  vec_free (hs->authority);
  vec_free (hs->target_path);
  vec_free (hs->target_query);

  hss_session_free (hs);
}

static session_cb_vft_t hss_cb_vft = {
  .session_accept_callback = hss_ts_accept_callback,
  .session_disconnect_callback = hss_ts_disconnect_callback,
  .session_connected_callback = hss_ts_connected_callback,
  .add_segment_callback = hss_add_segment_callback,
  .del_segment_callback = hss_del_segment_callback,
  .builtin_app_rx_callback = hss_ts_rx_callback,
  .builtin_app_tx_callback = hss_ts_tx_callback,
  .session_reset_callback = hss_ts_reset_callback,
  .session_cleanup_callback = hss_ts_cleanup,
};

static int
hss_attach ()
{
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  hss_main_t *hsm = &hss_main;
  u64 options[APP_OPTIONS_N_OPTIONS];
  vnet_app_attach_args_t _a, *a = &_a;
  u64 segment_size = 128 << 20;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  if (hsm->private_segment_size)
    segment_size = hsm->private_segment_size;

  a->api_client_index = ~0;
  a->name = format (0, "http_static_server");
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
hss_transport_needs_crypto (session_endpoint_cfg_t *sep)
{
  return sep->flags & SESSION_ENDPT_CFG_F_SECURE ||
	 sep->transport_proto == TRANSPORT_PROTO_TLS ||
	 sep->transport_proto == TRANSPORT_PROTO_DTLS ||
	 sep->transport_proto == TRANSPORT_PROTO_QUIC;
}

static int
hss_listen (hss_listener_t *l, session_handle_t *lh)
{
  hss_main_t *hsm = &hss_main;
  vnet_listen_args_t _a, *a = &_a;
  u8 need_crypto;
  transport_endpt_ext_cfg_t *ext_cfg;
  int rv;
  transport_endpt_cfg_http_t http_cfg = { l->keepalive_timeout, 0 };

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hsm->app_index;

  need_crypto = hss_transport_needs_crypto (&l->sep);

  l->sep.transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a->sep_ext, &l->sep, sizeof (l->sep));

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));

  if (need_crypto)
    {
      l->flags |= HSS_LISTENER_F_NEED_CRYPTO;
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = hsm->ckpair_index;
      if (l->flags & HSS_LISTENER_F_HTTP1_ONLY)
	ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_1_1;
      else if (l->flags & HSS_LISTENER_F_HTTP3)
	ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_3;
    }

  if (!(rv = vnet_listen (a)))
    *lh = a->handle;

  session_endpoint_free_ext_cfgs (&a->sep_ext);

  return rv;
}

static void
hss_url_handlers_init (hss_main_t *hsm)
{
  if (hsm->get_url_handlers)
    return;

  hsm->get_url_handlers = hash_create_string (0, sizeof (uword));
  hsm->post_url_handlers = hash_create_string (0, sizeof (uword));
  hss_builtinurl_json_handlers_init ();
}

int
hss_listener_add (hss_listener_t *l_cfg)
{
  hss_main_t *hsm = &hss_main;
  session_handle_t lh;
  app_listener_t *al;
  hss_listener_t *l;
  session_t *ls;

  if (hss_listen (l_cfg, &lh))
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  pool_get (hsm->listeners, l);
  *l = *l_cfg;
  l->l_index = l - hsm->listeners;
  l->session_handle = lh;

  al = app_listener_get_w_handle (lh);
  ls = app_listener_get_session (al);
  ls->opaque = l->l_index;

  if (l->www_root)
    hss_cache_init (&l->cache, l->cache_size, hsm->debug_level);
  if (l->enable_url_handlers)
    hss_url_handlers_init (hsm);

  l->max_age_formatted = format (0, "max-age=%d", l->max_age);

  return 0;
}

int
hss_listener_del (hss_listener_t *l_cfg)
{
  hss_main_t *hsm = &hss_main;
  hss_listener_t *l;
  u8 found = 0;

  pool_foreach (l, hsm->listeners)
    {
      if (clib_memcmp (&l_cfg->sep, &l->sep, sizeof (l_cfg->sep)) == 0)
	{
	  found = 1;
	  break;
	}
    }

  if (!found)
    return -1;

  vnet_unlisten_args_t args = { .handle = l->session_handle, hsm->app_index };

  vec_free (l->www_root);
  vec_free (l->max_age_formatted);
  hss_cache_free (&l->cache);
  pool_put (hsm->listeners, l);

  return vnet_unlisten (&args);
}

int
hss_create (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hss_main_t *hsm = &hss_main;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (hsm->sessions, num_threads - 1);

  /* Make sure session layer is enabled */
  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vnet_session_enable_disable (vm, &args);

  if (hss_attach ())
    {
      clib_warning ("failed to attach server");
      return -1;
    }

  if (hsm->have_default_listener && hss_listener_add (&hsm->default_listener))
    {
      clib_warning ("failed to start listening");
      return -1;
    }

  hsm->is_init = 1;

  return 0;
}

static clib_error_t *
hss_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hss_main_t *hsm = &hss_main;
  hss_listener_t *l = &hsm->default_listener;
  clib_error_t *error = 0;
  char *uri = 0;
  u64 seg_size;
  int rv;

  if (hsm->app_index != (u32) ~0)
    return clib_error_return (0, "http static server already initialized...");

  hsm->prealloc_fifos = 0;
  hsm->private_segment_size = 0;
  hsm->fifo_size = 0;

  l->cache_size = 10 << 20;
  l->max_age = HSS_DEFAULT_MAX_AGE;
  l->max_req_body_size = HSS_DEFAULT_MAX_BODY_SIZE;
  l->rx_buff_thresh = HSS_DEFAULT_RX_BUFFER_THRESH;
  l->keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  l->flags = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    goto no_input;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      /* Server config */
      if (unformat (line_input, "private-segment-size %U",
		    unformat_memory_size, &seg_size))
	hsm->private_segment_size = seg_size;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &hsm->fifo_size))
	;
      else if (unformat (line_input, "prealloc-fifos %d",
			 &hsm->prealloc_fifos))
	;
      else if (unformat (line_input, "debug %d", &hsm->debug_level))
	;
      else if (unformat (line_input, "debug"))
	hsm->debug_level = 1;
      /* Default listener parameters */
      else if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "www-root %s", &l->www_root))
	;
      else if (unformat (line_input, "url-handlers"))
	l->enable_url_handlers = 1;
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &l->cache_size))
	;
      else if (unformat (line_input, "max-age %d", &l->max_age))
	;
      else if (unformat (line_input, "max-req-body-size %U",
			 unformat_memory_size, &l->max_req_body_size))
	;
      else if (unformat (line_input, "rx-buff-thresh %U", unformat_memory_size,
			 &l->rx_buff_thresh))
	;
      else if (unformat (line_input, "keepalive-timeout %d",
			 &l->keepalive_timeout))
	;
      else if (unformat (line_input, "ptr-thresh %U", unformat_memory_size,
			 &l->use_ptr_thresh))
	;
      else if (unformat (line_input, "http1-only"))
	l->flags |= HSS_LISTENER_F_HTTP1_ONLY;
      else if (unformat (line_input, "http3"))
	l->flags |= HSS_LISTENER_F_HTTP3;
      /* Deprecated */
      else if (unformat (line_input, "max-body-size %U", unformat_memory_size,
			 &l->max_req_body_size))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);

  if (l->flags & HSS_LISTENER_F_HTTP1_ONLY && l->flags & HSS_LISTENER_F_HTTP3)
    {
      error = clib_error_return (0, "conflicting flags ('http1-only' and 'http3')");
      goto done;
    }

no_input:

  if (error)
    goto done;

  if (l->www_root)
    {
      /* Maintain legacy default uri behavior */
      if (!uri)
	uri = "tcp://0.0.0.0:80";
      if (l->cache_size < (128 << 10))
	{
	  error = clib_error_return (0, "cache-size must be at least 128kb");
	  vec_free (l->www_root);
	  goto done;
	}
    }

  if (uri)
    {
      if (parse_uri (uri, &l->sep))
	{
	  error = clib_error_return (0, "failed to parse uri %s", uri);
	  goto done;
	}
      hsm->have_default_listener = 1;
    }

  if ((rv = hss_create (vm)))
    {
      error = clib_error_return (0, "server_create returned %d", rv);
      vec_free (l->www_root);
    }

done:

  return error;
}

/*?
 * Enable the static http server
 *
 * @cliexpar
 * This command enables the static http server. Listeners can be added later
 * @clistart
 * http static server www-root /tmp/www uri tcp://0.0.0.0/80 cache-size 2m
 * @cliend
 * @cliexcmd{http static server [private-segment-size <nnMG>]
 * [fifo-size <nbytes>] [prealloc-fifos <nn>] [debug <nn>] [uri <uri>]
 * [www-root <path>] [url-handlers] [cache-size <nn>] [max-age <nseconds>]
 * [max-req-body-size <nn>] [rx-buff-thresh <nn>] [keepalive-timeout <nn>]
 * [ptr-thresh <nn>] [http1-only] [http3]}
?*/
VLIB_CLI_COMMAND (hss_create_command, static) = {
  .path = "http static server",
  .short_help = "http static server [private-segment-size <nnMG>] [fifo-size <nbytes>]\n"
		"[prealloc-fifos <nn>] [debug <nn>] [uri <uri>] [www-root <path>]\n"
		"[url-handlers] [cache-size <nn>] [max-age <nseconds>]\n"
		"[max-req-body-size <nn>] [rx-buff-thresh <nn>] [keepalive-timeout <nn>]\n"
		"[ptr-thresh <nn>] [http1-only] [http3]\n",
  .function = hss_create_command_fn,
};

static clib_error_t *
hss_add_del_listener_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  hss_main_t *hsm = &hss_main;
  clib_error_t *error = 0;
  hss_listener_t _l = {}, *l = &_l;
  u8 is_add = 1;
  char *uri = 0;

  if (!hsm->is_init)
    return clib_error_return (0, "Static server not initialized");

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "No input provided");

  l->cache_size = 10 << 20;
  l->max_age = HSS_DEFAULT_MAX_AGE;
  l->max_req_body_size = HSS_DEFAULT_MAX_BODY_SIZE;
  l->rx_buff_thresh = HSS_DEFAULT_RX_BUFFER_THRESH;
  l->keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  l->flags = 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "www-root %s", &l->www_root))
	;
      else if (unformat (line_input, "url-handlers"))
	l->enable_url_handlers = 1;
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &l->cache_size))
	;
      else if (unformat (line_input, "max-age %d", &l->max_age))
	;
      else if (unformat (line_input, "max-req-body-size %U",
			 unformat_memory_size, &l->max_req_body_size))
	;
      else if (unformat (line_input, "rx-buff-thresh %U", unformat_memory_size,
			 &l->rx_buff_thresh))
	;
      else if (unformat (line_input, "keepalive-timeout %d",
			 &l->keepalive_timeout))
	;
      else if (unformat (line_input, "ptr-thresh %U", unformat_memory_size,
			 &l->use_ptr_thresh))
	;
      else if (unformat (line_input, "http1-only"))
	l->flags |= HSS_LISTENER_F_HTTP1_ONLY;
      else if (unformat (line_input, "http3"))
	l->flags |= HSS_LISTENER_F_HTTP3;
      /* Deprecated */
      else if (unformat (line_input, "max-body-size %U", unformat_memory_size,
			 &l->max_req_body_size))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  break;
	}
    }
  unformat_free (line_input);

  if (l->flags & HSS_LISTENER_F_HTTP1_ONLY && l->flags & HSS_LISTENER_F_HTTP3)
    {
      error = clib_error_return (0, "conflicting flags ('http1-only' and 'http3')");
      goto done;
    }

  if (!uri)
    {
      error = clib_error_return (0, "Must set uri");
      goto done;
    }

  if (parse_uri (uri, &l->sep))
    {
      error = clib_error_return (0, "failed to parse uri %s", uri);
      goto done;
    }

  if (!is_add)
    {
      hss_listener_del (l);
      goto done;
    }

  if (l->www_root == 0 && !l->enable_url_handlers)
    {
      error = clib_error_return (0, "Must set www-root or url-handlers");
      goto done;
    }

  if (l->cache_size < (128 << 10))
    {
      error = clib_error_return (0, "cache-size must be at least 128kb");
      goto done;
    }

  if (hss_listener_add (l))
    {
      error = clib_error_return (0, "failed to create listener");
      goto done;
    }

done:

  vec_free (uri);
  return error;
}

/*?
 * Add static http server listener
 *
 * @cliexpar
 * Add a static http server listener. The listener can be used to
 * serve static files from the www-root directory or to handle
 * requests using url handlers.
 * @clistart
 * http static listener www-root /tmp/www uri tcp://0.0.0.0/80 cache-size 2m
 * @cliend
 * @cliexcmd{http static listener [uri <uri>] [www-root <path>] [url-handlers]
 * [cache-size <nn>] [max-age <nseconds>] [max-req-body-size <nn>]
 * [rx-buff-thresh <nn>] [keepalive-timeout <nn>] [ptr-thresh <nn>]
 * [http1-only] [http3]}
?*/
VLIB_CLI_COMMAND (hss_add_del_listener_command, static) = {
  .path = "http static listener",
  .short_help = "http static listener [add|del] [uri <uri>] [www-root <path>]\n"
		"[url-handlers] [cache-size <nn>] [max-age <nseconds>]\n"
		"[max-req-body-size <nn>] [rx-buff-thresh <nn>] [keepalive-timeout <nn>]\n"
		"[ptr-thresh <nn>] [http1-only] [http3]\n",
  .function = hss_add_del_listener_command_fn,
};

static u8 *
format_hss_session (u8 *s, va_list *args)
{
  hss_session_t *hs = va_arg (*args, hss_session_t *);
  int __clib_unused verbose = va_arg (*args, int);

  s = format (s, "\n path %s, data length %llu, data_offset %llu",
	      hs->path ? hs->path : (u8 *) "[none]", hs->data_len,
	      hs->data_offset);
  return s;
}

static u8 *
format_hss_listener (u8 *s, va_list *args)
{
  hss_listener_t *l = va_arg (*args, hss_listener_t *);
  int __clib_unused verbose = va_arg (*args, int);

  s = format (
    s, "listener %d, uri %U:%u, www-root %s, cache-size %U url-handlers %d",
    l->l_index, format_ip46_address, &l->sep.ip, l->sep.is_ip4,
    clib_net_to_host_u16 (l->sep.port), l->www_root, format_memory_size,
    l->cache_size, l->enable_url_handlers);
  return s;
}

static clib_error_t *
hss_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  int verbose = 0, show_cache = 0, show_sessions = 0, show_listeners = 0;
  u32 l_index = 0;
  hss_main_t *hsm = &hss_main;

  if (!hsm->is_init)
    return clib_error_return (0, "Static server disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "cache"))
	show_cache = 1;
      else if (unformat (input, "cache %u", &l_index))
	show_cache = 1;
      else if (unformat (input, "sessions"))
	show_sessions = 1;
      else if (unformat (input, "listeners"))
	show_listeners = 1;
      else
	break;
    }

  if ((show_cache + show_sessions + show_listeners) == 0)
    return clib_error_return (0, "specify one or more of cache, sessions");

  if (show_cache)
    {
      hss_listener_t *l = hss_listener_get (l_index);
      if (l == 0)
	return clib_error_return (0, "listener %d not found", l_index);
      vlib_cli_output (vm, "%U", format_hss_cache, &l->cache, verbose);
    }

  if (show_sessions)
    {
      u32 *session_indices = 0;
      hss_session_t *hs;
      int i, j;


      for (i = 0; i < vec_len (hsm->sessions); i++)
	{
	  pool_foreach (hs, hsm->sessions[i])
            vec_add1 (session_indices, hs - hsm->sessions[i]);

	  for (j = 0; j < vec_len (session_indices); j++)
	    {
	      vlib_cli_output (
		vm, "%U", format_hss_session,
		pool_elt_at_index (hsm->sessions[i], session_indices[j]),
		verbose);
	    }
	  vec_reset_length (session_indices);
	}
      vec_free (session_indices);
    }

  if (show_listeners)
    {
      hss_listener_t *l;
      pool_foreach (l, hsm->listeners)
	{
	  vlib_cli_output (vm, "%U", format_hss_listener, l, verbose);
	}
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
VLIB_CLI_COMMAND (hss_show_command, static) = {
  .path = "show http static server",
  .short_help = "show http static server [sessions] [cache] [listeners] "
		"[verbose [<nn>]]",
  .function = hss_show_command_fn,
};

static clib_error_t *
hss_clear_cache_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  hss_main_t *hsm = &hss_main;
  u32 busy_items = 0, l_index = 0;
  hss_listener_t *l;

  if (!hsm->is_init)
    return clib_error_return (0, "Static server disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &l_index))
	;
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  l = hss_listener_get (l_index);
  if (l == 0)
    return clib_error_return (0, "listener %d not found", l_index);

  busy_items = hss_cache_clear (&l->cache);

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
VLIB_CLI_COMMAND (clear_hss_cache_command, static) = {
  .path = "clear http static cache",
  .short_help = "clear http static cache [index <index>]",
  .function = hss_clear_cache_command_fn,
};

static clib_error_t *
hss_main_init (vlib_main_t *vm)
{
  hss_main_t *hsm = &hss_main;

  hsm->app_index = ~0;
  hsm->vlib_main = vm;

  /* Set up file extension to mime type index map */
  hsm->mime_type_indices_by_file_extensions =
    hash_create_string (0, sizeof (uword));

#define _(def, ext, str)                                                      \
  hash_set_mem (hsm->mime_type_indices_by_file_extensions, ext,               \
		HTTP_CONTENT_##def);
  foreach_http_content_type;
#undef _

  return 0;
}

VLIB_INIT_FUNCTION (hss_main_init);
