/* SPDX-License-Identifier: Apache-2.0
 * valscale.c - RESP-aware TCP load-balancing proxy for Valkey on VPP HostStack
 *
 * Data flow:
 *   client ──TCP──► VPP session layer ──RX fifo──► valscale_rx_cb
 *                                                       │
 *                                               RESP parse → hash(key)
 *                                                       │
 *                                               backend Unix socket fd
 *                                                       │
 *                                               write() to Valkey backend
 *
 *   Valkey backend ──Unix sock──► vs_backend_read_ready
 *                                       │
 *                               svm_fifo_enqueue(client_tx)
 *                                       │
 *                               session_program_tx_io_evt → TCP send
 */

#include <valscale/valscale.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vnet/session/session.h>
#include <vpp/app/version.h>

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>

valscale_main_t valscale_main = {
  .listen_port = 6379,
  .fifo_size = 8 << 20,
  .backend_socket_buffer = 16 << 20,
  .segment_size = 512ULL << 20,
  .server_client_index = ~0,
  .server_app_index = APP_INVALID_INDEX,
};

/* =========================================================================
 * RESP2 parser implementation
 * ========================================================================= */

/* Flush the line scratch buffer and parse as a decimal integer.
 * Returns the value or -1 on error. */
static i64
resp_line_to_i64 (resp_parser_t *p)
{
  i64 v = 0;
  i32 sign = 1;
  u32 i = 0;

  if (p->line_len == 0)
    return -1;

  if (p->line[0] == '-')
    {
      sign = -1;
      i = 1;
    }

  for (; i < p->line_len; i++)
    {
      if (p->line[i] < '0' || p->line[i] > '9')
	return -1;
      v = v * 10 + (p->line[i] - '0');
    }

  p->line_len = 0;
  return sign * v;
}

u32
resp_parse (resp_parser_t *p, const u8 *data, u32 len)
{
  const u8 *start = data;
  const u8 *end = data + len;

  while (data < end && !p->key_found && !p->no_key)
    {
      u8 c = *data;

      switch (p->state)
	{
	/* ---- initial byte: determines message type ---- */
	case RESP_S_START:
	  data++;
	  if (c == '*')
	    {
	      p->state = RESP_S_ARRAY_LEN;
	      p->line_len = 0;
	    }
	  else
	    {
	      /* Inline command: first char already consumed, keep in line */
	      if (p->line_len < RESP_LINE_BUF_SZ - 1)
		p->line[p->line_len++] = c;
	      p->state = RESP_S_INLINE;
	    }
	  break;

	/* ---- reading array count: N digits then \r\n ---- */
	case RESP_S_ARRAY_LEN:
	  data++;
	  if (c == '\r')
	    break; /* skip CR */
	  if (c == '\n')
	    {
	      i64 n = resp_line_to_i64 (p);
	      if (n <= 0)
		{
		  p->no_key = 1;
		  break;
		}
	      p->array_len = (i32) n;
	      p->elem_idx = 0;
	      p->state = RESP_S_ELEM_TYPE;
	    }
	  else
	    {
	      if (p->line_len < RESP_LINE_BUF_SZ - 1)
		p->line[p->line_len++] = c;
	    }
	  break;

	/* ---- start of each array element: expect '$' ---- */
	case RESP_S_ELEM_TYPE:
	  data++;
	  if (c == '$')
	    {
	      p->state = RESP_S_BULK_LEN;
	      p->line_len = 0;
	    }
	  else
	    {
	      p->no_key = 1; /* unexpected byte */
	    }
	  break;

	/* ---- reading bulk-string length: N digits then \r\n ---- */
	case RESP_S_BULK_LEN:
	  data++;
	  if (c == '\r')
	    break;
	  if (c == '\n')
	    {
	      i64 blen = resp_line_to_i64 (p);
	      if (blen < 0)
		{
		  /* null bulk string ($-1\r\n): no key */
		  p->no_key = 1;
		  break;
		}
	      p->bulk_len = blen;
	      p->bulk_remaining = blen;

	      if (blen == 0)
		{
		  /* empty bulk string → skip directly to trailing CRLF */
		  p->state = RESP_S_BULK_CR;
		}
	      else
		{
		  p->state = RESP_S_BULK_DATA;
		  /* if this is the key element, prepare the vec */
		  if (p->elem_idx == 1 && p->array_len >= 2)
		    {
		      vec_reset_length (p->key);
		      vec_validate (p->key, (u32) blen - 1);
		      vec_set_len (p->key, 0);
		    }
		}
	    }
	  else
	    {
	      if (p->line_len < RESP_LINE_BUF_SZ - 1)
		p->line[p->line_len++] = c;
	    }
	  break;

	/* ---- reading bulk string body ---- */
	case RESP_S_BULK_DATA:
	  {
	    u32 avail = (u32) (end - data);
	    u32 need = (u32) p->bulk_remaining;
	    u32 take = clib_min (avail, need);

	    if (p->elem_idx == 1 && p->array_len >= 2)
	      vec_add (p->key, data, take);

	    data += take;
	    p->bulk_remaining -= take;

	    if (p->bulk_remaining == 0)
	      p->state = RESP_S_BULK_CR;
	  }
	  break;

	/* ---- trailing \r after bulk body ---- */
	case RESP_S_BULK_CR:
	  data++;
	  if (c == '\r')
	    p->state = RESP_S_BULK_LF;
	  /* else: tolerate missing CR (shouldn't happen) */
	  break;

	/* ---- trailing \n after bulk body ---- */
	case RESP_S_BULK_LF:
	  data++;
	  /* c should be '\n' */
	  p->elem_idx++;

	  if (p->elem_idx == 1)
	    {
	      /* just finished elem[0] (command name) */
	      if (p->array_len < 2)
		p->no_key = 1; /* single-element command: no key */
	      else
		{
		  p->state = RESP_S_ELEM_TYPE;
		  p->line_len = 0;
		}
	    }
	  else
	    {
	      /* just finished elem[1] = the key */
	      p->key_found = 1;
	    }
	  break;

	/* ---- inline command: accumulate until \r\n ---- */
	case RESP_S_INLINE:
	  data++;
	  if (c == '\r')
	    break;
	  if (c == '\n')
	    {
	      p->line[p->line_len] = 0;
	      /* format: "CMD key [args...]" */
	      u8 *sp = (u8 *) memchr (p->line, ' ', p->line_len);
	      if (sp && (u32) (sp - p->line) < p->line_len - 1)
		{
		  u8 *ks = sp + 1;
		  /* skip multiple spaces */
		  while (*ks == ' ')
		    ks++;
		  u8 *ke = (u8 *) memchr (ks, ' ', p->line + p->line_len - ks);
		  if (!ke)
		    ke = p->line + p->line_len;
		  /* strip trailing CR */
		  while (ke > ks && *(ke - 1) == '\r')
		    ke--;
		  u32 klen = (u32) (ke - ks);
		  vec_reset_length (p->key);
		  vec_add (p->key, ks, klen);
		  p->key_found = 1;
		}
	      else
		p->no_key = 1;
	    }
	  else
	    {
	      if (p->line_len < RESP_LINE_BUF_SZ - 1)
		p->line[p->line_len++] = c;
	    }
	  break;

	default:
	  p->no_key = 1;
	  break;
	}
    }

  return (u32) (data - start);
}

/* =========================================================================
 * FNV-1a 32-bit hash  (public domain)
 * ========================================================================= */

static_always_inline u32
vs_fnv1a (const u8 *data, u32 len)
{
  u32 h = 2166136261u;
  for (u32 i = 0; i < len; i++)
    {
      h ^= data[i];
      h *= 16777619u;
    }
  return h;
}

static_always_inline u32
vs_select_backend (valscale_main_t *vsm, const u8 *key, u32 key_len)
{
  if (vsm->n_backends == 0)
    return 0;
  if (key_len == 0)
    return 0;

  /* Redis cluster {hashtag} support: if key contains '{...}', hash only
   * the content between the first '{' and the next '}'. */
  const u8 *open = (const u8 *) memchr (key, '{', key_len);
  if (open)
    {
      const u8 *close = (const u8 *) memchr (open + 1, '}', key_len - (open - key) - 1);
      if (close && close > open + 1)
	{
	  key_len = (u32) (close - open - 1);
	  key = open + 1;
	}
    }

  return vs_fnv1a (key, key_len) % vsm->n_backends;
}

/* =========================================================================
 * Connection pool helpers
 * ========================================================================= */

static vs_conn_t *
vs_conn_alloc (void)
{
  valscale_main_t *vsm = &valscale_main;
  vs_conn_t *c;

  clib_spinlock_lock_if_init (&vsm->conn_lock);
  pool_get_zero (vsm->conn_pool, c);
  c->conn_index = c - vsm->conn_pool;
  c->backend_fd = -1;
  c->backend_file_idx = ~0;
  resp_parser_init (&c->resp);
  clib_spinlock_unlock_if_init (&vsm->conn_lock);
  return c;
}

/* Must be called with conn_lock held (or no workers). */
static void
vs_conn_free_locked (vs_conn_t *c)
{
  valscale_main_t *vsm = &valscale_main;
  vec_free (c->pending_tx);
  vec_free (c->backend_rx_pending);
  vec_free (c->resp.key);
  clib_memset (c, 0xfe, sizeof (*c));
  pool_put (vsm->conn_pool, c);
}

/* =========================================================================
 * Backend Unix socket helpers
 * ========================================================================= */

/* Forward declarations */
static clib_error_t *vs_backend_read_ready (clib_file_t *f);
static clib_error_t *vs_backend_write_ready (clib_file_t *f);
static clib_error_t *vs_backend_error_ready (clib_file_t *f);
static void vs_backend_schedule_close (vs_conn_t *c);

static void
vs_client_disconnect (vs_conn_t *c)
{
  valscale_main_t *vsm = &valscale_main;
  vnet_disconnect_args_t da = {};

  da.handle = c->client_sh;
  da.app_index = vsm->server_app_index;
  c->state = VS_CONN_S_CLOSING;
  vnet_disconnect_session (&da);
}

static void
vs_backend_write_error (vs_conn_t *c)
{
  clib_warning ("valscale: backend write error (conn %u fd %d): %s", c->conn_index, c->backend_fd,
		strerror (errno));
  vs_backend_schedule_close (c);
  vs_client_disconnect (c);
}

/* Flush pending_tx to the backend fd.  Enables/disables write-notify. */
static void
vs_flush_pending (vs_conn_t *c)
{
  if (vec_len (c->pending_tx) == 0 || c->backend_fd < 0)
    return;

  ssize_t n = write (c->backend_fd, c->pending_tx, vec_len (c->pending_tx));
  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return;
      vec_reset_length (c->pending_tx);
      vs_backend_write_error (c);
      return;
    }

  if ((u32) n >= vec_len (c->pending_tx))
    {
      vec_reset_length (c->pending_tx);
      /* all sent: disable write notification */
      clib_file_set_data_available_to_write (&file_main, c->backend_file_idx, 0);
    }
  else
    {
      /* partial: remove written bytes, keep write notification armed */
      vec_delete (c->pending_tx, n, 0);
    }
}

/* Write data to backend, buffering if socket is not immediately writable. */
static void
vs_send_to_backend (vs_conn_t *c, const u8 *data, u32 len)
{
  if (c->backend_fd < 0 || len == 0)
    return;

  /* If there's already data pending, append and return. */
  if (vec_len (c->pending_tx) > 0)
    {
      vec_add (c->pending_tx, data, len);
      clib_file_set_data_available_to_write (&file_main, c->backend_file_idx, 1);
      return;
    }

  ssize_t n = write (c->backend_fd, data, len);
  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
	n = 0;
      else
	{
	  vs_backend_write_error (c);
	  return;
	}
    }

  if ((u32) n < len)
    {
      /* partial write: buffer remainder and arm write notification */
      vec_add (c->pending_tx, data + n, len - (u32) n);
      clib_file_set_data_available_to_write (&file_main, c->backend_file_idx, 1);
    }
}

/* Close backend FD and remove from file_main. */
static void
vs_backend_close (vs_conn_t *c)
{
  if (c->backend_fd < 0)
    return;
  if (c->backend_file_idx != ~0)
    {
      clib_file_del_by_index (&file_main, c->backend_file_idx);
      c->backend_file_idx = ~0;
    }
  /* fd is closed by clib_file_del; clear the cached value */
  c->backend_fd = -1;
  c->backend_closing = 0;
}

static void
vs_backend_close_rpc (void *arg)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = (u32) ((uword) arg >> 32);
  u32 expected_gen = (u32) (uword) arg;

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (!pool_is_free_index (vsm->conn_pool, ci))
    {
      vs_conn_t *c = vs_conn_get (ci);
      if (c->backend_gen == expected_gen)
	vs_backend_close (c);
    }

  clib_spinlock_unlock_if_init (&vsm->conn_lock);
}

static void
vs_backend_schedule_close (vs_conn_t *c)
{
  uword packed;

  if (c->backend_closing || c->backend_fd < 0)
    return;

  c->backend_closing = 1;
  packed = ((uword) c->conn_index << 32) | (uword) c->backend_gen;
  session_send_rpc_evt_to_thread (0, vs_backend_close_rpc, (void *) packed);
}

/* Connect to the Unix socket of backend[backend_idx].
 * Non-blocking: may return with state == VS_CONN_S_CONNECTING. */
static int
vs_backend_connect (vs_conn_t *c, u32 backend_idx)
{
  valscale_main_t *vsm = &valscale_main;
  struct sockaddr_un addr;
  int fd, rc;

  if (backend_idx >= vec_len (vsm->backends))
    {
      clib_warning ("valscale: invalid backend index %u", backend_idx);
      return -1;
    }

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    {
      clib_warning ("valscale: socket(): %s", strerror (errno));
      return -1;
    }

  /* Make non-blocking */
  if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0)
    {
      close (fd);
      return -1;
    }

  if (vsm->backend_socket_buffer)
    {
      int socket_buffer = (int) vsm->backend_socket_buffer;
      if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &socket_buffer, sizeof (socket_buffer)) < 0)
	clib_warning ("valscale: setsockopt(SO_SNDBUF): %s", strerror (errno));
      if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &socket_buffer, sizeof (socket_buffer)) < 0)
	clib_warning ("valscale: setsockopt(SO_RCVBUF): %s", strerror (errno));
    }

  clib_memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, (char *) vsm->backends[backend_idx].socket_path,
	   sizeof (addr.sun_path) - 1);

  rc = connect (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (rc < 0 && errno != EINPROGRESS)
    {
      clib_warning ("valscale: connect(%s): %s", vsm->backends[backend_idx].socket_path,
		    strerror (errno));
      close (fd);
      return -1;
    }

  c->backend_fd = fd;
  c->backend_idx = backend_idx;
  c->backend_closing = 0;
  c->backend_gen++;
  c->state = (rc == 0) ? VS_CONN_S_PROXYING : VS_CONN_S_CONNECTING;

  /* Register FD with VPP's epoll-based event loop. Only arm EPOLLOUT while
   * connect() is in progress; otherwise it causes a write-ready storm. */
  clib_file_t tmpl = {
    .file_descriptor = (u32) fd,
    .read_function = vs_backend_read_ready,
    .write_function = vs_backend_write_ready,
    .error_function = vs_backend_error_ready,
    .private_data = c->conn_index,
    .flags = (c->state == VS_CONN_S_CONNECTING) ? UNIX_FILE_DATA_AVAILABLE_TO_WRITE : 0,
    .description = format (0, "valscale-be-%u-idx%u", c->conn_index, backend_idx),
  };
  c->backend_file_idx = (u32) clib_file_add (&file_main, &tmpl);
  return 0;
}

/* =========================================================================
 * clib_file callbacks (called on main thread by epoll event loop)
 * ========================================================================= */

/* Flush backend_rx_pending into the client TX FIFO.
 * Always resolves the TX fifo via session handle to avoid stale pointers.
 * Returns 1 if the pending buffer is fully drained, 0 if FIFO still full. */
static int
vs_flush_backend_rx (vs_conn_t *c)
{
  if (vec_len (c->backend_rx_pending) == 0)
    return 1;

  session_t *s = session_get_from_handle_if_valid (c->client_sh);
  if (!s || !s->tx_fifo || s->session_state < SESSION_STATE_READY ||
      s->session_state > SESSION_STATE_OPENED)
    {
      /* Session gone or closing: discard buffered data */
      vec_reset_length (c->backend_rx_pending);
      return 1;
    }

  svm_fifo_t *tx = s->tx_fifo;
  u32 written = svm_fifo_enqueue (tx, vec_len (c->backend_rx_pending), c->backend_rx_pending);
  if (written > 0)
    {
      vec_delete (c->backend_rx_pending, written, 0);
      if (svm_fifo_set_event (tx))
	session_program_tx_io_evt (c->client_sh, SESSION_IO_EVT_TX);
    }

  return vec_len (c->backend_rx_pending) == 0;
}

static clib_error_t *
vs_backend_read_ready (clib_file_t *f)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = (u32) f->private_data;
  /* 4 MB: drains a full 256 KB pipeline batch in one read, one epoll wakeup.
   * Static is safe: clib_file callbacks run on the main thread only. */
  static u8 buf[4 << 20];
  ssize_t n;

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (pool_is_free_index (vsm->conn_pool, ci))
    goto done;

  vs_conn_t *c = vs_conn_get (ci);
  if (c->backend_closing || !c->client_tx)
    goto done;

  if (vec_len (c->backend_rx_pending) > 0)
    {
      vs_flush_backend_rx (c);
      goto done;
    }

  /* Resolve TX FIFO once for the entire drain loop */
  session_t *s = session_get_from_handle_if_valid (c->client_sh);
  if (!s || !s->tx_fifo || s->session_state < SESSION_STATE_READY ||
      s->session_state > SESSION_STATE_OPENED)
    goto done;

  svm_fifo_t *tx = s->tx_fifo;

  /* Drain loop: amortise epoll wakeup cost across multiple reads.
   * Signal TX once at the end rather than once per read. */
  int need_tx_evt = 0;
  while (1)
    {
      n = read (c->backend_fd, buf, sizeof (buf));
      if (n <= 0)
	{
	  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
	    break;
	  vs_backend_schedule_close (c);
	  vs_client_disconnect (c);
	  goto notify;
	}

      u32 written = svm_fifo_enqueue (tx, (u32) n, buf);
      if (written > 0)
	need_tx_evt = 1;

      if (written < (u32) n)
	{
	  vec_add (c->backend_rx_pending, buf + written, (u32) n - written);
	  break; /* FIFO full — stop until tx_callback drains it */
	}
    }

notify:
  if (need_tx_evt && svm_fifo_set_event (tx))
    session_program_tx_io_evt (c->client_sh, SESSION_IO_EVT_TX);

done:
  clib_spinlock_unlock_if_init (&vsm->conn_lock);
  return 0;
}

static clib_error_t *
vs_backend_write_ready (clib_file_t *f)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = (u32) f->private_data;

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (pool_is_free_index (vsm->conn_pool, ci))
    goto done;

  vs_conn_t *c = vs_conn_get (ci);

  if (c->backend_closing)
    goto done;

  if (c->state == VS_CONN_S_CONNECTING)
    {
      /* Check whether connect() completed successfully */
      int so_err = 0;
      socklen_t slen = sizeof (so_err);
      getsockopt (c->backend_fd, SOL_SOCKET, SO_ERROR, &so_err, &slen);
      if (so_err)
	{
	  clib_warning ("valscale: backend connect error: %s", strerror (so_err));
	  vs_backend_schedule_close (c);
	  vs_client_disconnect (c);
	  goto done;
	}
      c->state = VS_CONN_S_PROXYING;
    }

  vs_flush_pending (c);

done:
  clib_spinlock_unlock_if_init (&vsm->conn_lock);
  return 0;
}

static clib_error_t *
vs_backend_error_ready (clib_file_t *f)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = (u32) f->private_data;

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (!pool_is_free_index (vsm->conn_pool, ci))
    {
      vs_conn_t *c = vs_conn_get (ci);
      if (!c->backend_closing)
	{
	  clib_warning ("valscale: epoll error on backend fd %d (conn %u)", c->backend_fd, ci);
	  vs_backend_schedule_close (c);
	  vs_client_disconnect (c);
	}
    }

  clib_spinlock_unlock_if_init (&vsm->conn_lock);
  return 0;
}

/* =========================================================================
 * VPP HostStack session callbacks
 * ========================================================================= */

static int
vs_accept_callback (session_t *s)
{
  vs_conn_t *c = vs_conn_alloc ();

  c->client_sh = session_handle (s);
  c->client_rx = s->rx_fifo;
  c->client_tx = s->tx_fifo;
  c->state = VS_CONN_S_PARSING;

  s->opaque = c->conn_index;
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static void
vs_disconnect_callback (session_t *s)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = s->opaque;
  vnet_disconnect_args_t da = {};

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (pool_is_free_index (vsm->conn_pool, ci))
    goto done;

  vs_conn_t *c = vs_conn_get (ci);
  c->state = VS_CONN_S_CLOSING;
  c->client_rx = 0;
  c->client_tx = 0;
  vs_backend_close (c);

  da.handle = c->client_sh;
  da.app_index = vsm->server_app_index;
  vnet_disconnect_session (&da);

done:
  clib_spinlock_unlock_if_init (&vsm->conn_lock);
}

static void
vs_reset_callback (session_t *s)
{
  vs_disconnect_callback (s);
}

static int
vs_connected_callback (u32 app_index, u32 api_context, session_t *s, session_error_t err)
{
  /* Not used: backend connections go via Unix sockets, not session layer */
  return 0;
}

static int
vs_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
vs_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

/* RX callback: client sent us data */
static int
vs_rx_callback (session_t *s)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = s->opaque;
  /* 256 KB: matches LMCache chunk size, avoids looping on large SETs */
  static u8 tmp[256 << 10];

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (pool_is_free_index (vsm->conn_pool, ci))
    {
      clib_spinlock_unlock_if_init (&vsm->conn_lock);
      return 0;
    }

  vs_conn_t *c = vs_conn_get (ci);

  if (c->state == VS_CONN_S_PARSING)
    {
      /* ---- PHASE 1: identify the routing key ---- */
      u32 avail = svm_fifo_max_dequeue_cons (s->rx_fifo);
      if (avail == 0)
	goto done;

      /* Peek (do not consume yet) to run parser over buffered data */
      u32 peeked = svm_fifo_peek (s->rx_fifo, 0, clib_min (avail, sizeof (tmp)), tmp);
      resp_parse (&c->resp, tmp, peeked);

      if (!c->resp.key_found && !c->resp.no_key)
	goto done; /* need more data */

      /* Select backend */
      u32 bidx = 0;
      if (c->resp.key_found && vec_len (c->resp.key) > 0)
	bidx = vs_select_backend (vsm, c->resp.key, vec_len (c->resp.key));

      if (vs_backend_connect (c, bidx) < 0)
	{
	  /* Could not connect: drop client */
	  clib_spinlock_unlock_if_init (&vsm->conn_lock);
	  return -1;
	}

      /* Fall through to forward all pending RX data */
    }

  if (c->state == VS_CONN_S_CONNECTING || c->state == VS_CONN_S_PROXYING)
    {
      /* ---- PHASE 2: drain RX fifo → backend in large chunks ---- */
      u32 avail = svm_fifo_max_dequeue_cons (s->rx_fifo);
      while (avail > 0)
	{
	  u32 take = clib_min (avail, sizeof (tmp));
	  u32 deq = svm_fifo_dequeue (s->rx_fifo, take, tmp);
	  if (deq == 0)
	    break;

	  if (c->state == VS_CONN_S_PROXYING)
	    vs_send_to_backend (c, tmp, deq);
	  else
	    vec_add (c->pending_tx, tmp, deq); /* buffer until connected */

	  avail -= deq;
	}

      /* If pending and backend just became writable, arm write notification */
      if (vec_len (c->pending_tx) > 0 && c->backend_file_idx != ~0)
	clib_file_set_data_available_to_write (&file_main, c->backend_file_idx, 1);
    }

done:
  clib_spinlock_unlock_if_init (&vsm->conn_lock);
  return 0;
}

static int
vs_tx_callback (session_t *s)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = s->opaque;

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (!pool_is_free_index (vsm->conn_pool, ci))
    {
      vs_conn_t *c = vs_conn_get (ci);
      if (c->state != VS_CONN_S_CLOSING && vec_len (c->backend_rx_pending) > 0)
	vs_flush_backend_rx (c);
    }

  clib_spinlock_unlock_if_init (&vsm->conn_lock);
  return 0;
}

static void
vs_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  valscale_main_t *vsm = &valscale_main;
  u32 ci = s->opaque;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  clib_spinlock_lock_if_init (&vsm->conn_lock);

  if (!pool_is_free_index (vsm->conn_pool, ci))
    {
      vs_conn_t *c = vs_conn_get (ci);
      vs_backend_close (c);
      vs_conn_free_locked (c);
    }

  clib_spinlock_unlock_if_init (&vsm->conn_lock);
}

static session_cb_vft_t vs_session_cb_vft = {
  .session_accept_callback = vs_accept_callback,
  .session_disconnect_callback = vs_disconnect_callback,
  .session_reset_callback = vs_reset_callback,
  .session_connected_callback = vs_connected_callback,
  .add_segment_callback = vs_add_segment_callback,
  .del_segment_callback = vs_del_segment_callback,
  .builtin_app_rx_callback = vs_rx_callback,
  .builtin_app_tx_callback = vs_tx_callback,
  .session_cleanup_callback = vs_cleanup_callback,
};

/* =========================================================================
 * VPP application attach / listen
 * ========================================================================= */

static int
valscale_attach (void)
{
  valscale_main_t *vsm = &valscale_main;
  vnet_app_attach_args_t _a = {}, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  if (vsm->segment_size == 0)
    vsm->segment_size = 512ULL << 20;

  clib_memset (options, 0, sizeof (options));

  a->name = format (0, "valscale");
  a->api_client_index = vsm->server_client_index;
  a->session_cb_vft = &vs_session_cb_vft;
  a->options = options;

  options[APP_OPTIONS_SEGMENT_SIZE] = vsm->segment_size;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = vsm->segment_size;
  options[APP_OPTIONS_RX_FIFO_SIZE] = vsm->fifo_size;
  options[APP_OPTIONS_TX_FIFO_SIZE] = vsm->fifo_size;
  options[APP_OPTIONS_MAX_FIFO_SIZE] = vsm->fifo_size;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      clib_warning ("valscale: vnet_application_attach failed");
      return -1;
    }

  vsm->server_app_index = a->app_index;
  vec_free (a->name);
  return 0;
}

static int
valscale_listen (void)
{
  valscale_main_t *vsm = &valscale_main;
  vnet_listen_args_t _a = {}, *a = &_a;

  a->app_index = vsm->server_app_index;
  a->sep_ext.is_ip4 = 1;
  a->sep_ext.ip.ip4.as_u32 = 0; /* 0.0.0.0 */
  a->sep_ext.port = clib_host_to_net_u16 (vsm->listen_port);
  a->sep_ext.transport_proto = TRANSPORT_PROTO_TCP;
  a->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;

  if (vnet_listen (a))
    {
      clib_warning ("valscale: vnet_listen on port %u failed", vsm->listen_port);
      return -1;
    }
  return 0;
}

static int
valscale_create (vlib_main_t *vm)
{
  valscale_main_t *vsm = &valscale_main;
  vsm->vlib_main = vm;

  if (vlib_num_workers ())
    clib_spinlock_init (&vsm->conn_lock);

  if (valscale_attach ())
    return -1;

  return 0;
}

static int
valscale_start (vlib_main_t *vm)
{
  valscale_main_t *vsm = &valscale_main;

  if (!vsm->is_init)
    {
      session_enable_disable_args_t args = {
	.is_en = 1,
	.rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE,
      };
      vnet_session_enable_disable (vm, &args);

      if (valscale_create (vm))
	return -1;

      vsm->is_init = 1;
    }

  return valscale_listen ();
}

/* =========================================================================
 * CLI commands
 * ========================================================================= */

static clib_error_t *
valscale_enable_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  valscale_main_t *vsm = &valscale_main;
  unformat_input_t _li, *li = &_li;
  clib_error_t *err = 0;

  if (!unformat_user (input, unformat_line_input, li))
    {
      /* No arguments: just start with current config */
      if (valscale_start (vm))
	return clib_error_return (0, "valscale_start failed");
      return 0;
    }

  while (unformat_check_input (li) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (li, "port %d", &vsm->listen_port))
	;
      else if (unformat (li, "fifo-size %U", unformat_memory_size, &vsm->fifo_size))
	;
      else if (unformat (li, "segment-size %U", unformat_memory_size, &vsm->segment_size))
	;
      else if (unformat (li, "backend-socket-buffer %U", unformat_memory_size,
			 &vsm->backend_socket_buffer))
	;
      else
	{
	  err = clib_error_return (0, "unknown input '%U'", format_unformat_error, li);
	  goto done;
	}
    }

  if (valscale_start (vm))
    err = clib_error_return (0, "valscale_start failed");

done:
  unformat_free (li);
  return err;
}

VLIB_CLI_COMMAND (valscale_enable_cmd, static) = {
  .path = "valscale enable",
  .short_help = "valscale enable [port <n>] [fifo-size <n>[k|m]] "
		"[segment-size <n>[k|m|g]] "
		"[backend-socket-buffer <n>[k|m]]",
  .function = valscale_enable_fn,
};

static clib_error_t *
valscale_add_backend_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  valscale_main_t *vsm = &valscale_main;
  u8 *path = 0;

  if (!unformat (input, "%s", &path))
    return clib_error_return (0, "Usage: valscale add-backend <socket-path>");

  vs_backend_t be;
  clib_memset (&be, 0, sizeof (be));
  be.socket_path = path;
  vec_add1 (vsm->backends, be);
  vsm->n_backends = vec_len (vsm->backends);

  vlib_cli_output (vm, "valscale: added backend[%u] = %s", vsm->n_backends - 1, path);
  return 0;
}

VLIB_CLI_COMMAND (valscale_add_backend_cmd, static) = {
  .path = "valscale add-backend",
  .short_help = "valscale add-backend <unix-socket-path>",
  .function = valscale_add_backend_fn,
};

static clib_error_t *
valscale_show_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  valscale_main_t *vsm = &valscale_main;

  vlib_cli_output (vm,
		   "valscale: port=%u fifo=%u backend-socket-buffer=%u "
		   "segment-size=%U n_backends=%u is_init=%u",
		   vsm->listen_port, vsm->fifo_size, vsm->backend_socket_buffer, format_memory_size,
		   vsm->segment_size, vsm->n_backends, vsm->is_init);

  for (u32 i = 0; i < vec_len (vsm->backends); i++)
    vlib_cli_output (vm, "  backend[%u] = %s", i, vsm->backends[i].socket_path);

  u32 n_conns = 0;
  vs_conn_t *c;
  pool_foreach (c, vsm->conn_pool)
    n_conns++;
  vlib_cli_output (vm, "  active connections: %u", n_conns);

  return 0;
}

VLIB_CLI_COMMAND (valscale_show_cmd, static) = {
  .path = "show valscale",
  .short_help = "show valscale",
  .function = valscale_show_fn,
};

/* =========================================================================
 * startup.conf stanza:
 *
 *   valscale {
 *     port 6379
 *     fifo-size 64k
 *     backend /tmp/valkey-0.sock
 *     backend /tmp/valkey-1.sock
 *     backend /tmp/valkey-2.sock
 *   }
 * ========================================================================= */

static clib_error_t *
valscale_config_fn (vlib_main_t *vm, unformat_input_t *input)
{
  valscale_main_t *vsm = &valscale_main;
  u8 *path = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "port %d", &vsm->listen_port))
	;
      else if (unformat (input, "fifo-size %U", unformat_memory_size, &vsm->fifo_size))
	;
      else if (unformat (input, "segment-size %U", unformat_memory_size, &vsm->segment_size))
	;
      else if (unformat (input, "backend-socket-buffer %U", unformat_memory_size,
			 &vsm->backend_socket_buffer))
	;
      else if (unformat (input, "backend %s", &path))
	{
	  vs_backend_t be;
	  clib_memset (&be, 0, sizeof (be));
	  be.socket_path = path;
	  vec_add1 (vsm->backends, be);
	  vsm->n_backends++;
	  path = 0;
	}
      else
	return clib_error_return (0, "unknown valscale config '%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (valscale_config_fn, "valscale");

/* =========================================================================
 * Plugin init
 * ========================================================================= */

static clib_error_t *
valscale_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (valscale_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "RESP-aware Valkey proxy for the VPP HostStack",
};
