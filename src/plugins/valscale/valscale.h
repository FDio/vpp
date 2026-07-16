/* SPDX-License-Identifier: Apache-2.0
 * valscale.h - RESP-aware load-balancing proxy for Valkey on VPP HostStack
 *
 * Architecture:
 *   - Frontend: VPP HostStack TCP session layer (passive-open / server)
 *   - Backend:  Non-blocking Unix domain sockets + clib_file_main event loop
 *
 * Routing: first RESP command → extract key → FNV-1a hash → backend index
 */

#ifndef __included_valscale_h__
#define __included_valscale_h__

#include <vnet/vnet.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vppinfra/file.h>
#include <vlib/file.h>

/* =========================================================================
 * RESP2 protocol parser
 *
 * We parse the first RESP command in the stream to extract the routing key.
 * Commands are sent as arrays of bulk-strings:
 *   *N\r\n$len0\r\narg0\r\n$len1\r\narg1\r\n...
 *   elem[0] = command name, elem[1] = key (if N >= 2)
 *
 * Inline commands (not starting with '*') are also handled.
 * ========================================================================= */

typedef enum
{
  RESP_S_START = 0, /* initial state: read type byte           */
  RESP_S_ARRAY_LEN, /* after '*': reading decimal count        */
  RESP_S_ELEM_TYPE, /* start of an element: expecting '$'      */
  RESP_S_BULK_LEN,  /* after '$': reading decimal length       */
  RESP_S_BULK_DATA, /* reading bulk string body                */
  RESP_S_BULK_CR,   /* expecting '\r' after bulk body          */
  RESP_S_BULK_LF,   /* expecting '\n' after '\r'               */
  RESP_S_INLINE,    /* inline (non-array) command              */
} resp_state_t;

#define RESP_LINE_BUF_SZ 512

typedef struct
{
  resp_state_t state;

  /* Array parsing */
  i32 array_len; /* total elements expected (-1 = not set) */
  i32 elem_idx;	 /* which element we are currently reading */

  /* Bulk string parsing */
  i64 bulk_len;	      /* expected bytes in current bulk string */
  i64 bulk_remaining; /* bytes still to consume               */

  /* Key accumulation (element at index 1) */
  u8 *key; /* clib vec */

  /* Result flags */
  u8 key_found; /* set when key is fully read               */
  u8 no_key;	/* set when command provably has no key     */

  /* Scratch buffer for reading decimal numbers / inline */
  u8 line[RESP_LINE_BUF_SZ];
  u32 line_len;
} resp_parser_t;

static_always_inline void
resp_parser_init (resp_parser_t *p)
{
  clib_memset (p, 0, sizeof (*p));
  p->state = RESP_S_START;
  p->array_len = -1;
  p->elem_idx = -1;
  p->bulk_len = -1;
}

/* Parse up to len bytes starting at data.
 * Returns number of bytes consumed.
 * Stops when key_found or no_key is set. */
u32 resp_parse (resp_parser_t *p, const u8 *data, u32 len);

/* =========================================================================
 * Connection state machine
 * ========================================================================= */

typedef enum
{
  VS_CONN_S_PARSING = 0, /* buffering until key identified   */
  VS_CONN_S_CONNECTING,	 /* Unix socket connect() in flight  */
  VS_CONN_S_PROXYING,	 /* full-duplex proxy established    */
  VS_CONN_S_CLOSING,	 /* half/full close in progress      */
} vs_conn_state_t;

typedef struct vs_conn_
{
  /* --- VPP session (client side) --- */
  session_handle_t client_sh;
  svm_fifo_t *client_rx; /* data arriving from client  */
  svm_fifo_t *client_tx; /* data to send to client     */

  /* --- Backend Unix socket --- */
  int backend_fd;	/* -1 = not opened             */
  u32 backend_file_idx; /* index in file_main pool     */
  u32 backend_idx;	/* which backend was selected  */

  /* --- State --- */
  vs_conn_state_t state;

  /* --- Data buffered while backend is connecting (client→backend) --- */
  u8 *pending_tx; /* clib vec */

  /* --- Data read from backend that didn't fit in client TX FIFO --- */
  u8 *backend_rx_pending; /* clib vec; drained by vs_tx_callback */

  /* --- RESP parser (used only in PARSING state) --- */
  resp_parser_t resp;

  /* --- Pool housekeeping --- */
  u32 conn_index;

  /* Deferred backend close state (main-thread clib_file callbacks only) */
  u8 backend_closing;
  u32 backend_gen;
} vs_conn_t;

/* =========================================================================
 * Backend descriptor
 * ========================================================================= */

typedef struct
{
  u8 *socket_path; /* e.g. /tmp/valkey-0.sock */
} vs_backend_t;

/* =========================================================================
 * Plugin main structure
 * ========================================================================= */

typedef struct
{
  /* Connection pool */
  vs_conn_t *conn_pool;
  clib_spinlock_t conn_lock; /* only needed with workers */

  /* Configured backends */
  vs_backend_t *backends; /* clib vec */
  u32 n_backends;

  /* VPP application handles */
  u32 server_app_index;
  u32 server_client_index; /* ~0 for builtin */

  /* Configuration */
  u16 listen_port;
  u32 fifo_size;
  u32 backend_socket_buffer;
  u64 segment_size;

  /* VPP main backpointer */
  vlib_main_t *vlib_main;

  /* Initialisation flag */
  u8 is_init;
} valscale_main_t;

extern valscale_main_t valscale_main;

static_always_inline vs_conn_t *
vs_conn_get (u32 idx)
{
  return pool_elt_at_index (valscale_main.conn_pool, idx);
}

#endif /* __included_valscale_h__ */
