/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HSI_HSI_TRACKER_PRIVATE_H_
#define SRC_PLUGINS_HSI_HSI_TRACKER_PRIVATE_H_

#include <hsi/hsi_tracker.h>
#include <vnet/session/application.h>
#include <vnet/tcp/tcp.h>
#include <vppinfra/pool.h>

#define HSI_TCP_TRACKER_MAGIC	      0x48534954
#define HSI_TCP_DRAIN_INDEX_INVALID   ((u32) ~0)
#define HSI_TCP_DRAIN_CACHE_MAX_BYTES (2 << 20)
#define HSI_UDP_DRAIN_INDEX_INVALID   ((u32) ~0)
#define HSI_UDP_DRAIN_CACHE_MAX_BYTES (2 << 20)

STATIC_ASSERT (sizeof (uword) >= sizeof (u64), "hsi drain lookup requires 64-bit keys");

typedef enum hsi_tracker_flags_
{
  HSI_TRACKER_F_CLEANUP_PENDING = 1 << 0,
  HSI_TRACKER_F_FIN_RCVD = 1 << 1,
  HSI_TRACKER_F_FIN_ACKED = 1 << 2,
  HSI_TRACKER_F_PEER_FIN_PENDING = 1 << 3,
  HSI_TRACKER_F_FIN_WAIT = 1 << 4,
} hsi_tracker_flags_t;

#define HSI_TRACKER_F_FIN_DONE (HSI_TRACKER_F_FIN_RCVD | HSI_TRACKER_F_FIN_ACKED)
#define HSI_TRACKER_F_FIN_MASK                                                                     \
  (HSI_TRACKER_F_FIN_RCVD | HSI_TRACKER_F_FIN_ACKED | HSI_TRACKER_F_PEER_FIN_PENDING |             \
   HSI_TRACKER_F_FIN_WAIT)

typedef struct hsi_tcp_tracker_
{
  ip46_address_t tx_lcl_ip;
  ip46_address_t tx_rmt_ip;
  session_handle_t peer_session_handle;
  f64 fin_wait_start;
  u64 packets;
  u64 bytes;
  u32 magic;
  hsi_tracker_flags_t flags;
  u32 peer_fin_ack;
  u32 peer_conn_index;
  tcp_cc_algorithm_t *cc_algo;
  u32 tx_fib_index;
  i32 seq_delta;
  i32 ack_delta;
  i32 tsval_delta;
  i32 tsecr_delta;
  u16 tx_lcl_port;
  u16 tx_rmt_port;
  i8 wnd_delta;
} hsi_tcp_tracker_t;

#define HSI_TCP_TRACKER_OFFSET STRUCT_OFFSET_OF (tcp_connection_t, rcv_dupacks)

STATIC_ASSERT (sizeof (hsi_tcp_tracker_t) <=
		 (STRUCT_OFFSET_OF (tcp_connection_t, next_node_index) - HSI_TCP_TRACKER_OFFSET),
	       "hsi tcp tracker must not overlap tcp output fields");
STATIC_ASSERT ((HSI_TCP_TRACKER_OFFSET % __alignof__ (hsi_tcp_tracker_t)) == 0,
	       "hsi tcp tracker overlay must be aligned");
STATIC_ASSERT (STRUCT_OFFSET_OF (hsi_tcp_tracker_t, cc_algo) ==
		 (STRUCT_OFFSET_OF (tcp_connection_t, cc_algo) - HSI_TCP_TRACKER_OFFSET),
	       "hsi tcp tracker cc_algo must overlap tcp cc_algo");

typedef struct hsi_udp_tracker_
{
  u32 tx_fib_index;
  ip46_address_t tx_lcl_ip;
  ip46_address_t tx_rmt_ip;
  u16 tx_lcl_port;
  u16 tx_rmt_port;
} hsi_udp_tracker_t;

STATIC_ASSERT (sizeof (hsi_udp_tracker_t) <= (STRUCT_OFFSET_OF (udp_connection_t, start_ts) -
					      STRUCT_OFFSET_OF (udp_connection_t, bytes_in)),
	       "hsi udp tracker must fit in unused tracked udp fields");
STATIC_ASSERT ((STRUCT_OFFSET_OF (udp_connection_t, bytes_in) % __alignof__ (hsi_udp_tracker_t)) ==
		 0,
	       "hsi udp tracker overlay must be aligned");

typedef struct hsi_udp_track_snapshot_
{
  session_handle_t session_handle;
  u32 conn_index;
  u32 fib_index;
  ip46_address_t lcl_ip;
  ip46_address_t rmt_ip;
  u16 lcl_port;
  u16 rmt_port;
  clib_thread_index_t thread_index;
  u8 is_ip4;
} hsi_udp_track_snapshot_t;

struct hsi_udp_track_commit_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  hsi_udp_track_snapshot_t peer;
};

struct hsi_udp_peer_update_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
};

typedef struct hsi_tcp_fin_ack_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  u32 ack;
} hsi_tcp_fin_ack_req_t;

typedef struct hsi_tcp_peer_fin_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  u32 ack;
} hsi_tcp_peer_fin_req_t;

struct hsi_session_fifos_cleanup_req_
{
  clib_thread_index_t owner_thread;
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;
};

typedef enum hsi_tcp_drain_state_
{
  HSI_TCP_DRAIN_STATE_DRAINING,
  HSI_TCP_DRAIN_STATE_READY,
  HSI_TCP_DRAIN_STATE_FAILED,
} hsi_tcp_drain_state_t;

typedef enum hsi_tcp_drain_flags_
{
  HSI_TCP_DRAIN_F_RX_OOO = 1 << 0,
  HSI_TCP_DRAIN_F_STALLED = 1 << 1,
  HSI_TCP_DRAIN_F_WND_CLAMPED = 1 << 2,
  HSI_TCP_DRAIN_F_ABORT_SENT = 1 << 3,
  HSI_TCP_DRAIN_F_COMMIT_SENT = 1 << 4,
} hsi_tcp_drain_flags_t;

typedef enum hsi_udp_drain_state_
{
  HSI_UDP_DRAIN_STATE_DRAINING,
  HSI_UDP_DRAIN_STATE_READY,
  HSI_UDP_DRAIN_STATE_FAILED,
} hsi_udp_drain_state_t;

typedef enum hsi_udp_idle_state_
{
  HSI_UDP_IDLE_STATE_ACTIVE = 1,
  HSI_UDP_IDLE_STATE_CLEANUP_PENDING,
} hsi_udp_idle_state_t;

typedef enum hsi_tcp_cleanup_reason_
{
  HSI_TCP_CLEANUP_REASON_FIN,
  HSI_TCP_CLEANUP_REASON_RST,
} hsi_tcp_cleanup_reason_t;

struct hsi_tcp_drain_
{
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
  u32 conn_index;
  u32 peer_conn_index;
  hsi_tcp_track_snapshot_t snapshot;
  clib_thread_index_t thread_index;
  f64 start_time;
  f64 last_progress_time;
  u32 rx_deq;
  u32 tx_deq;
  u32 snd_una;
  u32 snd_nxt;
  u32 cached_bytes;
  u32 *cached_buffers;
  hsi_tcp_drain_flags_t flags;
  hsi_tcp_drain_state_t state;
};

struct hsi_tcp_drain_start_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
};

struct hsi_udp_drain_
{
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
  u32 conn_index;
  u32 peer_conn_index;
  clib_thread_index_t thread_index;
  f64 start_time;
  f64 last_progress_time;
  u32 rx_deq;
  u32 tx_deq;
  u32 cached_bytes;
  u32 *cached_buffers;
  u8 stalled;
  u8 cleanup_pending;
  hsi_udp_drain_state_t state;
};

struct hsi_udp_drain_start_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
};

struct hsi_udp_drain_cache_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  u32 buffer_index;
  u32 len;
};

static_always_inline hsi_worker_t *
hsi_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (hsi_main.wrk, thread_index);
}

static_always_inline uword
hsi_session_conn_key (u32 session_index, u32 conn_index)
{
  return ((uword) session_index << 32) | conn_index;
}

static_always_inline u32
hsi_session_conn_key_session_index (uword key)
{
  return key >> 32;
}

static_always_inline u32
hsi_session_conn_key_conn_index (uword key)
{
  return key & 0xffffffff;
}

static_always_inline void
hsi_session_take_ownership (session_t *s)
{
  s->app_wrk_index = APP_INVALID_INDEX;
}

static_always_inline u8
hsi_session_is_hsi_owned (session_t *s)
{
  return s->app_wrk_index == APP_INVALID_INDEX;
}

static_always_inline hsi_tcp_tracker_t *
hsi_tcp_tracker_from_connection (tcp_connection_t *tc)
{
  return (hsi_tcp_tracker_t *) &tc->rcv_dupacks;
}

static inline hsi_tcp_tracker_t *
hsi_tcp_tracker_get (tcp_connection_t *tc)
{
  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (tc->state == TCP_STATE_CLOSED);
  return hsi_tcp_tracker_from_connection (tc);
}

static_always_inline hsi_udp_tracker_t *
hsi_udp_tracker_from_connection (udp_connection_t *uc)
{
  return (hsi_udp_tracker_t *) &uc->bytes_in;
}

static inline hsi_udp_tracker_t *
hsi_udp_tracker_get (udp_connection_t *uc)
{
  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  return hsi_udp_tracker_from_connection (uc);
}

static_always_inline session_handle_t
hsi_udp_connection_peer_handle (udp_connection_t *uc)
{
  return ((u64) uc->next_node_opaque << 32) | uc->next_node_index;
}

static_always_inline void
hsi_udp_connection_peer_handle_set (udp_connection_t *uc, session_handle_t peer_handle)
{
  uc->next_node_index = (u32) peer_handle;
  uc->next_node_opaque = peer_handle >> 32;
}

static_always_inline tcp_connection_t *
hsi_tcp_connection_at_index (clib_thread_index_t thread_index, u32 conn_index)
{
  return tcp_main.wrk[thread_index].connections + conn_index;
}

static_always_inline tcp_connection_t *
hsi_tcp_connection_at_session (session_t *s)
{
  return hsi_tcp_connection_at_index (s->thread_index, s->connection_index);
}

static_always_inline udp_connection_t *
hsi_udp_connection_at_index (clib_thread_index_t thread_index, u32 conn_index)
{
  return udp_main.wrk[thread_index].connections + conn_index;
}

static_always_inline udp_connection_t *
hsi_udp_connection_at_session (session_t *s)
{
  return hsi_udp_connection_at_index (s->thread_index, s->connection_index);
}

static_always_inline uword
hsi_session_conn_key_from_session (session_t *s)
{
  return hsi_session_conn_key (s->session_index, s->connection_index);
}

static_always_inline uword
hsi_tcp_session_conn_key_from_connection (tcp_connection_t *tc)
{
  return hsi_session_conn_key (tc->c_s_index, tc->c_c_index);
}

static_always_inline uword
hsi_udp_session_conn_key_from_connection (udp_connection_t *uc)
{
  return hsi_session_conn_key (uc->c_s_index, uc->c_c_index);
}

static_always_inline u8
hsi_session_uses_remote_fifos (session_t *s)
{
  return (s->rx_fifo && s->rx_fifo->master_thread_index != s->thread_index) ||
	 (s->tx_fifo && s->tx_fifo->master_thread_index != s->thread_index);
}

static_always_inline void
hsi_drain_sample_fifos (session_t *s, u32 *rx_deq, u32 *tx_deq)
{
  *rx_deq = svm_fifo_max_dequeue (s->rx_fifo);
  *tx_deq = svm_fifo_max_dequeue_cons (s->tx_fifo);
}

static_always_inline u8
hsi_drain_cache_has_room (u32 *cached_buffers, u32 cached_bytes, u32 len, u32 max_packets,
			  u32 max_bytes)
{
  if (vec_len (cached_buffers) >= max_packets)
    return 0;
  if (cached_bytes > max_bytes)
    return 0;

  return len <= max_bytes - cached_bytes;
}

static_always_inline void
hsi_drain_cache_buffer (u32 **cached_buffers, u32 *cached_bytes, u32 buffer_index, u32 len)
{
  vec_add1 (*cached_buffers, buffer_index);
  *cached_bytes += len;
}

static_always_inline u32
hsi_drain_drop_cached_buffers (vlib_main_t *vm, u32 **cached_buffers, u32 *cached_bytes)
{
  u32 n_buffers = vec_len (*cached_buffers);

  if (!n_buffers)
    return 0;

  vlib_buffer_free (vm, *cached_buffers, n_buffers);
  vec_free (*cached_buffers);
  *cached_buffers = 0;
  *cached_bytes = 0;

  return n_buffers;
}

static_always_inline void
hsi_drain_enqueue_cached_buffers (vlib_main_t *vm, u32 node_index, u32 *buffers)
{
  u32 n_left, n_sent = 0;

  n_left = vec_len (buffers);
  while (n_left)
    {
      vlib_frame_t *f;
      u32 *to_next;
      u32 n_frame;

      n_frame = clib_min (n_left, VLIB_FRAME_SIZE);
      f = vlib_get_frame_to_node (vm, node_index);
      to_next = vlib_frame_vector_args (f);
      clib_memcpy_fast (to_next, buffers + n_sent, n_frame * sizeof (*buffers));
      f->n_vectors = n_frame;
      vlib_put_frame_to_node (vm, node_index, f);

      n_sent += n_frame;
      n_left -= n_frame;
    }
}

static_always_inline u32
hsi_tcp_drain_index_get (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  uword *p;

  p = hash_get (wrk->tcp_drain_by_session_conn, key);
  if (!p)
    return HSI_TCP_DRAIN_INDEX_INVALID;

  return p[0];
}

static_always_inline hsi_tcp_drain_t *
hsi_tcp_drain_get (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk;
  u32 drain_index;

  drain_index = hsi_tcp_drain_index_get (thread_index, key);
  if (drain_index == HSI_TCP_DRAIN_INDEX_INVALID)
    return 0;

  wrk = hsi_worker_get (thread_index);
  return pool_elt_at_index (wrk->tcp_drains, drain_index);
}

static_always_inline hsi_tcp_drain_t *
hsi_tcp_drain_pool_get (hsi_worker_t *wrk, u32 *drain_index)
{
  hsi_tcp_drain_t *drain;

  pool_get_zero (wrk->tcp_drains, drain);
  *drain_index = drain - wrk->tcp_drains;
  return drain;
}

static_always_inline void
hsi_tcp_drain_pool_put_index (hsi_worker_t *wrk, u32 drain_index)
{
  pool_put_index (wrk->tcp_drains, drain_index);
}

static_always_inline u32
hsi_udp_drain_index_get (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  uword *p;

  p = hash_get (wrk->udp_drain_by_session_conn, key);
  if (!p)
    return HSI_UDP_DRAIN_INDEX_INVALID;

  return p[0];
}

static_always_inline hsi_udp_drain_t *
hsi_udp_drain_get (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk;
  u32 drain_index;

  drain_index = hsi_udp_drain_index_get (thread_index, key);
  if (drain_index == HSI_UDP_DRAIN_INDEX_INVALID)
    return 0;

  wrk = hsi_worker_get (thread_index);
  return pool_elt_at_index (wrk->udp_drains, drain_index);
}

static_always_inline hsi_udp_drain_t *
hsi_udp_drain_pool_get (hsi_worker_t *wrk, u32 *drain_index)
{
  hsi_udp_drain_t *drain;

  pool_get_zero (wrk->udp_drains, drain);
  *drain_index = drain - wrk->udp_drains;
  return drain;
}

static_always_inline void
hsi_udp_drain_pool_put_index (hsi_worker_t *wrk, u32 drain_index)
{
  pool_put_index (wrk->udp_drains, drain_index);
}

static_always_inline session_t *
hsi_session_peer_get_if_valid (session_handle_tu_t sh)
{
  if (sh.thread_index == vlib_get_thread_index ())
    return session_get_from_handle_if_valid (sh);

  return session_get_from_handle_safe (sh);
}

int hsi_track_sessions_compatible (session_t *s, session_t *peer_s);
int hsi_track_tcp (session_t *s, session_t *peer_s);
int hsi_track_udp (session_t *s, session_t *peer_s);

void hsi_session_cleanup_fifos (session_t *s);
void hsi_session_cleanup (session_t *s);
void hsi_session_send_cleanup_pair (session_handle_t first);

int hsi_tcp_session_is_cleanup_ready (session_t *s);
session_handle_t hsi_tcp_session_cleanup_peer_handle (session_t *s);
void hsi_tcp_session_cleanup_state (session_t *s);

int hsi_udp_session_is_cleanup_ready (session_t *s);
session_handle_t hsi_udp_session_cleanup_peer_handle (session_t *s);
void hsi_udp_session_cleanup_state (session_t *s);

void hsi_tracker_show_tcp (vlib_main_t *vm, u32 thread_index, hsi_worker_t *wrk, f64 now);
void hsi_tracker_show_udp (vlib_main_t *vm, u32 thread_index, hsi_worker_t *wrk, f64 now);

#endif /* SRC_PLUGINS_HSI_HSI_TRACKER_PRIVATE_H_ */
