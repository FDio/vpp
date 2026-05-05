/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <hsi/hsi_tracker.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/pool.h>

#define HSI_TCP_TRACKER_MAGIC 0x48534954
#define HSI_UDP_TRACKER_MAGIC 0x48534955

typedef enum hsi_tcp_tracker_flags_
{
  HSI_TCP_TRACKER_F_PENDING = 1 << 0,
} hsi_tcp_tracker_flags_t;

typedef enum hsi_udp_tracker_flags_
{
  HSI_UDP_TRACKER_F_PENDING = 1 << 0,
} hsi_udp_tracker_flags_t;

typedef struct hsi_tcp_tracker_
{
  u32 magic;
  u32 flags;
  u32 peer_conn_index;
  u32 fib_index;
  ip46_address_t lcl_ip;
  ip46_address_t rmt_ip;
  u16 lcl_port;
  u16 rmt_port;
  clib_thread_index_t peer_thread_index;
  i32 seq_delta;
  i32 ack_delta;
  i32 tsval_delta;
  i32 tsecr_delta;
  i8 wnd_delta;
  u64 packets;
  u64 bytes;
} hsi_tcp_tracker_t;

typedef struct hsi_tcp_tracker_pending_
{
  u32 magic;
  u32 flags;
  hsi_tcp_track_snapshot_t snapshot;
} hsi_tcp_tracker_pending_t;

STATIC_ASSERT (sizeof (hsi_tcp_tracker_t) <= (STRUCT_OFFSET_OF (tcp_connection_t, bt) -
					      STRUCT_OFFSET_OF (tcp_connection_t, fr_occurences)),
	       "hsi tcp tracker must fit in unused tracked tcp fields");
STATIC_ASSERT (sizeof (hsi_tcp_tracker_pending_t) <=
		 (STRUCT_OFFSET_OF (tcp_connection_t, bt) -
		  STRUCT_OFFSET_OF (tcp_connection_t, fr_occurences)),
	       "hsi tcp tracker pending state must fit in unused tcp fields");
STATIC_ASSERT ((STRUCT_OFFSET_OF (tcp_connection_t, fr_occurences) %
		__alignof__ (hsi_tcp_tracker_t)) == 0,
	       "hsi tcp tracker overlay must be aligned");

typedef struct hsi_udp_tracker_
{
  ip46_address_t lcl_ip;
  ip46_address_t rmt_ip;
  u32 fib_index;
  u16 lcl_port;
  u16 rmt_port;
} hsi_udp_tracker_t;

typedef struct hsi_udp_tracker_pending_
{
  u32 magic;
  u32 flags;
} hsi_udp_tracker_pending_t;

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

static_always_inline hsi_worker_t *
hsi_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (hsi_main.wrk, thread_index);
}

static_always_inline hsi_tcp_tracker_t *
hsi_tcp_tracker_from_connection (tcp_connection_t *tc)
{
  return (hsi_tcp_tracker_t *) &tc->fr_occurences;
}

static_always_inline hsi_tcp_tracker_pending_t *
hsi_tcp_tracker_pending_from_connection (tcp_connection_t *tc)
{
  return (hsi_tcp_tracker_pending_t *) &tc->fr_occurences;
}

static inline hsi_tcp_tracker_t *
hsi_tcp_tracker_get (tcp_connection_t *tc)
{
  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  return hsi_tcp_tracker_from_connection (tc);
}

static_always_inline int
hsi_tcp_tracker_is_pending (tcp_connection_t *tc)
{
  hsi_tcp_tracker_pending_t *trk;

  trk = hsi_tcp_tracker_pending_from_connection (tc);
  return trk->magic == HSI_TCP_TRACKER_MAGIC && (trk->flags & HSI_TCP_TRACKER_F_PENDING);
}

static_always_inline void
hsi_tcp_tracker_pending_set (tcp_connection_t *tc, hsi_tcp_track_snapshot_t *snapshot)
{
  hsi_tcp_tracker_pending_t *trk;

  trk = hsi_tcp_tracker_pending_from_connection (tc);
  trk->magic = HSI_TCP_TRACKER_MAGIC;
  trk->flags = HSI_TCP_TRACKER_F_PENDING;
  trk->snapshot = *snapshot;
}

static_always_inline hsi_tcp_track_snapshot_t *
hsi_tcp_tracker_pending_snapshot (tcp_connection_t *tc)
{
  hsi_tcp_tracker_pending_t *trk;

  ASSERT (hsi_tcp_tracker_is_pending (tc));
  trk = hsi_tcp_tracker_pending_from_connection (tc);
  return &trk->snapshot;
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

static_always_inline hsi_udp_tracker_pending_t *
hsi_udp_tracker_pending_from_connection (udp_connection_t *uc)
{
  return (hsi_udp_tracker_pending_t *) &uc->bytes_in;
}

static_always_inline int
hsi_udp_tracker_is_pending (udp_connection_t *uc)
{
  hsi_udp_tracker_pending_t *trk = hsi_udp_tracker_pending_from_connection (uc);

  return trk->magic == HSI_UDP_TRACKER_MAGIC && (trk->flags & HSI_UDP_TRACKER_F_PENDING);
}

static_always_inline void
hsi_udp_tracker_pending_set (udp_connection_t *uc)
{
  hsi_udp_tracker_pending_t *trk = hsi_udp_tracker_pending_from_connection (uc);

  trk->magic = HSI_UDP_TRACKER_MAGIC;
  trk->flags = HSI_UDP_TRACKER_F_PENDING;
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

static_always_inline int
hsi_track_sessions_compatible (session_t *s, session_t *peer_s)
{
  if (!peer_s || s == peer_s)
    return 0;
  if (s->session_type != peer_s->session_type)
    return 0;
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING ||
      peer_s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return 0;

  return 1;
}

static void
hsi_tcp_track_snapshot (session_t *s, tcp_connection_t *tc, hsi_tcp_track_snapshot_t *snap)
{
  snap->session_handle = session_handle (s);
  snap->conn_index = tc->c_c_index;
  snap->thread_index = tc->c_thread_index;
  snap->fib_index = tc->c_fib_index;
  snap->lcl_ip = tc->c_lcl_ip;
  snap->rmt_ip = tc->c_rmt_ip;
  snap->lcl_port = tc->c_lcl_port;
  snap->rmt_port = tc->c_rmt_port;
  snap->snd_nxt = tc->snd_nxt;
  snap->rcv_nxt = tc->rcv_nxt;
  snap->ts_now = tcp_tstamp (tc);
  snap->tsval_recent = tc->tsval_recent;
  snap->rcv_wscale = tc->rcv_wscale;
  snap->snd_wscale = tc->snd_wscale;
}

static_always_inline int
hsi_tcp_track_connections_compatible (tcp_connection_t *tc0, tcp_connection_t *tc1)
{
  if (tc0->c_is_ip4 != tc1->c_is_ip4)
    return 0;
  if (!!tcp_opts_tstamp (&tc0->rcv_opts) != !!tcp_opts_tstamp (&tc1->rcv_opts))
    return 0;
  if (!!tcp_opts_sack_permitted (&tc0->rcv_opts) != !!tcp_opts_sack_permitted (&tc1->rcv_opts))
    return 0;

  return 1;
}

static_always_inline int
hsi_tcp_track_is_possible (tcp_connection_t *tc0, tcp_connection_t *tc1, u8 allow_tc1_pending)
{
  if (hsi_tcp_tracker_is_pending (tc0))
    return 0;
  if (tc1->cfg_flags & TCP_CFG_F_TRACKED)
    return 0;
  if (hsi_tcp_tracker_is_pending (tc1) && !allow_tc1_pending)
    return 0;

  return hsi_tcp_track_connections_compatible (tc0, tc1);
}

static void
hsi_tcp_tracker_init (hsi_tcp_tracker_t *trk, tcp_connection_t *tc, hsi_tcp_track_snapshot_t *peer)
{
  clib_memset (trk, 0, sizeof (*trk));

  trk->peer_conn_index = peer->conn_index;
  trk->peer_thread_index = peer->thread_index;
  trk->fib_index = peer->fib_index;
  trk->lcl_ip = peer->lcl_ip;
  trk->rmt_ip = peer->rmt_ip;
  trk->lcl_port = peer->lcl_port;
  trk->rmt_port = peer->rmt_port;

  /*
   * Packets received on tc are sent using peer's local/remote tuple. At
   * commit, tc->rcv_nxt maps to peer->snd_nxt and tc->snd_nxt maps to
   * peer->rcv_nxt.
   */
  trk->seq_delta = (i32) (peer->snd_nxt - tc->rcv_nxt);
  trk->ack_delta = (i32) (peer->rcv_nxt - tc->snd_nxt);
  trk->tsval_delta = (i32) (peer->ts_now - tc->tsval_recent);
  trk->tsecr_delta = (i32) (peer->tsval_recent - tcp_tstamp (tc));
  trk->wnd_delta = (i8) tc->snd_wscale - (i8) peer->rcv_wscale;
}

static void
hsi_tcp_track_commit_connection (tcp_connection_t *tc, hsi_tcp_track_snapshot_t *peer)
{
  hsi_tcp_tracker_init (hsi_tcp_tracker_from_connection (tc), tc, peer);

  tc->cfg_flags |= TCP_CFG_F_TRACKED;
}

static void
hsi_tcp_track_commit (session_t *s, hsi_tcp_track_snapshot_t *peer)
{
  tcp_connection_t *tc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  tc = hsi_tcp_connection_at_session (s);
  tcp_connection_timers_reset (tc);
  tcp_cong_recovery_off (tc);
  hsi_tcp_track_commit_connection (tc, peer);
}

static void
hsi_tcp_track_commit_req_free_rpc (void *arg)
{
  hsi_tcp_track_commit_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->tcp_track_commit_reqs, a);
}

static void
hsi_tcp_track_commit_rpc (void *arg)
{
  hsi_tcp_track_commit_req_t *a = arg;
  tcp_connection_t *tc;

  tc = hsi_tcp_connection_at_index (vlib_get_thread_index (), a->conn_index);
  tcp_connection_timers_reset (tc);
  tcp_cong_recovery_off (tc);
  hsi_tcp_track_commit_connection (tc, &a->peer);
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_track_commit_req_free_rpc, a);
}

static int
hsi_tcp_track_send_commit (session_t *peer_s, hsi_tcp_track_snapshot_t *peer)
{
  hsi_tcp_track_commit_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index;

  thread_index = peer->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ());
  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->tcp_track_commit_reqs, a);

  a->owner_thread = thread_index;
  a->conn_index = peer_s->connection_index;
  a->peer = *peer;
  session_send_rpc_evt_to_thread (peer_s->thread_index, hsi_tcp_track_commit_rpc, a);

  return 0;
}

static int
hsi_tcp_track_session_pair (session_t *s, session_t *peer_s)
{
  tcp_connection_t *tc0, *tc1;
  hsi_tcp_track_snapshot_t snap0, snap1;
  u8 is_same_thread;

  tc0 = hsi_tcp_connection_at_session (s);
  tc1 = hsi_tcp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;

  ASSERT (!(tc0->cfg_flags & TCP_CFG_F_TRACKED));

  if (!hsi_tcp_track_is_possible (tc0, tc1, !is_same_thread))
    return -1;

  if (is_same_thread)
    {
      hsi_tcp_track_snapshot (s, tc0, &snap0);
      hsi_tcp_track_snapshot (peer_s, tc1, &snap1);

      hsi_tcp_track_commit (s, &snap1);
      hsi_tcp_track_commit (peer_s, &snap0);

      return 0;
    }

  if (!hsi_tcp_tracker_is_pending (tc1))
    {
      hsi_tcp_track_snapshot (s, tc0, &snap0);
      hsi_tcp_tracker_pending_set (tc0, &snap0);
      return 0;
    }

  hsi_tcp_track_snapshot (s, tc0, &snap0);
  snap1 = *hsi_tcp_tracker_pending_snapshot (tc1);

  if (hsi_tcp_track_send_commit (peer_s, &snap0))
    return -1;

  hsi_tcp_track_commit (s, &snap1);

  return 0;
}

static void
hsi_udp_tracker_init (hsi_udp_tracker_t *trk, udp_connection_t *uc, hsi_udp_track_snapshot_t *peer)
{
  clib_memset (trk, 0, sizeof (*trk));

  trk->fib_index = peer->fib_index;
  trk->lcl_ip = peer->lcl_ip;
  trk->rmt_ip = peer->rmt_ip;
  trk->lcl_port = peer->lcl_port;
  trk->rmt_port = peer->rmt_port;
}

static void
hsi_udp_track_snapshot (session_t *s, udp_connection_t *uc, hsi_udp_track_snapshot_t *snap)
{
  snap->session_handle = session_handle (s);
  snap->conn_index = uc->c_c_index;
  snap->thread_index = uc->c_thread_index;
  snap->fib_index = uc->c_fib_index;
  snap->lcl_ip = uc->c_lcl_ip;
  snap->rmt_ip = uc->c_rmt_ip;
  snap->lcl_port = uc->c_lcl_port;
  snap->rmt_port = uc->c_rmt_port;
  snap->is_ip4 = uc->c_is_ip4;
}

static_always_inline int
hsi_udp_track_connections_compatible (udp_connection_t *uc0, udp_connection_t *uc1)
{
  if (uc0->c_is_ip4 != uc1->c_is_ip4)
    return 0;

  return 1;
}

static_always_inline int
hsi_udp_track_is_possible (udp_connection_t *uc0, udp_connection_t *uc1, u8 allow_uc1_pending)
{
  if (!(uc0->flags & UDP_CONN_F_CONNECTED) || !(uc1->flags & UDP_CONN_F_CONNECTED))
    return 0;
  if (hsi_udp_tracker_is_pending (uc0))
    return 0;
  if (uc1->cfg_flags & UDP_CFG_F_TRACKED)
    return 0;
  if (hsi_udp_tracker_is_pending (uc1) && !allow_uc1_pending)
    return 0;

  return hsi_udp_track_connections_compatible (uc0, uc1);
}

static void
hsi_udp_track_prepare (session_t *s, udp_connection_t *uc, hsi_udp_track_snapshot_t *snap)
{
  hsi_udp_track_snapshot (s, uc, snap);
  hsi_udp_tracker_pending_set (uc);
}

static void
hsi_udp_track_commit_connection (udp_connection_t *uc, hsi_udp_track_snapshot_t *peer)
{
  hsi_udp_tracker_init (hsi_udp_tracker_from_connection (uc), uc, peer);

  uc->cfg_flags |= UDP_CFG_F_TRACKED;
}

static void
hsi_udp_track_commit (session_t *s, hsi_udp_track_snapshot_t *peer)
{
  udp_connection_t *uc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  uc = hsi_udp_connection_at_session (s);
  hsi_udp_track_commit_connection (uc, peer);
}

static int
hsi_udp_track_session_pair (session_t *s, session_t *peer_s)
{
  hsi_udp_track_snapshot_t snap0, snap1;
  udp_connection_t *uc0, *uc1;
  u8 is_same_thread;

  uc0 = hsi_udp_connection_at_session (s);
  uc1 = hsi_udp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;

  ASSERT (!(uc0->cfg_flags & UDP_CFG_F_TRACKED));

  if (!hsi_udp_track_is_possible (uc0, uc1, !is_same_thread))
    return -1;

  if (is_same_thread)
    {
      hsi_udp_track_snapshot (s, uc0, &snap0);
      hsi_udp_track_snapshot (peer_s, uc1, &snap1);

      hsi_udp_track_commit (s, &snap1);
      hsi_udp_track_commit (peer_s, &snap0);

      return 0;
    }

  if (!hsi_udp_tracker_is_pending (uc1))
    {
      hsi_udp_track_prepare (s, uc0, &snap0);
      return 0;
    }

  hsi_udp_track_snapshot (peer_s, uc1, &snap1);
  hsi_udp_track_prepare (s, uc0, &snap0);

  hsi_udp_track_commit_connection (uc0, &snap1);
  hsi_udp_track_commit_connection (uc1, &snap0);

  return 0;
}

__clib_export int
hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle)
{
  session_handle_tu_t peer_handle = { .handle = peer_session_handle };
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  session_t *peer_s;
  transport_proto_t proto;

  if (!s || peer_session_handle == SESSION_INVALID_HANDLE)
    return -1;

  if (thread_index != s->thread_index)
    return -1;

  if (peer_handle.thread_index >= vec_len (session_main.wrk))
    return -1;

  peer_s = session_get_from_handle_safe (peer_handle);
  if (!hsi_track_sessions_compatible (s, peer_s))
    return -1;

  proto = session_get_transport_proto (s);
  switch (proto)
    {
    case TRANSPORT_PROTO_TCP:
      return hsi_tcp_track_session_pair (s, peer_s);
    case TRANSPORT_PROTO_UDP:
      return hsi_udp_track_session_pair (s, peer_s);
    default:
      return -1;
    }
}

static_always_inline u16
hsi_tcp_translate_window (u16 window, hsi_tcp_tracker_t *trk)
{
  u32 wnd = clib_net_to_host_u16 (window);

  if (trk->wnd_delta > 0)
    wnd = clib_min (wnd << trk->wnd_delta, 0xffff);
  else if (trk->wnd_delta < 0)
    wnd >>= -trk->wnd_delta;

  return clib_host_to_net_u16 ((u16) wnd);
}

static_always_inline void
hsi_tcp_rewrite_options (tcp_header_t *tcp_hdr, hsi_tcp_tracker_t *trk)
{
  u8 *data = (u8 *) (tcp_hdr + 1);
  u8 *end = (u8 *) tcp_hdr + tcp_header_bytes (tcp_hdr);
  u8 kind, opt_len;
  u32 v;

  while (data < end)
    {
      kind = data[0];
      if (kind == TCP_OPTION_EOL)
	break;
      if (kind == TCP_OPTION_NOOP)
	{
	  data += 1;
	  continue;
	}

      if (data + 1 >= end)
	break;

      opt_len = data[1];
      if (opt_len < 2 || data + opt_len > end)
	break;

      if (kind == TCP_OPTION_TIMESTAMP && opt_len == TCP_OPTION_LEN_TIMESTAMP)
	{
	  v = clib_mem_unaligned (data + 2, u32);
	  v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->tsval_delta);
	  clib_mem_unaligned (data + 2, u32) = v;

	  v = clib_mem_unaligned (data + 6, u32);
	  if (v)
	    v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->tsecr_delta);
	  clib_mem_unaligned (data + 6, u32) = v;
	}
      else if (kind == TCP_OPTION_SACK_BLOCK && opt_len >= 10 &&
	       !((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
	{
	  u8 *sack = data + 2;

	  while (sack + TCP_OPTION_LEN_SACK_BLOCK <= data + opt_len)
	    {
	      v = clib_mem_unaligned (sack, u32);
	      v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->ack_delta);
	      clib_mem_unaligned (sack, u32) = v;

	      v = clib_mem_unaligned (sack + 4, u32);
	      v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->ack_delta);
	      clib_mem_unaligned (sack + 4, u32) = v;

	      sack += TCP_OPTION_LEN_SACK_BLOCK;
	    }
	}

      data += opt_len;
    }
}

void
hsi_tcp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc,
				   void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4)
{
  hsi_tcp_tracker_t *trk;
  u32 seq, ack;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  trk = hsi_tcp_tracker_get (tc);

  seq = clib_net_to_host_u32 (tcp_hdr->seq_number);
  tcp_hdr->seq_number = clib_host_to_net_u32 (seq + trk->seq_delta);

  if (tcp_ack (tcp_hdr))
    {
      ack = clib_net_to_host_u32 (tcp_hdr->ack_number);
      tcp_hdr->ack_number = clib_host_to_net_u32 (ack + trk->ack_delta);
    }

  tcp_hdr->window = hsi_tcp_translate_window (tcp_hdr->window, trk);
  if (tcp_header_bytes (tcp_hdr) > sizeof (*tcp_hdr))
    hsi_tcp_rewrite_options (tcp_hdr, trk);

  tcp_hdr->src_port = trk->lcl_port;
  tcp_hdr->dst_port = trk->rmt_port;
  vnet_buffer (b)->ip.fib_index = trk->fib_index;
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->l4_hdr_offset = (u8 *) tcp_hdr - b->data;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;

      ip4->src_address = trk->lcl_ip.ip4;
      ip4->dst_address = trk->rmt_ip.ip4;
      ip4->checksum = ip4_header_checksum (ip4);
      tcp_hdr->checksum = 0;
      tcp_hdr->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
      b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP6;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					    VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      int bogus = 0;

      ip6->src_address = trk->lcl_ip.ip6;
      ip6->dst_address = trk->rmt_ip.ip6;
      tcp_hdr->checksum = 0;
      tcp_hdr->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
      b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP4;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
    }

  trk->packets += 1;
  trk->bytes += vlib_buffer_length_in_chain (vm, b);
}

void
hsi_udp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc,
				   void *ip_hdr, udp_header_t *udp_hdr, u8 is_ip4)
{
  hsi_udp_tracker_t *trk;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  trk = hsi_udp_tracker_get (uc);

  udp_hdr->src_port = trk->lcl_port;
  udp_hdr->dst_port = trk->rmt_port;
  vnet_buffer (b)->ip.fib_index = trk->fib_index;
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->l4_hdr_offset = (u8 *) udp_hdr - b->data;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;

      ip4->src_address = trk->lcl_ip.ip4;
      ip4->dst_address = trk->rmt_ip.ip4;
      ip4->checksum = ip4_header_checksum (ip4);
      udp_hdr->checksum = 0;
      udp_hdr->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
      if (udp_hdr->checksum == 0)
	udp_hdr->checksum = 0xffff;
      b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP6;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					    VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      int bogus = 0;

      ip6->src_address = trk->lcl_ip.ip6;
      ip6->dst_address = trk->rmt_ip.ip6;
      udp_hdr->checksum = 0;
      udp_hdr->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
      if (udp_hdr->checksum == 0)
	udp_hdr->checksum = 0xffff;
      b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP4;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
    }
}
