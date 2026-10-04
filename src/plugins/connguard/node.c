/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_xddos Application Filter (VPP mode) packet path: records
 * the TCP connections of admin-listed protected services (server IP +
 * port) so connguard.c's once-a-second scan can find slow
 * application-layer attacks (Slowloris, slow POST, slow read, idle
 * connection holding) per connection, and counts each protected server's
 * SYN / SYN-ACK / RST exchanged with WAN-side clients for Server Health
 * Detection. VPP counterpart of
 * ebpf/xdp_bridge/kern/xdp_bridge.c's app_filter_track — same recorded
 * fields, same meaning, see that function's map doc comment.
 *
 * Two nodes, attached ONLY to LAN-role interfaces (servers are on the LAN
 * side, clients on the WAN side) and only while the feature is enabled —
 * disabled, neither node is on any packet's path at all:
 *
 *   connguard-out  ("interface-output" arc of a LAN interface): client →
 *                  server packets that arrived on a WAN-role interface, at
 *                  the moment they are actually transmitted to the server.
 *                  Running on the output side, after the ACL / classify /
 *                  policer stages, means a SYN those stages dropped is
 *                  never counted — it never reached the server, so it
 *                  must not lower the server's SYN-ACK response ratio.
 *                  Client packets of a connection the scan has reset are
 *                  dropped here.
 *   connguard-in   ("device-input" arc of a LAN interface): server →
 *                  client packets (SYN-ACK, RST, FIN, data).
 *
 * WAN interfaces get nothing. On a LAN interface, a packet that isn't TCP
 * to or from a protected service costs one bihash lookup.
 *
 * conns[] is a fixed, 2-way set-associative slot table rather than a
 * bihash: worker threads create entries and update them in place without
 * any lock or memory allocation, and a colliding new connection simply
 * takes over the older slot — the equivalent of the XDP side's LRU
 * eviction. Races between two workers on one slot can only make a
 * heuristic reading slightly off, never corrupt memory; readers always
 * re-check the 4-tuple.
 *
 * A client SYN only goes into the separate halfopen[] table (same
 * design); the connection enters conns[] — the table everything is judged
 * on — once the client ACKs the server's SYN-ACK, which a spoofed source
 * never does. So a spoofed-source SYN flood can't push tracked
 * connections out, and a half-open connection is never judged (see
 * kern/xdp_bridge.c's app_halfopen_map for the live finding behind this).
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/feature/feature.h>

#include <connguard/connguard.h>

typedef enum
{
  CONNGUARD_NEXT_DROP,
  CONNGUARD_N_NEXT,
} connguard_next_t;

static_always_inline int
connguard_slot_match (connguard_conn_t *c, u32 cip, u32 sip, u16 cp, u16 sp)
{
  return c->state != CONNGUARD_FREE && c->client_ip == cip &&
	 c->server_ip == sip && c->client_port == cp && c->server_port == sp;
}

static_always_inline connguard_conn_t *
connguard_slot_find (connguard_main_t *cm, u32 cip, u32 sip, u16 cp, u16 sp)
{
  u32 base = connguard_slot_base (cip, sip, cp, sp);
  connguard_conn_t *c0 = &cm->conns[base];
  connguard_conn_t *c1 = &cm->conns[base + 1];

  if (connguard_slot_match (c0, cip, sip, cp, sp))
    return c0;
  if (connguard_slot_match (c1, cip, sip, cp, sp))
    return c1;
  return 0;
}

/* connguard_slot_victim: how willing a slot is to be taken over by a new
 * connection — higher is more willing. */
static_always_inline u64
connguard_slot_victim (connguard_conn_t *c, u64 now)
{
  switch (c->state)
    {
    case CONNGUARD_FREE:
    case CONNGUARD_CLOSED:
      return ~0ULL;
    case CONNGUARD_KILLED:
      if (now - c->wait_start_ns >= CONNGUARD_KILLED_KEEP_NS)
	return ~0ULL;
      return 0; /* still dropping the reset client's packets */
    case CONNGUARD_SYN:
      if (now - c->start_ns >= CONNGUARD_SYN_STALE_NS)
	return ~0ULL - 1;
      break;
    default:
      break;
    }
  return now - c->start_ns; /* otherwise the older one */
}

static_always_inline connguard_conn_t *
connguard_slot_claim (connguard_main_t *cm, u64 now, u32 cip, u32 sip, u16 cp,
		      u16 sp)
{
  u32 base = connguard_slot_base (cip, sip, cp, sp);
  connguard_conn_t *c0 = &cm->conns[base];
  connguard_conn_t *c1 = &cm->conns[base + 1];

  if (connguard_slot_match (c0, cip, sip, cp, sp))
    return c0;
  if (connguard_slot_match (c1, cip, sip, cp, sp))
    return c1;
  return connguard_slot_victim (c1, now) > connguard_slot_victim (c0, now) ?
	   c1 :
	   c0;
}

static_always_inline int
connguard_ho_match (connguard_halfopen_t *o, u32 cip, u32 sip, u16 cp, u16 sp)
{
  return o->used && o->client_ip == cip && o->server_ip == sip &&
	 o->client_port == cp && o->server_port == sp;
}

static_always_inline connguard_halfopen_t *
connguard_ho_find (connguard_main_t *cm, u32 cip, u32 sip, u16 cp, u16 sp)
{
  u32 base = connguard_halfopen_base (cip, sip, cp, sp);
  connguard_halfopen_t *o0 = &cm->halfopen[base];
  connguard_halfopen_t *o1 = &cm->halfopen[base + 1];

  if (connguard_ho_match (o0, cip, sip, cp, sp))
    return o0;
  if (connguard_ho_match (o1, cip, sip, cp, sp))
    return o1;
  return 0;
}

/* connguard_ho_claim: the pair's matching slot, else a free one, else the
 * older one. */
static_always_inline connguard_halfopen_t *
connguard_ho_claim (connguard_main_t *cm, u64 now, u32 cip, u32 sip, u16 cp,
		    u16 sp)
{
  u32 base = connguard_halfopen_base (cip, sip, cp, sp);
  connguard_halfopen_t *o0 = &cm->halfopen[base];
  connguard_halfopen_t *o1 = &cm->halfopen[base + 1];

  if (connguard_ho_match (o0, cip, sip, cp, sp))
    return o0;
  if (connguard_ho_match (o1, cip, sip, cp, sp))
    return o1;
  if (!o0->used)
    return o0;
  if (!o1->used)
    return o1;
  return (now - o1->start_ns) > (now - o0->start_ns) ? o1 : o0;
}

/* connguard_track: returns 1 when the packet must be dropped. is_c2s:
 * client → server (connguard-out); tx_sw_if_index is then the LAN
 * interface the server sits behind. */
static_always_inline int
connguard_track (vlib_main_t *vm, connguard_main_t *cm, vlib_buffer_t *b,
		 int is_c2s, u32 tx_sw_if_index)
{
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u8 *end = (u8 *) eth + b->current_length;

  if ((u8 *) (eth + 1) > end ||
      eth->type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    return 0;
  ip4_header_t *ip = (ip4_header_t *) (eth + 1);
  if ((u8 *) (ip + 1) > end || ip->protocol != IP_PROTOCOL_TCP)
    return 0;
  tcp_header_t *tcp = (tcp_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
  if ((u8 *) (tcp + 1) > end)
    return 0;

  u16 sport = clib_net_to_host_u16 (tcp->src_port);
  u16 dport = clib_net_to_host_u16 (tcp->dst_port);
  u32 cip, sip;
  u16 cp, sp;
  if (is_c2s)
    {
      cip = ip->src_address.as_u32;
      sip = ip->dst_address.as_u32;
      cp = sport;
      sp = dport;
    }
  else
    {
      cip = ip->dst_address.as_u32;
      sip = ip->src_address.as_u32;
      cp = dport;
      sp = sport;
    }

  clib_bihash_kv_8_8_t kv, val;
  kv.key = ((u64) sip << 32) | sp;
  if (clib_bihash_search_8_8 (&cm->svc_table, &kv, &val))
    return 0;
  u32 sidx = (u32) val.value;
  if (sidx >= CONNGUARD_MAX_SERVERS || vm->thread_index >= cm->n_threads)
    return 0;
  connguard_health_t *h =
    &cm->health[vm->thread_index * CONNGUARD_MAX_SERVERS + sidx];

  u32 hdr_len = ip4_header_bytes (ip) + tcp_header_bytes (tcp);
  u32 tot_len = clib_net_to_host_u16 (ip->length);
  u32 plen = tot_len > hdr_len ? tot_len - hdr_len : 0;
  u8 fl = tcp->flags;
  u64 now = connguard_now_ns (vm);
  connguard_conn_t *c;

  if (is_c2s)
    {
      if ((fl & TCP_FLAG_SYN) && !(fl & TCP_FLAG_ACK))
	{
	  h->syn++;
	  connguard_halfopen_t *o =
	    connguard_ho_claim (cm, now, cip, sip, cp, sp);
	  /* Free the slot first so a concurrent reader never matches a
	   * half-written 4-tuple, publish it last. */
	  o->used = 0;
	  CLIB_MEMORY_STORE_BARRIER ();
	  o->client_ip = cip;
	  o->server_ip = sip;
	  o->client_port = cp;
	  o->server_port = sp;
	  o->synacked = 0;
	  o->rcv_nxt = clib_net_to_host_u32 (tcp->seq_number) + 1;
	  o->server_sw_if_index = tx_sw_if_index;
	  o->start_ns = now;
	  clib_memcpy_fast (o->dst_mac, eth->dst_address, 6);
	  clib_memcpy_fast (o->src_mac, eth->src_address, 6);
	  CLIB_MEMORY_STORE_BARRIER ();
	  o->used = 1;
	  return 0;
	}
      c = connguard_slot_find (cm, cip, sip, cp, sp);
      if (!c)
	{
	  /* The client's ACK of the server's SYN-ACK completes the
	   * handshake: only now does the connection get tracked. */
	  if (!(fl & TCP_FLAG_ACK) ||
	      (fl & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN)))
	    return 0;
	  connguard_halfopen_t *o = connguard_ho_find (cm, cip, sip, cp, sp);
	  if (!o || !o->synacked)
	    return 0;
	  c = connguard_slot_claim (cm, now, cip, sip, cp, sp);
	  c->state = CONNGUARD_FREE;
	  CLIB_MEMORY_STORE_BARRIER ();
	  c->client_ip = cip;
	  c->server_ip = sip;
	  c->client_port = cp;
	  c->server_port = sp;
	  c->flags = 0;
	  c->server_idx = (u8) sidx;
	  c->rcv_nxt = o->rcv_nxt;
	  c->wait_bytes = 0;
	  c->wait_segs = 0;
	  c->server_sw_if_index = o->server_sw_if_index;
	  c->start_ns = o->start_ns;
	  c->wait_start_ns = 0;
	  c->zero_win_ns = 0;
	  clib_memcpy_fast (c->dst_mac, o->dst_mac, 6);
	  clib_memcpy_fast (c->src_mac, o->src_mac, 6);
	  CLIB_MEMORY_STORE_BARRIER ();
	  c->state = CONNGUARD_EST;
	  o->used = 0;
	}
      if (c->state == CONNGUARD_KILLED)
	return 1;
      if (c->state == CONNGUARD_CLOSED)
	return 0;
      if (fl & (TCP_FLAG_RST | TCP_FLAG_FIN))
	{
	  c->state = CONNGUARD_CLOSED;
	  return 0;
	}
      if (tcp->window == 0)
	{
	  if (!c->zero_win_ns)
	    c->zero_win_ns = now;
	}
      else if (c->zero_win_ns)
	c->zero_win_ns = 0;
      if (plen > 0)
	{
	  u32 seg_end = clib_net_to_host_u32 (tcp->seq_number) + plen;
	  if ((i32) (seg_end - c->rcv_nxt) > 0)
	    {
	      c->rcv_nxt = seg_end;
	      c->flags |= CONNGUARD_F_CLIENT_DATA;
	      if (!c->wait_start_ns)
		{
		  c->wait_start_ns = now;
		  c->wait_bytes = 0;
		  c->wait_segs = 0;
		}
	      c->wait_bytes += plen;
	      c->wait_segs++;
	    }
	}
      return 0;
    }

  /* server → client. A SYN-ACK or RST counts toward Server Health only
   * when it answers a WAN client's connection (a halfopen[] or conns[]
   * entry exists), the same basis the SYN counter has — see
   * kern/xdp_bridge.c's app_filter_track. */
  if ((fl & TCP_FLAG_SYN) && (fl & TCP_FLAG_ACK))
    {
      connguard_halfopen_t *o = connguard_ho_find (cm, cip, sip, cp, sp);
      if (o)
	{
	  h->synack++;
	  o->synacked = 1;
	}
      return 0;
    }
  if (fl & TCP_FLAG_RST)
    {
      c = connguard_slot_find (cm, cip, sip, cp, sp);
      if (c || connguard_ho_find (cm, cip, sip, cp, sp))
	h->rst++;
      if (c && c->state != CONNGUARD_KILLED)
	c->state = CONNGUARD_CLOSED;
      return 0;
    }
  if (!(fl & TCP_FLAG_FIN) && plen == 0)
    return 0; /* pure ACK: nothing to record */
  c = connguard_slot_find (cm, cip, sip, cp, sp);
  if (!c || c->state == CONNGUARD_KILLED)
    return 0;
  if (fl & TCP_FLAG_FIN)
    {
      c->state = CONNGUARD_CLOSED;
      return 0;
    }
  /* The server answered: whatever the client was sending is complete. */
  if (c->wait_start_ns)
    {
      c->wait_start_ns = 0;
      c->wait_bytes = 0;
      c->wait_segs = 0;
    }
  return 0;
}

static_always_inline uword
connguard_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int is_out)
{
  connguard_main_t *cm = &connguard_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 n_dropped = 0;
  int enabled = cm->enabled && cm->conns != 0 && cm->halfopen != 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u32 next0;
      int drop0 = 0;

      if (n_left > 2)
	{
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  CLIB_PREFETCH (b[2]->data + b[2]->current_data,
			 CLIB_CACHE_LINE_BYTES, LOAD);
	}

      vnet_feature_next (&next0, b[0]);

      if (PREDICT_TRUE (enabled))
	{
	  if (is_out)
	    {
	      u32 rx = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      if (rx < vec_len (cm->role_by_sw_if_index) &&
		  cm->role_by_sw_if_index[rx] == CONNGUARD_ROLE_WAN)
		drop0 = connguard_track (
		  vm, cm, b[0], 1, vnet_buffer (b[0])->sw_if_index[VLIB_TX]);
	    }
	  else
	    connguard_track (vm, cm, b[0], 0, 0);
	}

      if (PREDICT_FALSE (drop0))
	{
	  next0 = CONNGUARD_NEXT_DROP;
	  n_dropped++;
	}
      next[0] = (u16) next0;

      b++;
      next++;
      n_left--;
    }

  if (n_dropped)
    vlib_increment_simple_counter (&cm->dropped_counters, vm->thread_index, 0,
				   n_dropped);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (connguard_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return connguard_node_inline (vm, node, frame, 1 /* is_out */);
}

VLIB_NODE_FN (connguard_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return connguard_node_inline (vm, node, frame, 0 /* is_out */);
}

VLIB_REGISTER_NODE (connguard_out_node) = {
  .name = "connguard-out",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = CONNGUARD_N_NEXT,
  .next_nodes = {
    [CONNGUARD_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (connguard_in_node) = {
  .name = "connguard-in",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = CONNGUARD_N_NEXT,
  .next_nodes = {
    [CONNGUARD_NEXT_DROP] = "error-drop",
  },
};
