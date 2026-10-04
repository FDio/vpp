/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_xddos ETA (VPP mode) packet path: copies TLS/QUIC
 * ClientHello packets to etad over a memif interface. Monitor only: the
 * original packet always continues unchanged. VPP counterpart of
 * ebpf/xdp_bridge/kern/xdp_bridge.c's eta_extract — same candidates, same
 * split-ClientHello following, same rate limit.
 *
 * One node, "eta", on the "interface-output" arc of the bridge interfaces
 * that have a role (wan/lan), attached only while ETA is enabled — disabled,
 * it is on no packet's path at all. Output side on purpose: like the XDP
 * stage (last in its IPv4 block), only packets actually forwarded are
 * looked at, so sources the ACL already blocks don't use up the extraction
 * budget during a flood.
 *
 * Per packet, an ordinary packet costs a few header compares:
 *   - TCP with payload starting 16 03 xx LL LL 01 (TLS handshake record,
 *     ClientHello): copied; if the record is longer than this segment, the
 *     flow is followed into its next segments through the per-thread slot
 *     table (looked at only while this thread has a slot in use);
 *   - UDP of at least ETA_QUIC_MIN_INITIAL payload bytes starting with a
 *     QUIC long header of type Initial: copied.
 * Copies are rate limited per thread (token bucket) and simply skipped
 * when out of tokens or buffers. libmerc (in etad) reassembles a split
 * ClientHello only from in-order segments: RSS keeps a flow on one worker,
 * and a worker's copies reach the memif queue in order.
 *
 * Each copy gets an eta_frame_hdr_t in front (headroom), telling etad the
 * receive interface and whether it is a WAN-role (inbound) one.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/feature/feature.h>

#include <eta/eta.h>

#define ETA_KIND_NONE	  0
#define ETA_KIND_TLS	  1
#define ETA_KIND_TLS_CONT 2
#define ETA_KIND_QUIC	  3

static_always_inline u32
eta_slot_index (u32 saddr, u32 daddr, u16 sport, u16 dport)
{
  u32 h = saddr ^ daddr ^ ((u32) sport << 16 | dport);
  h ^= h >> 16;
  h ^= h >> 8;
  return h & (ETA_FLOW_SLOTS - 1);
}

static_always_inline void
eta_slot_free (eta_per_thread_t *pt, eta_flow_slot_t *s)
{
  s->remaining = 0;
  if (pt->active_slots)
    pt->active_slots--;
}

/* eta_take_token: per-thread token bucket; 1 if the copy may go out,
 * else counts the skip in *n_limited. */
static_always_inline int
eta_take_token (eta_main_t *em, eta_per_thread_t *pt, f64 now, u32 *n_limited)
{
  if (em->rate == 0)
    return 1;
  f64 elapsed = now - pt->last;
  pt->last = now;
  pt->tokens += elapsed * em->rate_per_thread;
  if (pt->tokens > em->burst)
    pt->tokens = em->burst;
  if (pt->tokens < 1.0)
    {
      (*n_limited)++;
      return 0;
    }
  pt->tokens -= 1.0;
  return 1;
}

/* eta_classify: which kind of ClientHello candidate b is (ETA_KIND_*),
 * from header compares only — the per-packet hot path. Untagged IPv4 only,
 * like the XDP stage. */
static_always_inline int
eta_classify (eta_per_thread_t *pt, vlib_buffer_t *b)
{
  u8 *p = vlib_buffer_get_current (b);
  u32 len = b->current_length;

  if (PREDICT_FALSE (len < sizeof (ethernet_header_t) + sizeof (ip4_header_t)))
    return ETA_KIND_NONE;
  if (((ethernet_header_t *) p)->type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    return ETA_KIND_NONE;
  ip4_header_t *ip = (ip4_header_t *) (p + sizeof (ethernet_header_t));
  u32 ihl = ip4_header_bytes (ip);
  u32 off = sizeof (ethernet_header_t) + ihl;

  if (ip->protocol == IP_PROTOCOL_TCP)
    {
      if (PREDICT_FALSE (off + sizeof (tcp_header_t) > len))
	return ETA_KIND_NONE;
      u32 l4 = off + tcp_header_bytes ((tcp_header_t *) (p + off));
      /* no payload (pure ACK etc.), or payload not in this buffer */
      if (l4 >= len ||
	  clib_net_to_host_u16 (ip->length) + sizeof (ethernet_header_t) <= l4)
	return ETA_KIND_NONE;
      if (p[l4] == 0x16)
	return ETA_KIND_TLS;
      return pt->active_slots ? ETA_KIND_TLS_CONT : ETA_KIND_NONE;
    }
  if (ip->protocol == IP_PROTOCOL_UDP)
    {
      u32 pl = off + sizeof (udp_header_t);
      /* long header (0b11......), packet type Initial: 00 (v1) or 01 (v2) */
      if (pl < len &&
	  clib_net_to_host_u16 (ip->length) >= ihl + sizeof (udp_header_t) + ETA_QUIC_MIN_INITIAL &&
	  (p[pl] & 0xe0) == 0xc0)
	return ETA_KIND_QUIC;
    }
  return ETA_KIND_NONE;
}

/* eta_candidate: the slower checks for a candidate. Returns 1 if b is to
 * be copied (the token is already taken). */
static_always_inline int
eta_candidate (eta_main_t *em, eta_per_thread_t *pt, vlib_buffer_t *b,
	       int kind, f64 now, u32 *n_limited)
{
  u8 *p = vlib_buffer_get_current (b);
  u32 len = b->current_length;
  ip4_header_t *ip = (ip4_header_t *) (p + sizeof (ethernet_header_t));
  u32 ihl = ip4_header_bytes (ip);

  if (ip4_is_fragment (ip))
    return 0;

  if (kind == ETA_KIND_QUIC)
    {
      u32 off = sizeof (ethernet_header_t) + ihl + sizeof (udp_header_t);
      if (off + 5 > len)
	return 0;
      /* version 0 is Version Negotiation, not an Initial */
      if ((p[off + 1] | p[off + 2] | p[off + 3] | p[off + 4]) == 0)
	return 0;
      return eta_take_token (em, pt, now, n_limited);
    }

  tcp_header_t *t = (tcp_header_t *) ((u8 *) ip + ihl);
  u32 l4_hlen = ihl + tcp_header_bytes (t);
  u32 plen = clib_net_to_host_u16 (ip->length) - l4_hlen;
  u32 seq = clib_net_to_host_u32 (t->seq_number);
  u16 sport = clib_net_to_host_u16 (t->src_port);
  u16 dport = clib_net_to_host_u16 (t->dst_port);
  eta_flow_slot_t *s = &pt->slots[eta_slot_index (
    ip->src_address.as_u32, ip->dst_address.as_u32, sport, dport)];

  if (kind == ETA_KIND_TLS)
    {
      u32 off = sizeof (ethernet_header_t) + l4_hlen;
      if (off + 6 > len)
	return 0;
      /* 16 03 xx LL LL 01: handshake record, TLS 1.x, ClientHello */
      if (p[off + 1] != 0x03 || p[off + 5] != 0x01)
	return 0;
      if (!eta_take_token (em, pt, now, n_limited))
	return 0;
      u32 rec_total = 5 + ((u32) p[off + 3] << 8 | p[off + 4]);
      if (rec_total > plen)
	{
	  if (s->remaining == 0)
	    pt->active_slots++;
	  s->saddr = ip->src_address.as_u32;
	  s->daddr = ip->dst_address.as_u32;
	  s->sport = sport;
	  s->dport = dport;
	  s->next_seq = seq + plen;
	  s->remaining = rec_total - plen;
	  s->expire = now + ETA_FLOW_TIMEOUT;
	}
      return 1;
    }

  /* ETA_KIND_TLS_CONT */
  if (s->remaining == 0 || s->saddr != ip->src_address.as_u32 ||
      s->daddr != ip->dst_address.as_u32 || s->sport != sport ||
      s->dport != dport)
    return 0;
  /* libmerc needs the segments in order; anything else ends the attempt */
  if (now > s->expire || seq != s->next_seq || !eta_take_token (em, pt, now, n_limited))
    {
      eta_slot_free (pt, s);
      return 0;
    }
  if (plen >= s->remaining)
    eta_slot_free (pt, s);
  else
    {
      s->remaining -= plen;
      s->next_seq += plen;
    }
  return 1;
}

/* eta_slow: a ClientHello candidate (rare) — the remaining checks and the
 * copy, kept out of line so the per-packet loop stays small. */
static never_inline void
eta_slow (vlib_main_t *vm, eta_main_t *em, eta_per_thread_t *pt,
	  vlib_buffer_t *b, int kind, f64 *now, u32 *copies, u32 *n_copies,
	  u32 *n_limited, u32 *n_no_buffer)
{
  if (*now == 0)
    *now = vlib_time_now (vm);

  if (kind == ETA_KIND_TLS_CONT)
    {
      /* only a flow this thread follows */
      u8 *p = vlib_buffer_get_current (b);
      ip4_header_t *ip = (ip4_header_t *) (p + sizeof (ethernet_header_t));
      tcp_header_t *t = (tcp_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
      eta_flow_slot_t *s = &pt->slots[eta_slot_index (
	ip->src_address.as_u32, ip->dst_address.as_u32,
	clib_net_to_host_u16 (t->src_port), clib_net_to_host_u16 (t->dst_port))];
      if (s->remaining == 0 || s->saddr != ip->src_address.as_u32)
	return;
    }
  u32 rx = vnet_buffer (b)->sw_if_index[VLIB_RX];
  int inbound = rx < vec_len (em->role_by_sw_if_index) &&
		em->role_by_sw_if_index[rx] == ETA_ROLE_WAN;
  /* scope inbound: not from a WAN-role interface (e.g. LAN -> LAN) */
  if (em->inbound_only && !inbound)
    return;
  if (!eta_candidate (em, pt, b, kind, *now, n_limited))
    return;

  vlib_buffer_t *c = vlib_buffer_copy (vm, b);
  if (PREDICT_FALSE (c == 0))
    {
      (*n_no_buffer)++;
      return;
    }
  eta_frame_hdr_t *h;
  vlib_buffer_advance (c, -(word) sizeof (*h));
  h = vlib_buffer_get_current (c);
  h->magic = ETA_FRAME_MAGIC;
  h->sw_if_index = rx;
  h->flags = inbound ? ETA_FRAME_F_INBOUND : 0;
  h->reserved = 0;
  vnet_buffer (c)->sw_if_index[VLIB_TX] = em->output_sw_if_index;
  copies[(*n_copies)++] = vlib_get_buffer_index (vm, c);
}

VLIB_NODE_FN (eta_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  eta_main_t *em = &eta_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0, n_rate_limited = 0, n_no_buffer = 0;
  u32 thread_index = vm->thread_index;
  eta_per_thread_t *pt = vec_elt_at_index (em->per_thread, thread_index);
  f64 now = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  if (PREDICT_FALSE (!em->enabled))
    {
      /* being disabled: just pass everything on */
      while (n_left > 0)
	{
	  u32 next0;
	  vnet_feature_next (&next0, b[0]);
	  next[0] = (u16) next0;
	  b++;
	  next++;
	  n_left--;
	}
      goto done;
    }

  while (n_left >= 8)
    {
      u32 next0, next1, next2, next3;
      int k0, k1, k2, k3;

      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);
      CLIB_PREFETCH (vlib_buffer_get_current (b[4]), CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (vlib_buffer_get_current (b[5]), CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (vlib_buffer_get_current (b[6]), CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (vlib_buffer_get_current (b[7]), CLIB_CACHE_LINE_BYTES, LOAD);

      vnet_feature_next (&next0, b[0]);
      vnet_feature_next (&next1, b[1]);
      vnet_feature_next (&next2, b[2]);
      vnet_feature_next (&next3, b[3]);
      next[0] = (u16) next0;
      next[1] = (u16) next1;
      next[2] = (u16) next2;
      next[3] = (u16) next3;

      k0 = eta_classify (pt, b[0]);
      k1 = eta_classify (pt, b[1]);
      k2 = eta_classify (pt, b[2]);
      k3 = eta_classify (pt, b[3]);
      if (PREDICT_FALSE (k0 | k1 | k2 | k3))
	{
	  /* In packet order, classifying each again after the previous one
	   * was handled: a ClientHello's next segment in the same group is
	   * only a candidate once the first one has claimed its slot. */
	  int i;
	  for (i = 0; i < 4; i++)
	    {
	      int k = i == 0 ? k0 : eta_classify (pt, b[i]);
	      if (k)
		eta_slow (vm, em, pt, b[i], k, &now, copies, &n_copies,
			  &n_rate_limited, &n_no_buffer);
	    }
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      u32 next0;
      int k0;

      vnet_feature_next (&next0, b[0]);
      next[0] = (u16) next0;
      k0 = eta_classify (pt, b[0]);
      if (PREDICT_FALSE (k0))
	eta_slow (vm, em, pt, b[0], k0, &now, copies, &n_copies,
		  &n_rate_limited, &n_no_buffer);
      b++;
      next++;
      n_left--;
    }

done:
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (n_copies)
    {
      vnet_hw_interface_t *hw =
	vnet_get_sup_hw_interface (em->vnet_main, em->output_sw_if_index);
      vlib_frame_t *f = vlib_get_frame_to_node (vm, hw->output_node_index);
      clib_memcpy_fast (vlib_frame_vector_args (f), copies,
			n_copies * sizeof (u32));
      f->n_vectors = n_copies;
      vlib_put_frame_to_node (vm, hw->output_node_index, f);
      vlib_increment_simple_counter (&em->counters[ETA_CNT_EXPORTED],
				     thread_index, 0, n_copies);
    }
  if (n_rate_limited)
    vlib_increment_simple_counter (&em->counters[ETA_CNT_RATE_LIMITED],
				   thread_index, 0, n_rate_limited);
  if (n_no_buffer)
    vlib_increment_simple_counter (&em->counters[ETA_CNT_NO_BUFFER],
				   thread_index, 0, n_no_buffer);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (eta_node) = {
  .name = "eta",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};
