/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vppinfra/vector/ip_csum.h>

#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>

#include <vnet/ip/ip_psh_cksum.h>
#include <ige.h>

#define IGE_TX_MAX_SEGS	    16
#define IGE_TX_MAX_GSO_SEGS 40

#define IGE_TX_POPTS_IXSM 1
#define IGE_TX_POPTS_TXSM 2

#define IGE_TX_L4T_UDP 0
#define IGE_TX_L4T_TCP 1

static_always_inline u32
ige_tx_prepare_offload (vlib_buffer_t *b, ige_tx_ctx_desc_t *ctx)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
  u32 is_tcp = oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
  u32 is_udp = oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
  u32 is_gso = b->flags & VNET_BUFFER_F_GSO;
  u32 is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
  i16 l3_hdr_offset = vnet_buffer (b)->l3_hdr_offset;
  ip4_header_t *ip4 = (void *) (b->data + l3_hdr_offset);
  ip6_header_t *ip6 = (void *) (b->data + l3_hdr_offset);
  u32 popts = 0;

  if (is_gso && !is_tcp && !is_udp)
    {
      u8 proto = is_ip4 ? ip4->protocol : ip6->protocol;

      is_tcp = proto == IP_PROTOCOL_TCP;
      is_udp = proto == IP_PROTOCOL_UDP;
    }

  *ctx = (ige_tx_ctx_desc_t) {
    .maclen = l3_hdr_offset - b->current_data,
    .ipv4 = is_ip4 != 0,
    .dtyp = 2,
    .dext = 1,
  };

  if (is_tcp || is_udp)
    {
      i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset;
      u16 l3_len = l4_hdr_offset - l3_hdr_offset;
      u16 sum;

      if (is_gso)
	{
	  ctx->mss = vnet_buffer2 (b)->gso_size;
	  if (is_ip4)
	    ip4->length = 0;
	  else
	    ip6->payload_length = 0;
	}

      if (is_ip4)
	{
	  ip4_psh_t psh = {
	    .src = ip4->src_address,
	    .dst = ip4->dst_address,
	    .proto = ip4->protocol,
	    .l4len =
	      is_gso ? 0 : clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) - l3_len),
	  };
	  sum = ~clib_ip_csum ((u8 *) &psh, sizeof (psh));
	}
      else
	{
	  ip6_psh_t psh = {
	    .src = ip6->src_address,
	    .dst = ip6->dst_address,
	    .l4len = is_gso ? 0 :
			      clib_host_to_net_u32 (clib_net_to_host_u16 (ip6->payload_length) -
						    (l3_len - sizeof (*ip6))),
	    .proto = clib_host_to_net_u32 (is_tcp ? IP_PROTOCOL_TCP : IP_PROTOCOL_UDP),
	  };
	  sum = ~clib_ip_csum ((u8 *) &psh, sizeof (psh));
	}

      ctx->iplen = l3_len;
      if (is_tcp)
	{
	  tcp_header_t *tcp = (void *) (b->data + l4_hdr_offset);

	  tcp->checksum = sum;
	  ctx->l4t = IGE_TX_L4T_TCP;
	  ctx->l4len = tcp_header_bytes (tcp);
	}
      else
	{
	  ((udp_header_t *) (b->data + l4_hdr_offset))->checksum = sum;
	  ctx->l4t = IGE_TX_L4T_UDP;
	  ctx->l4len = sizeof (udp_header_t);
	}
      popts |= IGE_TX_POPTS_TXSM;
    }
  else if (is_ip4)
    ctx->iplen = ip4_header_bytes (ip4);

  if (is_ip4 && (is_gso || (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)))
    {
      ip4->checksum = 0;
      popts |= IGE_TX_POPTS_IXSM;
    }

  return popts;
}

static_always_inline void
ige_enq_ctx (vlib_buffer_t *b, u32 bi, ige_tx_ctx_desc_t *ctx, ige_tx_desc_t *descs,
	     u32 *buffer_indices, u16 *tail, u16 mask)
{
  u32 slot = *tail & mask;

  descs[slot].qwords[0] = ctx->qwords[0];
  descs[slot].qwords[1] = ctx->qwords[1];
  buffer_indices[slot] = bi;
  b->ref_count++;
  (*tail)++;
}

static_always_inline void
ige_enq_txd (vlib_main_t *vm, vlib_buffer_t *b, u32 bi, int first, int last, u32 pkt_len, u32 popts,
	     u32 tso_hdr_len, ige_tx_desc_t *descs, u32 *buffer_indices, u16 *tail, u16 mask,
	     int use_va)
{
  u32 len = b->current_length;
  u32 slot = *tail & mask;
  ige_tx_desc_t d = {
    .eop = last ? 1 : 0,
    .rs = last ? 1 : 0,
    .ifcs = 1,
    .dext = 1,
    .dtyp = 0b0011,
    .dtalen = len,
  };
  d.addr = use_va ? vlib_buffer_get_current_va (b) :
		    vlib_buffer_get_current_pa (vm, b);
  if (first)
    {
      d.paylen = pkt_len;
      d.popts = popts;
      if (tso_hdr_len)
	{
	  d.paylen = pkt_len - tso_hdr_len;
	  d.tse = 1;
	}
    }

  descs[slot] = d;
  buffer_indices[slot] = bi;
  (*tail)++;
}

static_always_inline void
ige_txq_complete (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  ige_txq_t *itq = vnet_dev_get_tx_queue_data (txq);

  u16 head = itq->head;
  u16 tail = itq->tail;
  u16 n_free;

  if (head == tail)
    return;

  u32 new_head = __atomic_load_n (itq->wb, __ATOMIC_ACQUIRE);
  u16 mask = txq->size - 1;
  n_free = (new_head - head) & mask;

  if (!n_free)
    return;

  vlib_buffer_free_from_ring_no_next (vm, itq->buffer_indices, head & mask,
				      txq->size, n_free);

  itq->head = head + n_free;
}

static_always_inline u32
ige_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	     u32 max_pkts, int va, u32 *drop_too_long, u32 *n_drop_too_long)
{
  ige_txq_t *const itq = vnet_dev_get_tx_queue_data (txq);
  ige_tx_desc_t *const d = itq->descs;
  u32 *const bi = itq->buffer_indices;
  const u16 size = txq->size;
  const u16 mask = size - 1;
  u16 n_pkts = 0;

  ige_txq_complete (vm, txq);

  u16 head = itq->head;
  u16 tail = itq->tail;
  u16 n_free = size - 1 - (u16) (tail - head);

  while (n_pkts < max_pkts && n_free)
    {
      u32 hbi = from[n_pkts];
      vlib_buffer_t *b = vlib_get_buffer (vm, hbi);
      ige_tx_ctx_desc_t ctx;
      u32 popts = 0;
      u32 n_ctx = 0;
      u32 tso_hdr_len = 0;

      if (PREDICT_FALSE (b->flags & (VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_GSO)))
	{
	  popts = ige_tx_prepare_offload (b, &ctx);
	  n_ctx = popts != 0;
	  if (ctx.mss)
	    tso_hdr_len = ctx.maclen + ctx.iplen + ctx.l4len;
	}

      if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  vlib_buffer_t *tb = b;
	  u32 pkt_len = b->current_length;
	  u32 n = 1, tbi;
	  u32 max_segs = tso_hdr_len ? IGE_TX_MAX_GSO_SEGS : IGE_TX_MAX_SEGS;

	  while (tb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      if (n >= max_segs)
		{
		  drop_too_long[(*n_drop_too_long)++] = hbi;
		  goto next;
		}
	      tb = vlib_get_buffer (vm, tb->next_buffer);
	      pkt_len += tb->current_length;
	      n++;
	    }

	  if (n + n_ctx > n_free)
	    break;

	  if (n_ctx)
	    ige_enq_ctx (b, hbi, &ctx, d, bi, &tail, mask);
	  ige_enq_txd (vm, b, hbi, 1, 0, pkt_len, popts, tso_hdr_len, d, bi, &tail, mask, va);
	  tbi = b->next_buffer;
	  tb = vlib_get_buffer (vm, tbi);
	  for (u32 i = 1; i < n; i++)
	    {
	      u32 nbi = tb->next_buffer;
	      int last = (i == n - 1);
	      ige_enq_txd (vm, tb, tbi, 0, last, 0, 0, 0, d, bi, &tail, mask, va);
	      if (!last)
		{
		  tbi = nbi;
		  tb = vlib_get_buffer (vm, tbi);
		}
	    }
	  n_free -= n + n_ctx;
	}
      else
	{
	  if (n_ctx + 1 > n_free)
	    break;

	  if (n_ctx)
	    ige_enq_ctx (b, hbi, &ctx, d, bi, &tail, mask);
	  ige_enq_txd (vm, b, hbi, 1, 1, b->current_length, popts, tso_hdr_len, d, bi, &tail, mask,
		       va);
	  n_free -= 1 + n_ctx;
	}

    next:
      n_pkts++;
    }

  if (itq->tail != tail)
    {
      __atomic_store_n (itq->reg_tdt, tail & mask, __ATOMIC_RELEASE);
      itq->tail = tail;
    }

  return n_pkts;
}

static void
ige_tx_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
		    u32 n_bufs, u32 n_processed, u16 first)
{
  ige_txq_t *itq = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1;
  u16 end = itq->tail;

  for (u32 i = 0; i < n_bufs; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u16 start = first;
      u16 n_desc = 0;
      ige_tx_trace_t *t;

      if (first != end && itq->buffer_indices[first & mask] == from[i])
	{
	  do
	    n_desc++;
	  while (itq->descs[(first + n_desc - 1) & mask].eop == 0);
	  first += n_desc;
	}

      if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
	continue;

      t = vlib_add_trace (vm, node, b, sizeof (*t) + n_desc * sizeof (t->desc[0]));
      t->hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
      t->queue_id = txq->queue_id;
      t->buffer_index = from[i];
      t->n_desc = n_desc;
      if (n_desc)
	t->error = 0;
      else if (i >= n_processed)
	t->error = node->errors[IGE_TX_NODE_CTR_NO_FREE_SLOTS];
      else
	t->error = node->errors[IGE_TX_NODE_CTR_BUFFER_CHAIN_TOO_LONG];
      for (u32 j = 0; j < n_desc; j++)
	t->desc[j] = itq->descs[(start + j) & mask];
    }
}

VNET_DEV_NODE_FN (ige_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  ige_txq_t *itq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 *const frame_from = from;
  u32 drop_too_long[VLIB_FRAME_SIZE];
  u32 n_drop_too_long = 0;
  u16 n, n_left, first_tail;
  int n_reties = 2;

  n_left = frame->n_vectors;

  vnet_dev_tx_queue_lock_if_needed (txq);
  first_tail = itq->tail;

  while (n_reties--)
    {
      if (dev->va_dma)
	n = ige_txq_enq (vm, node, txq, from, n_left, 1, drop_too_long, &n_drop_too_long);
      else
	n = ige_txq_enq (vm, node, txq, from, n_left, 0, drop_too_long, &n_drop_too_long);

      from += n;
      n_left -= n;

      if (n == 0 || n_left == 0)
	break;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    ige_tx_trace_frame (vm, node, txq, frame_from, frame->n_vectors, frame->n_vectors - n_left,
			first_tail);

  if (n_drop_too_long)
    {
      vlib_error_count (vm, node->node_index, IGE_TX_NODE_CTR_BUFFER_CHAIN_TOO_LONG,
			n_drop_too_long);
      vlib_buffer_free (vm, drop_too_long, n_drop_too_long);
    }

  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, IGE_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
