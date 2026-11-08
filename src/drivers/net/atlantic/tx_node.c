/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ip/ip4_packet.h>
#include <atlantic.h>

#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>

#define ATL_TX_CSO_IP4 1
#define ATL_TX_CSO_L4  2
#define ATL_TX_GSO     4

#define ATL_TX_MAX_SEGS	    8
#define ATL_TX_MAX_GSO_SEGS 32

static_always_inline u32
atl_tx_prepare_offload (vlib_buffer_t *b, atl_tx_ctx_desc_t *ctx)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;
  u32 cso = 0;

  if (PREDICT_FALSE (b->flags & VNET_BUFFER_F_GSO))
    {
      i16 l3_hdr_offset = vnet_buffer (b)->l3_hdr_offset;
      i16 l4_hdr_offset = vnet_buffer (b)->l4_hdr_offset;
      tcp_header_t *tcp = (void *) (b->data + l4_hdr_offset);
      u32 is_ip4 = b->flags & VNET_BUFFER_F_IS_IP4;
      u32 l2 = l3_hdr_offset - b->current_data, l3 = l4_hdr_offset - l3_hdr_offset;
      u32 l4 = tcp_header_bytes (tcp), mss = vnet_buffer2 (b)->gso_size;

      *ctx = (atl_tx_ctx_desc_t) {
	.type_txc = 1,
	.ipv6 = !is_ip4,
	.tcp = 1,
	.l2_len = l2,
	.l3_len_lo = l3 & 1,
	.l3_len_hi = l3 >> 1,
	.l4_len = l4,
	.mss = mss,
      };

      if (is_ip4)
	((ip4_header_t *) (b->data + l3_hdr_offset))->checksum = 0;
      return ATL_TX_GSO | ATL_TX_CSO_L4 | (is_ip4 ? ATL_TX_CSO_IP4 : 0);
    }

  if (oflags & (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    cso |= ATL_TX_CSO_L4;

  if ((b->flags & VNET_BUFFER_F_IS_IP4) && (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM))
    {
      ip4_header_t *ip4 = (void *) (b->data + vnet_buffer (b)->l3_hdr_offset);

      ip4->checksum = 0;
      cso |= ATL_TX_CSO_IP4;
    }

  return cso;
}

static_always_inline u32
atl_tx_one_batch (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_t *dev,
		  vnet_dev_tx_queue_t *txq, u32 *bi_ring, u16 mask, u32 *from, u32 n_pkts,
		  u16 *tail_ptr, u32 *drop_indices, u32 *n_drop_ptr)
{
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  atl_tx_desc_t desc;
  u16 seg_len[8 * 32];
  void *seg_data[8 * 32];
  u32 seg_bi[8 * 32];
  u16 pkt_first_seg[32];
  u32 pkt_len[32];
  u8 pkt_cso[32];
  atl_tx_ctx_desc_t pkt_ctx[32];
  u32 n_drop = *n_drop_ptr;
  u32 n = 0;
  u16 tail = *tail_ptr;
  u16 n_free = txq->size - 1 - (tail - aq->head_index);
  u32 n_enq = 0;
  u32 n_seg = 0;

  for (u32 p = 0; p < n_pkts; p++)
    {
      u32 buffer_index = from[p];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, buffer_index);
      u32 total_len = 0;
      u32 n_desc = 0;

      u32 max_segs = (b0->flags & VNET_BUFFER_F_GSO) ? ATL_TX_MAX_GSO_SEGS : ATL_TX_MAX_SEGS;

      if (n_free < ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? max_segs + 1 : 1) ||
	  n_seg + max_segs > ARRAY_LEN (seg_len))
	break;

      pkt_cso[n_enq] = 0;
      if (PREDICT_FALSE (b0->flags & (VNET_BUFFER_F_OFFLOAD | VNET_BUFFER_F_GSO)))
	pkt_cso[n_enq] = atl_tx_prepare_offload (b0, &pkt_ctx[n_enq]);

      pkt_first_seg[n_enq] = n_seg;

      for (;;)
	{
	  seg_bi[n_seg] = buffer_index;
	  seg_len[n_seg] = b0->current_length;
	  seg_data[n_seg] = vlib_buffer_get_current (b0);
	  total_len += b0->current_length;
	  n_seg++;
	  n_desc++;

	  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	    break;

	  if (PREDICT_FALSE (n_desc == max_segs))
	    {
	      drop_indices[n_drop++] = from[p];
	      n++;
	      goto next_pkt;
	    }

	  buffer_index = b0->next_buffer;
	  b0 = vlib_get_buffer (vm, buffer_index);
	}

      pkt_len[n_enq] = total_len;

      if (PREDICT_FALSE (pkt_cso[n_enq] & ATL_TX_GSO))
	{
	  u16 slot = tail & mask;
	  u32 hbi = seg_bi[pkt_first_seg[n_enq]];

	  aq->descs[slot].qwords[0] = pkt_ctx[n_enq].qwords[0];
	  aq->descs[slot].qwords[1] = pkt_ctx[n_enq].qwords[1];
	  bi_ring[slot] = hbi;
	  vlib_get_buffer (vm, hbi)->ref_count++;
	  tail++;
	  n_free--;
	  pkt_len[n_enq] -= pkt_ctx[n_enq].l2_len +
			    (pkt_ctx[n_enq].l3_len_hi << 1 | pkt_ctx[n_enq].l3_len_lo) +
			    pkt_ctx[n_enq].l4_len;
	}

      for (u32 i = 0; i < n_desc; i++)
	{
	  u32 seg_index = pkt_first_seg[n_enq] + i;
	  u8 is_last = (i + 1) == n_desc;
	  u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, seg_data[seg_index]);
	  u16 slot = tail & mask;
	  u32 bi = seg_bi[seg_index];

	  desc = (atl_tx_desc_t) {
	    .addr = dma_addr,
	    .type_txd = 1,
	    .blen = seg_len[seg_index],
	    .eop = is_last,
	    .len = pkt_len[n_enq],
	    .ip4csum = (i == 0) & (pkt_cso[n_enq] & ATL_TX_CSO_IP4),
	    .l4csum = (i == 0) & !!(pkt_cso[n_enq] & ATL_TX_CSO_L4),
	    .lso = !!(pkt_cso[n_enq] & ATL_TX_GSO),
	    .ctx_en = !!(pkt_cso[n_enq] & ATL_TX_GSO),
	  };

	  aq->descs[slot] = desc;
	  bi_ring[slot] = bi;
	  tail++;
	}

      n_free -= n_desc;
      n_enq++;
      n++;

      if (n_free == 0)
	break;

    next_pkt:;
    }

  *n_drop_ptr = n_drop;
  *tail_ptr = tail;
  return n;
}

static void
atl_tx_trace_frame (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
		    u32 n_bufs, u32 n_processed, u16 first, u16 tail)
{
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  u16 mask = txq->size - 1;

  for (u32 i = 0; i < n_bufs; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u16 n_desc = 0;
      atl_tx_trace_t *t;

      if (first != tail && aq->buffer_indices[first & mask] == from[i])
	{
	  n_desc = aq->descs[first & mask].type_txc;
	  do
	    n_desc++;
	  while (aq->descs[(first + n_desc - 1) & mask].eop == 0);
	}

      if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
	{
	  first += n_desc;
	  continue;
	}

      t = vlib_add_trace (vm, node, b, sizeof (*t) + n_desc * sizeof (t->desc[0]));
      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      t->buffer_index = from[i];
      t->queue_id = txq->queue_id;
      t->n_desc = n_desc;
      if (n_desc)
	t->error = 0;
      else if (i >= n_processed)
	t->error = node->errors[ATL_TX_NODE_CTR_NO_FREE_SLOTS];
      else
	t->error = node->errors[ATL_TX_NODE_CTR_CHAIN_TOO_LONG];
      for (u32 j = 0; j < n_desc; j++)
	t->desc[j] = aq->descs[(first + j) & mask];
      first += n_desc;
    }
}

VNET_DEV_NODE_FN (atl_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vnet_dev_t *dev = txq->port->dev;
  atl_txq_t *aq = vnet_dev_get_tx_queue_data (txq);
  u32 *from = vlib_frame_vector_args (frame);
  u32 *const frame_from = from;
  u32 *bi_ring = aq->buffer_indices;
  u32 n_left = frame->n_vectors;
  u32 drop_indices[VLIB_FRAME_SIZE];
  u32 n_drop = 0;
  u32 n;
  u16 mask = txq->size - 1;
  u16 head;
  u16 tail;
  u16 old_tail;
  u16 n_used;
  u16 n_free;

  vnet_dev_tx_queue_lock_if_needed (txq);
  head = atl_reg_rd_u32 (dev, ATL_REG_TX_DMA_DESC_HEAD_PTR (txq->queue_id));
  n_free = (head - aq->head_index) & mask;
  if (n_free)
    {
      vlib_buffer_free_from_ring_no_next (vm, bi_ring, aq->head_index & mask, txq->size, n_free);
      aq->head_index += n_free;
    }

  n_used = aq->tail_index - aq->head_index;
  n_free = txq->size - 1 - n_used;

  old_tail = aq->tail_index;
  tail = old_tail;

  if (n_free == 0)
    goto no_space;

  while (n_left >= 32)
    {
      n = atl_tx_one_batch (vm, node, dev, txq, bi_ring, mask, from, 32, &tail, drop_indices,
			    &n_drop);
      from += n;
      n_left -= n;
      if (n < 32)
	break;
    }

  if (n_left)
    {
      n = atl_tx_one_batch (vm, node, dev, txq, bi_ring, mask, from, n_left, &tail, drop_indices,
			    &n_drop);
      from += n;
      n_left -= n;
    }

  aq->tail_index = tail;
  if (tail != old_tail)
    __atomic_store_n (aq->tail_reg, tail & mask, __ATOMIC_RELEASE);

no_space:
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    atl_tx_trace_frame (vm, node, txq, frame_from, frame->n_vectors, frame->n_vectors - n_left,
			old_tail, tail);

  if (n_drop)
    {
      vlib_buffer_free (vm, drop_indices, n_drop);
      vlib_error_count (vm, node->node_index, ATL_TX_NODE_CTR_CHAIN_TOO_LONG, n_drop);
    }

  if (n_left)
    {
      vlib_buffer_free (vm, from, n_left);
      vlib_error_count (vm, node->node_index, ATL_TX_NODE_CTR_NO_FREE_SLOTS, n_left);
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  return frame->n_vectors - n_left;
}
