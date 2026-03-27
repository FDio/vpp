/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <cadence.h>

#define CDN_RX_REFILL_BATCH 64

static_always_inline u32
cdn_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_main_t *vnm = vnet_get_main ();
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 *to_next;
  uword n_left_to_next;
  u32 n_rx = 0;
  u32 n_rx_bytes = 0;
  u32 n_trace;
  cdn_rx_desc_ctrl_t w1s[VLIB_FRAME_SIZE], *w1 = w1s;
  u32 *buffer_indices = crq->buffer_indices;
  cdn_rx_desc_t *descs = crq->descs;
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u16 size = rxq->size;
  u16 mask = size - 1;
  u16 head = crq->head;
  u16 head_slot = head & mask;
  u16 slot = head & mask;
  u16 n_left;
  u16 n_slots = clib_min (VLIB_FRAME_SIZE, size - head_slot);
  cdn_rx_desc_t *d = descs + slot;
  u32 addr = __atomic_load_n (&d->addr.as_u32, __ATOMIC_ACQUIRE);

  if ((addr & 1) == 0)
    return 0;

  w1s[n_rx++] = d->ctrl;
  slot++;

  while (n_rx < n_slots)
    {
      d = descs + slot;
      addr = __atomic_load_n (&d->addr.as_u32, __ATOMIC_ACQUIRE);
      if ((addr & 1) == 0)
	break;

      w1s[n_rx] = d->ctrl;
      n_rx++;
      slot++;
    }

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  vlib_buffer_copy_indices (to_next, buffer_indices + head_slot, n_rx);
  vlib_get_buffers (vm, to_next, buffers, n_rx);
  b[n_rx] = b[n_rx + 1] = b[n_rx + 2] = b[n_rx + 3] = b[n_rx - 1];

  for (n_left = n_rx; n_left >= 4; w1 += 4, b += 4, n_left -= 4)
    {
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);

      b[0]->template = bt;
      b[1]->template = bt;
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);
      b[2]->template = bt;
      b[3]->template = bt;
      n_rx_bytes += b[0]->current_length = w1[0].frm_len;
      n_rx_bytes += b[1]->current_length = w1[1].frm_len;
      n_rx_bytes += b[2]->current_length = w1[2].frm_len;
      n_rx_bytes += b[3]->current_length = w1[3].frm_len;
    }

  for (; n_left > 0; w1 += 1, b += 1, n_left -= 1)
    {
      b[0]->template = bt;
      n_rx_bytes += b[0]->current_length = w1[0].frm_len;
    }

  n_trace = vlib_get_trace_count (vm, node);

  if (PREDICT_FALSE (n_trace))
    for (u32 i = 0; i < n_rx && n_trace; i++)
      {
	vlib_buffer_t *b = buffers[i];

	if (vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0))
	  {
	    cdn_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));

	    tr->word1 = w1s[i].as_u32;
	    tr->buffer_index = to_next[i];
	    tr->hw_if_index = hw_if_index;
	    tr->queue_id = rxq->queue_id;
	    tr->next_index = next_index;
	    n_trace--;
	  }
      }

  vlib_set_trace_count (vm, node, n_trace);

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);

      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  to_next += n_rx;
  n_left_to_next -= n_rx;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  crq->head = head + n_rx;

  if (n_rx)
    vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_RX,
				     vm->thread_index, sw_if_index, n_rx, n_rx_bytes);

  return n_rx;
}

static_always_inline void
cdn_rx_queue_repost (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 *buffer_indices = crq->buffer_indices;
  cdn_rx_desc_t *descs = crq->descs;
  u16 size = rxq->size;
  u16 mask = size - 1;
  u16 head = crq->head;
  u16 tail = crq->tail;
  u16 n_empty = head - tail;

  for (; n_empty >= CDN_RX_REFILL_BATCH;
       n_empty -= CDN_RX_REFILL_BATCH, tail += CDN_RX_REFILL_BATCH)
    {
      u16 slot0 = tail & mask;
      vlib_buffer_t *b;
      u64 dma_addr;
      u16 slot;

      if (vlib_buffer_strict_alloc_from_pool (vm, buffer_indices + slot0, CDN_RX_REFILL_BATCH,
					      bpi) == 0)
	{
	  vlib_error_count (vm, node->node_index, CDN_RX_NODE_CTR_NO_BUFFER, CDN_RX_REFILL_BATCH);
	  break;
	}

      for (u32 i = 1; i < CDN_RX_REFILL_BATCH; i++)
	{
	  slot = slot0 + i;
	  b = vlib_get_buffer (vm, buffer_indices[slot]);
	  dma_addr = vnet_dev_get_dma_addr (vm, dev, b->data);
	  u64x2 d = { dma_addr, 0 };
	  u32x4 v = u32x4_shuffle ((u32x4) d, 0, 2, 1, 3);

	  descs[slot].as_u32x4 = v;
	}

      /* Preserve the wrap bit on the final RX descriptor in the ring. */
      if (PREDICT_FALSE (slot == size - 1))
	descs[slot].addr.wrap = 1;

      b = vlib_get_buffer (vm, buffer_indices[slot0]);
      dma_addr = vnet_dev_get_dma_addr (vm, dev, b->data);

      descs[slot0].ctrl.as_u32 = 0;
      descs[slot0].addrh = dma_addr >> 32;
      descs[slot0].resvd = 0;
      __atomic_store_n (&descs[slot0].addr.as_u32, dma_addr, __ATOMIC_RELEASE);
    }

  crq->tail = tail;
}

VNET_DEV_NODE_FN (cdn_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 n_rx = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += cdn_rx_one_queue (vm, node, rxq);
      cdn_rx_queue_repost (vm, node, rxq);
    }

  return n_rx;
}
