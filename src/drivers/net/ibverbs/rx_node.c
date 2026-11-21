/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/counters.h>
#include <ibverbs.h>

static_always_inline u8
ibv_rx_maybe_ip4 (vlib_buffer_t *b)
{
  ethernet_header_t *e = vlib_buffer_get_current (b);
  u16 type = clib_net_to_host_u16 (e->type);

  return type == ETHERNET_TYPE_IP4 || type == ETHERNET_TYPE_VLAN || type == ETHERNET_TYPE_DOT1AD ||
	 type == ETHERNET_TYPE_VLAN_9100 || type == ETHERNET_TYPE_VLAN_9200;
}

static_always_inline void
ibv_rxq_refill (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 bsz = IBV_RX_REFILL_BATCH_SZ, mask = rxq->size - 1, n_ds = iq->n_ds;
  u32 alloc[IBV_RX_REFILL_BATCH_SZ * IBV_RXQ_MAX_CHAIN_SZ];
  u16 tail = iq->tail;

  while ((u16) (rxq->size - (u16) (tail - iq->head)) >= bsz)
    {
      ibv_rx_refill_entry_t *re = iq->refill_entries;
      struct ibv_recv_wr *bad_wr = 0;
      u32 slot = tail & mask, n_alloc = 0, n_posted, k = 0;

      for (u32 i = 0; i < bsz; i++)
	n_alloc += iq->n_used[slot + i];

      if (n_alloc && !vlib_buffer_strict_alloc_from_pool (vm, alloc, n_alloc, bpi))
	{
	  vlib_error_count (vm, node->node_index, IBV_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      for (u32 i = 0; i < bsz; i++)
	{
	  u32 *bufs = iq->buffers + (slot + i) * IBV_RXQ_MAX_CHAIN_SZ;

	  for (u32 j = 0; j < iq->n_used[slot + i]; j++)
	    /* coverity[uninit_use] - alloc holds n_alloc buffers, the sum of n_used */
	    bufs[j] = alloc[k++];
	  iq->n_used[slot + i] = 0;
	  for (u32 j = 0; j < n_ds; j++)
	    re[i].sge[j].addr = pointer_to_uword (vlib_get_buffer (vm, bufs[j])->data);
	}

      if (ibv_post_wq_recv (iq->ibv_wq, &re[0].recv_wr, &bad_wr))
	{
	  vlib_error_count (vm, node->node_index, IBV_RX_NODE_CTR_IBV_POST_RECV, 1);
	  n_posted = bad_wr ? (ibv_rx_refill_entry_t *) bad_wr - re : 0;
	  tail += n_posted;
	  break;
	}

      tail += bsz;
    }

  iq->tail = tail;
}

static_always_inline u32
ibv_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		  int single_buffer)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 mask = rxq->size - 1, buf_sz = iq->buf_sz;
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 to_drop[VLIB_FRAME_SIZE], *to_next, n_left_to_next, n_trace;
  u32 n_rx = 0, n_drop = 0, n_rx_bytes = 0;
  u8 ip4_unverified = 0;
  u16 head = iq->head, head0 = iq->head;
  int n;

  n = ibv_poll_cq (iq->ibv_cq, VLIB_FRAME_SIZE, wc);
  if (PREDICT_FALSE (n < 0))
    vlib_error_count (vm, node->node_index, IBV_RX_NODE_CTR_IBV_POLL_CQ, 1);
  if (n <= 0)
    return 0;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  for (u32 i = 0; i < n; i++, head++)
    {
      u32 slot = head & mask;
      u32 *bufs = iq->buffers + slot * IBV_RXQ_MAX_CHAIN_SZ;
      vlib_buffer_t *b = vlib_get_buffer (vm, bufs[0]);
      u32 len = wc[i].byte_len, n_segs = 1;

      if (PREDICT_FALSE (wc[i].status != IBV_WC_SUCCESS))
	{
	  b->template = bt;
	  to_drop[n_drop++] = bufs[0];
	  iq->n_used[slot] = 1;
	  if (iq->rx_error == 0)
	    {
	      iq->rx_error_status = wc[i].status;
	      iq->rx_error = 1;
	    }
	  continue;
	}

      b->template = bt;
      if (single_buffer)
	{
	  iq->n_used[slot] = 1;
	  b->current_length = len;
	}
      else
	{
	  n_segs = clib_max ((len + buf_sz - 1) / buf_sz, 1);
	  iq->n_used[slot] = n_segs;
	  b->current_length = clib_min (len, buf_sz);
	}
      if (!single_buffer && PREDICT_FALSE (n_segs > 1))
	{
	  vlib_buffer_t *cb = b;

	  b->total_length_not_including_first_buffer = len - b->current_length;
	  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  for (u32 j = 1; j < n_segs; j++)
	    {
	      cb->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      cb->next_buffer = bufs[j];
	      cb = vlib_get_buffer (vm, bufs[j]);
	      cb->template = bt;
	      cb->current_length = clib_min (len - j * buf_sz, buf_sz);
	    }
	}
      n_rx_bytes += len;
      if (wc[i].wc_flags & IBV_WC_IP_CSUM_OK)
	b->flags |= VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT;
      else if (!ip4_unverified)
	ip4_unverified = ibv_rx_maybe_ip4 (b);
      to_next[n_rx++] = bufs[0];
    }

  iq->head = head;

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 *rx = to_next, *drop = to_drop;

      for (u32 i = 0; i < n && n_trace; i++)
	{
	  u32 bi = wc[i].status == IBV_WC_SUCCESS ? *rx++ : *drop++;
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);

	  if (vlib_trace_buffer (vm, node, next_index, b, 0))
	    {
	      u32 slot = (u16) (head0 + i) & mask, n_sge = iq->n_ds;
	      u32 *sb = iq->buffers + slot * IBV_RXQ_MAX_CHAIN_SZ;
	      ibv_rx_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr) + n_sge * sizeof (struct ibv_sge));
	      tr->next_index = next_index;
	      tr->qid = rxq->queue_id;
	      tr->hw_if_index = hw_if_index;
	      tr->wc = wc[i];
	      tr->buffer_flags = b->flags;
	      tr->slot = slot;
	      tr->n_sge = n_sge;
	      for (u32 j = 0; j < n_sge; j++)
		tr->sge[j] = (struct ibv_sge) {
		  .addr = pointer_to_uword (vlib_get_buffer (vm, sb[j])->data),
		  .length = buf_sz,
		  .lkey = iq->refill_entries[0].sge[0].lkey,
		};
	      n_trace--;
	    }
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_FALSE (n_drop))
    {
      vlib_buffer_free (vm, to_drop, n_drop);
      vlib_error_count (vm, node->node_index, IBV_RX_NODE_CTR_DESC_ERROR, n_drop);
    }

  if (PREDICT_FALSE (n_rx == 0))
    {
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      return 0;
    }

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);

      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      if (!ip4_unverified)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx);

  vlib_increment_combined_counter (vnet_get_main ()->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_rx, n_rx_bytes);

  return n_rx;
}

VNET_DEV_NODE_FN (ibv_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      if (PREDICT_FALSE (iq->rx_error > 1))
	continue;
      if (iq->single_buffer)
	rv += ibv_rx_one_queue (vm, node, rxq, 1);
      else
	rv += ibv_rx_one_queue (vm, node, rxq, 0);
      if (PREDICT_FALSE (iq->rx_error))
	{
	  iq->rx_error = 2;
	  continue;
	}
      ibv_rxq_refill (vm, node, rxq);
    }

  return rv;
}
