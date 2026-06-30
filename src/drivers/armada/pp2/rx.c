/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

static_always_inline u64
mvpp2_rx_desc_get_cookie (mvpp2_rx_desc_t *desc)
{
  return ((u64) desc->buf_virt_ptr_hi << 32) | desc->buf_virt_ptr_lo;
}

static_always_inline u16
mvpp2_rx_desc_get_pkt_len (mvpp2_rx_desc_t *desc)
{
  return desc->byte_count - MV_MH_SIZE;
}

static_always_inline uword
mrvl_pp2_rx_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rx_queue_if_rt_data_t *if_rt_data = vnet_dev_get_rx_queue_if_rt_data (rxq);
  vnet_main_t *vnm = vnet_get_main ();
  uintptr_t hif_base = md->threads[vm->thread_index].hif.base;
  u32 buffer_indices[VLIB_FRAME_SIZE];
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE + 4], **b = buffers;
  u16 packet_lengths[VLIB_FRAME_SIZE];
  vlib_buffer_template_t bt = if_rt_data->buffer_template;
  u32 next_index = if_rt_data->next_index;
  u32 sw_if_index = if_rt_data->sw_if_index;
  u64 n_rx_bytes = 0;
  u16 n_desc = VLIB_FRAME_SIZE;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 n_trace, n_left;
  u16 *pl;
  u16 rxq_size = rxq->size;
  u32 first_desc_index;
  u32 desc_index;

  /* Refresh cached RX descriptor count from hardware. */
  if (n_desc > mrq->desc_received)
    {
      mvpp22_rxq_status_reg_t status = {
	.as_u32 = mvpp2_reg_rd (hif_base, MVPP2_RXQ_STATUS_REG (mrq->hw_id)),
      };

      mrq->desc_received = status.occupied;
      n_desc = clib_min (n_desc, mrq->desc_received);
    }
  if (!n_desc)
    return 0;

  /* Extract buffer indices and packet lengths from RX descriptors. */
  first_desc_index = mrq->desc_next_idx;
  desc_index = first_desc_index;
  for (u32 i = 0; i < n_desc; i++)
    {
      mvpp2_rx_desc_t *desc = mrq->hw_descs + desc_index;

      buffer_indices[i] = mvpp2_rx_desc_get_cookie (desc);
      packet_lengths[i] = mvpp2_rx_desc_get_pkt_len (desc);
      if (++desc_index == rxq_size)
	desc_index = 0;
    }
  mrq->desc_next_idx = desc_index;

  /* Resolve buffer indices once and pad the prefetch tail. */
  vlib_get_buffers (vm, buffer_indices, b, n_desc);
  b[n_desc] = b[n_desc + 1] = b[n_desc + 2] = b[n_desc + 3] = b[n_desc - 1];

  /* Initialize received buffers four at a time. */
  bt.current_data = 2;
  for (n_left = n_desc, pl = packet_lengths; n_left >= 4; b += 4, pl += 4, n_left -= 4)
    {
      clib_prefetch_store (b[4]);
      clib_prefetch_store (b[5]);
      clib_prefetch_store (b[6]);
      clib_prefetch_store (b[7]);
      b0 = b[0];
      b1 = b[1];
      b2 = b[2];
      b3 = b[3];
      b0->template = bt;
      b1->template = bt;
      b2->template = bt;
      b3->template = bt;

      n_rx_bytes += b0->current_length = pl[0];
      n_rx_bytes += b1->current_length = pl[1];
      n_rx_bytes += b2->current_length = pl[2];
      n_rx_bytes += b3->current_length = pl[3];
    }

  /* Initialize the remaining received buffers. */
  for (; n_left; b++, pl++, n_left--)
    {
      b0 = b[0];
      b0->template = bt;

      n_rx_bytes += b0->current_length = pl[0];
    }

  /* Add trace records for selected packets. */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node)) > 0))
    {
      desc_index = first_desc_index;
      for (u32 i = 0; i < n_desc && n_trace > 0; i++)
	{
	  mvpp2_rx_desc_t *desc = mrq->hw_descs + desc_index;
	  vlib_buffer_t *b = buffers[i];

	  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0)))
	    {
	      mvpp2_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));

	      *tr = (mvpp2_rx_trace_t) {
		.desc = *desc,
		.next_index = next_index,
		.sw_if_index = sw_if_index,
	      };
	      n_trace--;
	    }
	  if (++desc_index == rxq_size)
	    desc_index = 0;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  /* Return consumed RX descriptors to hardware. */
  mvpp2_reg_wr (hif_base, MVPP2_RXQ_STATUS_UPDATE_REG (mrq->hw_id),
		(mvpp22_rxq_status_reg_t) {
		  .occupied = n_desc,
		  .available = n_desc,
		}
		  .as_u32);
  mrq->desc_received -= n_desc;
  mrq->n_bpool_refill += n_desc;

  /* Enqueue packets to the next node and update interface counters. */
  vlib_buffer_enqueue_to_single_next (vm, node, buffer_indices, next_index, n_desc);
  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_desc, n_rx_bytes);

  return n_desc;
}

static_always_inline u32
mrvl_pp2_bpool_put (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *n_alloc_fail)
{
  mvpp2_device_t *md = vnet_dev_get_data (rxq->port->dev);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  mvpp2_tx_desc_t desc = mrq->bpool_desc_template;
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  mvpp2_hif_t *hif = &thread->hif;
  u32 *desc_rsrvd = md->lbk_desc_rsrvd + vm->thread_index;
  uintptr_t hif_base = hif->base;
  const u32 batch_size = MRVL_PP2_BUFF_BATCH_SZ;
  u32 n_free = hif->n_free;
  u32 ring_size = hif->n_desc;
  u32 next = hif->next;
  u32 buffer_indices[batch_size];
  vlib_buffer_t *buffers[batch_size];
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 n_desc;
  u32 i, n_put = 0;

  /* Wait until a full refill batch is needed. */
  if (mrq->n_bpool_refill < batch_size)
    return 0;

  /* Refresh cached HIF descriptor availability if needed. */
  if (n_free < mrq->n_bpool_refill)
    {
      u32 occ_desc = mvpp2_reg_rd (hif_base, MVPP2_AGGR_TXQ_STATUS_REG (hif->id));
      n_free = ring_size - (occ_desc & MVPP2_AGGR_TXQ_PENDING_MASK);
    }

  n_desc = clib_min (mrq->n_bpool_refill, n_free);

  /* Reserve loopback TXQ descriptor credits. */
  if (n_desc >= batch_size && *desc_rsrvd < n_desc)
    {
      mvpp22_txq_rsvd_req_reg_t request = {
	.count = clib_max (n_desc - *desc_rsrvd, MVPP2_CPU_DESC_CHUNK),
	.queue = MVPP2_LOOPBACK_TXQ_ID,
      };
      u32 val;

      val =
	mvpp2_reg_wr_rd (hif_base, MVPP2_TXQ_RSVD_REQ_REG, request.as_u32, MVPP2_TXQ_RSVD_RSLT_REG);
      val &= MVPP2_TXQ_RSVD_RSLT_MASK;
      val += *desc_rsrvd;
      *desc_rsrvd = val;
      n_desc = clib_min (n_desc, val);
    }

  /* Allocate buffers and write loopback descriptors in batches. */
  for (; n_desc >= batch_size; n_desc -= batch_size)
    {
      if (PREDICT_FALSE (!vlib_buffer_strict_alloc_from_pool (vm, buffer_indices, batch_size,
							      buffer_pool_index)))
	{
	  (*n_alloc_fail)++;
	  break;
	}

      vlib_get_buffers (vm, buffer_indices, buffers, batch_size);

      for (i = 0; i < batch_size; i++)
	{
	  u64 addr = vlib_buffer_get_pa (vm, buffers[i]) - 64;

	  desc.buf_phys_ptr_lo = addr;
	  desc.buf_phys_ptr_hi = addr >> 32;
	  desc.buf_virt_ptr_lo = buffer_indices[i];
	  hif->descs[next] = desc;
	  if (++next == ring_size)
	    next = 0;
	}
      n_put += batch_size;
    }

  /* Commit HIF descriptor state and notify hardware. */
  *desc_rsrvd -= n_put;
  hif->n_free = n_free - n_put;
  hif->next = next;

  if (n_put)
    mvpp2_reg_wr (hif_base, MVPP2_AGGR_TXQ_UPDATE_REG, n_put);

  /* Account completed buffer pool refill. */
  mrq->n_bpool_refill -= n_put;
  return n_put;
}

u32
mrvl_pp2_bpool_put_no_inline (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  u32 n_alloc_fail = 0;

  return mrvl_pp2_bpool_put (vm, rxq, &n_alloc_fail);
}

VNET_DEV_NODE_FN (mvpp2_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  u32 n_alloc_fail = 0;
  u32 node_index = node->node_index;

  /* Poll RX queues and refill their buffer pools. */
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += mrvl_pp2_rx_inline (vm, node, rxq);
      mrvl_pp2_bpool_put (vm, rxq, &n_alloc_fail);
    }

  /* Report buffer allocation failures from refill. */
  if (n_alloc_fail)
    vlib_error_count (vm, node_index, MVPP2_RX_NODE_CTR_BUFFER_ALLOC, n_alloc_fail);
  return n_rx;
}
