/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_rdma/ibv/ibv.h>

static_always_inline void
rdma_ibv_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  rdma_ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1;
  u16 ring_space = rxq->size - (iq->tail - iq->head);
  u32 slot = iq->tail & mask;
  u32 n_wr = 1u << RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ;
  u32 n_alloc = clib_min (n_wr, ring_space);
  u32 n, i;
  u32 *bufs = iq->buffers + slot;
  rdma_ibv_rx_refill_entry_t *re = iq->refill_entries;
  struct ibv_recv_wr *next_wr, *bad_wr = 0;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  if (n_alloc < 16)
    return;

  n_alloc = clib_min (n_alloc, rxq->size - slot);
  n_alloc &= ~(8 - 1);

  n = vlib_buffer_alloc_to_ring_from_pool (vm, iq->buffers, slot, rxq->size,
					   n_alloc, buffer_pool_index);
  if (PREDICT_FALSE (n != n_alloc))
    {
      u32 n_free;
      if (n < 8)
	{
	  if (n)
	    vlib_buffer_free_from_ring (vm, iq->buffers, slot, rxq->size, n);
	  return;
	}

      n_free = n & (8 - 1);
      n -= n_free;
      if (n_free)
	vlib_buffer_free_from_ring (vm, iq->buffers, (slot + n) & mask,
				    rxq->size, n_free);
    }

  n_alloc = n;
  n = n_alloc;

  while (n >= 8)
    {
      u64 va[8];
      if (PREDICT_TRUE (n >= 16))
	{
	  clib_prefetch_store (re + 16);
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, 8,
				    sizeof (vlib_buffer_t));

      re[0].sge.addr = va[0];
      re[1].sge.addr = va[1];
      re[2].sge.addr = va[2];
      re[3].sge.addr = va[3];
      re[4].sge.addr = va[4];
      re[5].sge.addr = va[5];
      re[6].sge.addr = va[6];
      re[7].sge.addr = va[7];

      re += 8;
      bufs += 8;
      n -= 8;
    }

  next_wr = re[-1].recv_wr.next;
  re[-1].recv_wr.next = 0;
  n = n_alloc;
  if (ibv_post_recv (iq->ibv_qp, &iq->refill_entries[0].recv_wr, &bad_wr) != 0)
    {
      n = 0;
      if (bad_wr)
	{
	  for (i = 0; i < n_alloc; i++)
	    {
	      if (&iq->refill_entries[i].recv_wr == bad_wr)
		break;
	    }
	  n = i;
	}
      vlib_buffer_free_from_ring (vm, iq->buffers, slot + n, rxq->size,
				  n_alloc - n);
    }
  re[-1].recv_wr.next = next_wr;

  iq->tail += n;
}

static_always_inline u32
rdma_ibv_input_bufs (vnet_dev_rx_queue_t *rxq, vlib_buffer_t **b,
		     struct ibv_wc *wc, u32 n_left_from)
{
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 n_rx_bytes = 0;

  while (n_left_from >= 4)
    {
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  clib_prefetch_load (wc + 4);
	  clib_prefetch_load (wc + 5);
	  clib_prefetch_load (wc + 6);
	  clib_prefetch_load (wc + 7);
	  vlib_prefetch_buffer_header (b[4 + 0], STORE);
	  vlib_prefetch_buffer_header (b[4 + 1], STORE);
	  vlib_prefetch_buffer_header (b[4 + 2], STORE);
	  vlib_prefetch_buffer_header (b[4 + 3], STORE);
	}

      b[0]->template = bt;
      b[1]->template = bt;
      b[2]->template = bt;
      b[3]->template = bt;

      n_rx_bytes += b[0]->current_length = wc[0].byte_len;
      n_rx_bytes += b[1]->current_length = wc[1].byte_len;
      n_rx_bytes += b[2]->current_length = wc[2].byte_len;
      n_rx_bytes += b[3]->current_length = wc[3].byte_len;

      b += 4;
      wc += 4;
      n_left_from -= 4;
    }

  while (n_left_from >= 1)
    {
      b[0]->template = bt;
      n_rx_bytes += b[0]->current_length = wc[0].byte_len;

      b += 1;
      wc += 1;
      n_left_from -= 1;
    }

  return n_rx_bytes;
}

static_always_inline u32
rdma_ibv_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vnet_dev_rx_queue_t *rxq)
{
  rdma_ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  vnet_main_t *vnm = vnet_get_main ();
  u32 next_index;
  u32 *to_next;
  u32 n_left_to_next;
  u32 n_rx_bytes = 0;
  int n_rx_packets = 0;
  u32 mask = rxq->size - 1;
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];

  n_rx_packets = ibv_poll_cq (iq->ibv_cq, VLIB_FRAME_SIZE, wc);

  if (PREDICT_FALSE (n_rx_packets <= 0))
    return 0;

  next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  vlib_buffer_copy_indices_from_ring (to_next, iq->buffers, iq->head & mask,
				      rxq->size, n_rx_packets);
  vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
  iq->head += n_rx_packets;
  n_rx_bytes = rdma_ibv_input_bufs (rxq, bufs, wc, n_rx_packets);

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, sw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

VNET_DEV_NODE_FN (rdma_ibv_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      rv += rdma_ibv_rx_one_queue (vm, node, rxq);
      rdma_ibv_rxq_refill (vm, rxq);
    }

  return rv;
}
