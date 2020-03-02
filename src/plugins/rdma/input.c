/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <rdma/rdma.h>

#define foreach_rdma_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) RDMA_INPUT_ERROR_##f,
  foreach_rdma_input_error
#undef _
    RDMA_INPUT_N_ERROR,
} rdma_input_error_t;

static __clib_unused char *rdma_input_error_strings[] = {
#define _(n,s) s,
  foreach_rdma_input_error
#undef _
};

static_always_inline void
rdma_device_input_refill (vlib_main_t * vm, rdma_device_t * rd,
			  rdma_rxq_t * rxq, int is_mlx5dv)
{
  u32 n_alloc, n;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  struct ibv_recv_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  u32 slot = rxq->tail & (rxq->size - 1);

  /* do not enqueue more packet than ring space */
  n_alloc = clib_min (VLIB_FRAME_SIZE, rxq->size - (rxq->tail - rxq->head));

  /* do not bother to allocate if too small */
  if (n_alloc < 16)
    return;

  /* avoid wrap-around logic in core loop */
  n_alloc = clib_min (n_alloc, rxq->size - slot);

  n_alloc &= ~7;		/* round to 8 */

  n = n_alloc = vlib_buffer_alloc_to_ring_from_pool (vm, rxq->bufs, slot,
						     rxq->size, n_alloc,
						     rd->pool);

  /* if ring is full or allocation error, do nothing */
  if (PREDICT_FALSE (n != n_alloc))
    return;

  if (is_mlx5dv)
    {
      u64 va[8];
      mlx5dv_rwq_t *wqe = rxq->rwq + slot;

      while (n >= 1)
	{
	  vlib_get_buffers_with_offset (vm, rxq->bufs + slot, (void **) va, 8,
					sizeof (vlib_buffer_t));
#ifdef CLIB_HAVE_VEC256
	  *(u64x4 *) va = u64x4_byte_swap (*(u64x4 *) va);
	  *(u64x4 *) (va + 4) = u64x4_byte_swap (*(u64x4 *) (va + 4));
#else
	  for (int i = 0; i < 8; i++)
	    va[i] = clib_host_to_net_u64 (va[i]);
#endif
	  wqe[0].addr = va[0];
	  wqe[1].addr = va[1];
	  wqe[2].addr = va[2];
	  wqe[3].addr = va[3];
	  wqe[4].addr = va[4];
	  wqe[5].addr = va[5];
	  wqe[6].addr = va[6];
	  wqe[7].addr = va[7];
	  wqe += 8;
	  slot += 8;
	  n -= 8;
	}

      CLIB_MEMORY_STORE_BARRIER ();
      rxq->tail += n_alloc;
      rxq->rwq_db[MLX5_RCV_DBR] = clib_host_to_net_u32 (rxq->tail);
      return;
    }

  vlib_get_buffers (vm, &rxq->bufs[slot], bufs, n_alloc);

  while (n >= 4)
    {
      if (PREDICT_TRUE (n >= 8))
	{
	  CLIB_PREFETCH (&s[4 + 0], 4 * sizeof (s[0]), STORE);
	  CLIB_PREFETCH (&w[4 + 0], 4 * sizeof (w[0]), STORE);
	}

      s[0].addr = vlib_buffer_get_va (b[0]);
      s[0].length = vlib_buffer_get_default_data_size (vm);
      s[0].lkey = rd->lkey;

      s[1].addr = vlib_buffer_get_va (b[1]);
      s[1].length = vlib_buffer_get_default_data_size (vm);
      s[1].lkey = rd->lkey;

      s[2].addr = vlib_buffer_get_va (b[2]);
      s[2].length = vlib_buffer_get_default_data_size (vm);
      s[2].lkey = rd->lkey;

      s[3].addr = vlib_buffer_get_va (b[3]);
      s[3].length = vlib_buffer_get_default_data_size (vm);
      s[3].lkey = rd->lkey;

      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;

      w[1].next = &w[1] + 1;
      w[1].sg_list = &s[1];
      w[1].num_sge = 1;

      w[2].next = &w[2] + 1;
      w[2].sg_list = &s[2];
      w[2].num_sge = 1;

      w[3].next = &w[3] + 1;
      w[3].sg_list = &s[3];
      w[3].num_sge = 1;

      s += 4;
      w += 4;
      b += 4;
      n -= 4;
    }

  while (n >= 1)
    {
      s[0].addr = vlib_buffer_get_va (b[0]);
      s[0].length = vlib_buffer_get_default_data_size (vm);
      s[0].lkey = rd->lkey;

      w[0].next = &w[0] + 1;
      w[0].sg_list = &s[0];
      w[0].num_sge = 1;

      s += 1;
      w += 1;
      b += 1;
      n -= 1;
    }

  w[-1].next = 0;		/* fix next pointer in WR linked-list last item */

  n = n_alloc;
  if (ibv_post_wq_recv (rxq->wq, wr, &w) != 0)
    {
      n = w - wr;
      vlib_buffer_free_from_ring (vm, rxq->bufs, slot + n, rxq->size,
				  n_alloc - n);
    }

  rxq->tail += n;
}

static_always_inline void
rdma_device_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
			 const rdma_device_t * rd, u32 n_left, const u32 * bi,
			 u32 next_index)
{
  u32 n_trace, i;

  if (PREDICT_TRUE (0 == (n_trace = vlib_get_trace_count (vm, node))))
    return;

  i = 0;
  while (n_trace && n_left)
    {
      vlib_buffer_t *b;
      rdma_input_trace_t *tr;
      b = vlib_get_buffer (vm, bi[0]);
      vlib_trace_buffer (vm, node, next_index, b,
			 /* follow_chain */ 0);
      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
      tr->next_index = next_index;
      tr->hw_if_index = rd->hw_if_index;

      /* next */
      n_trace--;
      n_left--;
      bi++;
      i++;
    }
  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline void
rdma_device_input_ethernet (vlib_main_t * vm, vlib_node_runtime_t * node,
			    const rdma_device_t * rd, u32 next_index)
{
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  ethernet_input_frame_t *ef;

  if (PREDICT_FALSE (VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT != next_index))
    return;

  nf =
    vlib_node_runtime_get_next_frame (vm, node,
				      VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT);
  f = vlib_get_frame (vm, nf->frame);
  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
  /* FIXME: f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK; */

  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = rd->sw_if_index;
  ef->hw_if_index = rd->hw_if_index;
}

static_always_inline u32
rdma_device_input_bufs (vlib_main_t * vm, const rdma_device_t * rd,
			u32 * next, u32 * bi, struct ibv_wc * wc,
			u32 n_left_from, vlib_buffer_t * bt)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 n_rx_bytes[4] = { 0 };

  vlib_get_buffers (vm, bi, bufs, n_left_from);
  ASSERT (bt->buffer_pool_index == bufs[0]->buffer_pool_index);

  while (n_left_from >= 4)
    {
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  CLIB_PREFETCH (&wc[4 + 0], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&wc[4 + 1], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&wc[4 + 2], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (&wc[4 + 3], CLIB_CACHE_LINE_BYTES, LOAD);
	  vlib_prefetch_buffer_header (b[4 + 0], STORE);
	  vlib_prefetch_buffer_header (b[4 + 1], STORE);
	  vlib_prefetch_buffer_header (b[4 + 2], STORE);
	  vlib_prefetch_buffer_header (b[4 + 3], STORE);
	}

      vlib_buffer_copy_indices (next, bi, 4);

      vlib_buffer_copy_template (b[0], bt);
      vlib_buffer_copy_template (b[1], bt);
      vlib_buffer_copy_template (b[2], bt);
      vlib_buffer_copy_template (b[3], bt);

      b[0]->current_length = wc[0].byte_len;
      b[1]->current_length = wc[1].byte_len;
      b[2]->current_length = wc[2].byte_len;
      b[3]->current_length = wc[3].byte_len;

      n_rx_bytes[0] += wc[0].byte_len;
      n_rx_bytes[1] += wc[1].byte_len;
      n_rx_bytes[2] += wc[2].byte_len;
      n_rx_bytes[3] += wc[3].byte_len;

      next += 4;
      bi += 4;
      b += 4;
      wc += 4;
      n_left_from -= 4;
    }

  while (n_left_from >= 1)
    {
      vlib_buffer_copy_indices (next, bi, 1);
      vlib_buffer_copy_template (b[0], bt);
      b[0]->current_length = wc[0].byte_len;
      n_rx_bytes[0] += wc[0].byte_len;

      next += 1;
      bi += 1;
      b += 1;
      wc += 1;
      n_left_from -= 1;
    }

  return n_rx_bytes[0] + n_rx_bytes[1] + n_rx_bytes[2] + n_rx_bytes[3];
}

static_always_inline uword
rdma_device_poll_cq_mlx5dv (rdma_rxq_t * rxq, u32 * byte_cnt)
{
  u16 mask = rxq->cq_size - 1;
  u8 cqe_last_byte;
  u32 n_rx_packets = 0;
  u16 next_cqe = rxq->next_cqe;
  mlx5dv_rcq_t *cqe = rxq->rcq + next_cqe;

  while (((cqe_last_byte = cqe->as_u8[0x3f])) != 0xf0)
    {
      if (n_rx_packets == VLIB_FRAME_SIZE)
	break;

      if (cqe_last_byte != 0x20)
	{
	  fformat (stderr, "wqe slot %u last byte %x\n", rxq->next_cqe,
		   cqe_last_byte);
	  fformat (stderr, "wqe next %u\n", rxq->next_cqe);
	  fformat (stderr, "%U\n", format_hexdump, cqe, 64);
	  exit (1);
	}

      byte_cnt[0] = cqe->as_u32[11];
      n_rx_packets++;

      /* next cqe */
      next_cqe = (next_cqe + 1) & mask;
      cqe = rxq->rcq + next_cqe;
      byte_cnt++;
    }
  rxq->next_cqe = next_cqe;
  return n_rx_packets;
}

static_always_inline uword
rdma_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, rdma_device_t * rd, u16 qid,
			  int use_mlx5dv)
{
  rdma_main_t *rm = &rdma_main;
  vnet_main_t *vnm = vnet_get_main ();
  rdma_per_thread_data_t *ptd = vec_elt_at_index (rm->per_thread_data,
						  vm->thread_index);
  rdma_rxq_t *rxq = vec_elt_at_index (rd->rxqs, qid);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 byte_cnts[VLIB_FRAME_SIZE];
  vlib_buffer_t bt;
  u32 next_index, *to_next, n_left_to_next, n_rx_bytes = 0;
  int n_rx_packets;
  u32 slot, n_tail;

  if (use_mlx5dv)
    n_rx_packets = rdma_device_poll_cq_mlx5dv (rxq, byte_cnts);
  else
    n_rx_packets = ibv_poll_cq (rxq->cq, VLIB_FRAME_SIZE, wc);

  if (PREDICT_FALSE (n_rx_packets <= 0))
    goto refill;

  /* init buffer template */
  vlib_buffer_copy_template (&bt, &ptd->buffer_template);
  vnet_buffer (&bt)->sw_if_index[VLIB_RX] = rd->sw_if_index;
  bt.buffer_pool_index = rd->pool;

  /* update buffer template for input feature arcs if any */
  next_index = rd->per_interface_next_index;
  if (PREDICT_FALSE (vnet_device_input_have_features (rd->sw_if_index)))
    vnet_feature_start_device_input_x1 (rd->sw_if_index, &next_index, &bt);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (use_mlx5dv)
    {
      vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
      u32 n_left = n_rx_packets;
      u32 *bc = byte_cnts;

      vlib_buffer_copy_indices_from_ring (to_next, rxq->bufs, rxq->head &
					  (rxq->size - 1), rxq->size,
					  n_rx_packets);

      vlib_get_buffers (vm, to_next, bufs, n_rx_packets);

#if defined CLIB_HAVE_VEC256
      for (int i = 0; i < n_rx_packets; i += 8)
	*(u32x8 *) (bc + i) = u32x8_byte_swap (*(u32x8 *) (bc + i));
#elif defined CLIB_HAVE_VEC128
      for (int i = 0; i < n_rx_packets; i += 4)
	*(u32x4 *) (bc + i) = u32x4_byte_swap (*(u32x4 *) (bc + i));
#else
      for (int i = 0; i < n_rx_packets; i++)
	bc[i] = clib_net_to_host_u32 (bc[i]);
#endif

      while (n_left >= 8)
	{
	  clib_prefetch_store (b[4]);
	  vlib_buffer_copy_template (b[0], &bt);
	  n_rx_bytes += b[0]->current_length = bc[0];
	  clib_prefetch_store (b[5]);
	  vlib_buffer_copy_template (b[1], &bt);
	  n_rx_bytes += b[1]->current_length = bc[1];
	  clib_prefetch_store (b[6]);
	  vlib_buffer_copy_template (b[2], &bt);
	  n_rx_bytes += b[2]->current_length = bc[2];
	  clib_prefetch_store (b[7]);
	  vlib_buffer_copy_template (b[3], &bt);
	  n_rx_bytes += b[3]->current_length = bc[3];

	  /* next */
	  bc += 4;
	  b += 4;
	  n_left -= 4;
	}
      while (n_left)
	{
	  vlib_buffer_copy_template (b[0], &bt);
	  n_rx_bytes += b[0]->current_length = bc[0];
	  //fformat (stderr, "enq bi %x from slot %u\n", bi, rxq->head);

	  /* next */
	  bc++;
	  b++;
	  n_left--;
	}
      rxq->head += n_rx_packets;
    }
  else
    {
      /*
       * avoid wrap-around logic in core loop
       * we requested VLIB_FRAME_SIZE packets and rxq->size >= VLIB_FRAME_SIZE
       *    => we can process all packets in 2 iterations max
       */
      slot = rxq->head & (rxq->size - 1);
      n_tail = clib_min (n_rx_packets, rxq->size - slot);
      n_rx_bytes =
	rdma_device_input_bufs (vm, rd, &to_next[0], &rxq->bufs[slot], wc,
				n_tail, &bt);
      if (n_tail < n_rx_packets)
	n_rx_bytes +=
	  rdma_device_input_bufs (vm, rd, &to_next[n_tail], &rxq->bufs[0],
				  &wc[n_tail], n_rx_packets - n_tail, &bt);
      rxq->head += n_rx_packets;
    }

  rdma_device_input_ethernet (vm, node, rd, next_index);

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  rdma_device_input_trace (vm, node, rd, n_rx_packets, to_next, next_index);

  vlib_increment_combined_counter
    (vnm->interface_main.combined_sw_if_counters +
     VNET_INTERFACE_COUNTER_RX, vm->thread_index,
     rd->hw_if_index, n_rx_packets, n_rx_bytes);

refill:
  rdma_device_input_refill (vm, rd, rxq, use_mlx5dv);

  return n_rx_packets;
}

VLIB_NODE_FN (rdma_input_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u32 n_rx = 0;
  rdma_main_t *rm = &rdma_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    rdma_device_t *rd;
    rd = vec_elt_at_index (rm->devices, dq->dev_instance);
    if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_ADMIN_UP) == 0)
      continue;

    if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_MLX5DV))
      n_rx += rdma_device_input_inline (vm, node, frame, rd, dq->queue_id, 1);
    else
      n_rx += rdma_device_input_inline (vm, node, frame, rd, dq->queue_id, 0);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (rdma_input_node) = {
  .name = "rdma-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .sibling_of = "device-input",
  .format_trace = format_rdma_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = RDMA_INPUT_N_ERROR,
  .error_strings = rdma_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
