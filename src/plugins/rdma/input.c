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
ibv_set_recv_wr_and_sge (struct ibv_recv_wr *w, struct ibv_sge *s, u64 va,
			 u32 data_size, u32 lkey)
{
  s[0].addr = va;
  s[0].length = data_size;
  s[0].lkey = lkey;
  w[0].next = w + 1;
  w[0].sg_list = s;
  w[0].num_sge = 1;
}

static_always_inline void
rdma_device_input_refill (vlib_main_t * vm, rdma_device_t * rd,
			  rdma_rxq_t * rxq, int is_mlx5dv)
{
  u32 n_alloc, n;
  struct ibv_recv_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  u32 mask = rxq->size - 1;
  u32 slot = rxq->tail & mask;
  u32 *bufs = rxq->bufs + slot;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u32 lkey = rd->lkey;

  /* do not enqueue more packet than ring space */
  n_alloc = clib_min (VLIB_FRAME_SIZE, rxq->size - (rxq->tail - rxq->head));

  /* do not bother to allocate if too small */
  if (n_alloc < 16)
    return;

  /* avoid wrap-around logic in core loop */
  n_alloc = clib_min (n_alloc, rxq->size - slot);

  n_alloc &= ~7;		/* round to 8 */

  n = vlib_buffer_alloc_to_ring_from_pool (vm, rxq->bufs, slot, rxq->size,
					   n_alloc, rd->pool);

  if (PREDICT_FALSE (n != n_alloc))
    {
      u32 n_free;
      if (n < 8)
	{
	  if (n)
	    vlib_buffer_free_from_ring (vm, rxq->bufs, slot, rxq->size, n);
	  return;
	}

      /* partial allocation, round and return rest */
      n_free = n - (n & 7);
      n -= n_free;
      if (n_free)
	vlib_buffer_free_from_ring (vm, rxq->bufs, (slot + n) & mask,
				    rxq->size, n_free);
    }

  n_alloc = n;

  if (is_mlx5dv)
    {
      u64 __clib_aligned (32) va[8];
      mlx5dv_rwq_t *wqe = rxq->wqes + slot;

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
      rxq->wq_db[MLX5_RCV_DBR] = clib_host_to_net_u32 (rxq->tail);
      return;
    }

  while (n >= 8)
    {
      u64 va[8];
      if (PREDICT_TRUE (n >= 16))
	{
	  clib_prefetch_store (s + 16);
	  clib_prefetch_store (w + 16);
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, 8,
				    sizeof (vlib_buffer_t));

      ibv_set_recv_wr_and_sge (w++, s++, va[0], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[1], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[2], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[3], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[4], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[5], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[6], data_size, lkey);
      ibv_set_recv_wr_and_sge (w++, s++, va[7], data_size, lkey);

      bufs += 8;
      n -= 8;
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
			 u32 next_index, u16 * cqe_flags, int is_mlx5dv)
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
      tr->cqe_flags = is_mlx5dv ? clib_net_to_host_u16 (cqe_flags[0]) : 0;

      /* next */
      n_trace--;
      n_left--;
      cqe_flags++;
      bi++;
      i++;
    }
  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline void
rdma_device_input_ethernet (vlib_main_t * vm, vlib_node_runtime_t * node,
			    const rdma_device_t * rd, u32 next_index,
			    int skip_ip4_cksum)
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
  if (skip_ip4_cksum)
    f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;

  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = rd->sw_if_index;
  ef->hw_if_index = rd->hw_if_index;
}

static_always_inline u32
rdma_device_input_bufs (vlib_main_t * vm, const rdma_device_t * rd,
			vlib_buffer_t ** b, struct ibv_wc *wc,
			u32 n_left_from, vlib_buffer_t * bt)
{
  u32 n_rx_bytes = 0;

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

      vlib_buffer_copy_template (b[0], bt);
      vlib_buffer_copy_template (b[1], bt);
      vlib_buffer_copy_template (b[2], bt);
      vlib_buffer_copy_template (b[3], bt);

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
      vlib_buffer_copy_template (b[0], bt);
      n_rx_bytes += b[0]->current_length = wc[0].byte_len;

      b += 1;
      wc += 1;
      n_left_from -= 1;
    }

  return n_rx_bytes;
}

static_always_inline void
process_mini_cqes (rdma_rxq_t * rxq, u32 skip, u32 n_left, u32 cq_ci,
		   u32 mask, u32 * byte_cnt)
{
  mlx5dv_mini_cqe_t *mcqe;
  u32 mcqe_array_index = (cq_ci + 1) & mask;
  mcqe = (mlx5dv_mini_cqe_t *) (rxq->cqes + mcqe_array_index);

  mcqe_array_index = cq_ci;

  if (skip)
    {
      u32 n = skip & ~7;

      if (n)
	{
	  mcqe_array_index = (mcqe_array_index + n) & mask;
	  mcqe = (mlx5dv_mini_cqe_t *) (rxq->cqes + mcqe_array_index);
	  skip -= n;
	}

      if (skip)
	{
	  n = clib_min (8 - skip, n_left);
	  for (int i = 0; i < n; i++)
	    byte_cnt[i] = mcqe[skip + i].byte_count;
	  mcqe_array_index = (mcqe_array_index + 8) & mask;
	  mcqe = (mlx5dv_mini_cqe_t *) (rxq->cqes + mcqe_array_index);
	  n_left -= n;
	  byte_cnt += n;
	}

    }

  while (n_left >= 8)
    {
      for (int i = 0; i < 8; i++)
	byte_cnt[i] = mcqe[i].byte_count;

      n_left -= 8;
      byte_cnt += 8;
      mcqe_array_index = (mcqe_array_index + 8) & mask;
      mcqe = (mlx5dv_mini_cqe_t *) (rxq->cqes + mcqe_array_index);
    }

  if (n_left)
    {
      for (int i = 0; i < n_left; i++)
	byte_cnt[i] = mcqe[i].byte_count;
    }
}

static_always_inline void
cqe_set_owner (mlx5dv_cqe_t * cqe, u32 n_left, u8 owner)
{
  while (n_left >= 8)
    {
      cqe[0].opcode_cqefmt_se_owner = owner;
      cqe[1].opcode_cqefmt_se_owner = owner;
      cqe[2].opcode_cqefmt_se_owner = owner;
      cqe[3].opcode_cqefmt_se_owner = owner;
      cqe[4].opcode_cqefmt_se_owner = owner;
      cqe[5].opcode_cqefmt_se_owner = owner;
      cqe[6].opcode_cqefmt_se_owner = owner;
      cqe[7].opcode_cqefmt_se_owner = owner;
      n_left -= 8;
      cqe += 8;
    }
  while (n_left)
    {
      cqe[0].opcode_cqefmt_se_owner = owner;
      n_left--;
      cqe++;
    }
}

static_always_inline void
compressed_cqe_reset_owner (rdma_rxq_t * rxq, u32 n_mini_cqes, u32 cq_ci,
			    u32 mask, u32 log2_cq_size)
{
  u8 owner;
  u32 offset, cq_size = 1 << log2_cq_size;


  /* first CQE is reset by hardware */
  cq_ci++;
  n_mini_cqes--;

  offset = cq_ci & mask;
  owner = 0xf0 | ((cq_ci >> log2_cq_size) & 1);

  if (offset + n_mini_cqes < cq_size)
    {
      cqe_set_owner (rxq->cqes + offset, n_mini_cqes, owner);
    }
  else
    {
      u32 n = cq_size - offset;
      cqe_set_owner (rxq->cqes + offset, n, owner);
      cqe_set_owner (rxq->cqes, n_mini_cqes - n, owner ^ 1);
    }

}

static_always_inline uword
rdma_device_poll_cq_mlx5dv (rdma_device_t * rd, rdma_rxq_t * rxq,
			    u32 * byte_cnt, u16 * cqe_flags)
{
  u32 n_rx_packets = 0;
  u32 log2_cq_size = rxq->log2_cq_size;
  u32 mask = pow2_mask (log2_cq_size);
  u32 cq_ci = rxq->cq_ci;

  if (rxq->n_mini_cqes_left)
    {
      /* partially processed mini-cqe array */
      u32 n_mini_cqes = rxq->n_mini_cqes;
      u32 n_mini_cqes_left = rxq->n_mini_cqes_left;
      process_mini_cqes (rxq, n_mini_cqes - n_mini_cqes_left,
			 n_mini_cqes_left, cq_ci, mask, byte_cnt);
      compressed_cqe_reset_owner (rxq, n_mini_cqes, cq_ci, mask,
				  log2_cq_size);
      clib_memset_u16 (cqe_flags, rxq->last_cqe_flags, n_mini_cqes_left);
      n_rx_packets = n_mini_cqes_left;
      byte_cnt += n_mini_cqes_left;
      cqe_flags += n_mini_cqes_left;
      rxq->n_mini_cqes_left = 0;
      rxq->cq_ci = cq_ci = cq_ci + n_mini_cqes;
    }

  while (n_rx_packets < VLIB_FRAME_SIZE)
    {
      u8 cqe_last_byte, owner;
      mlx5dv_cqe_t *cqe = rxq->cqes + (cq_ci & mask);

      clib_prefetch_load (rxq->cqes + ((cq_ci + 8) & mask));

      owner = (cq_ci >> log2_cq_size) & 1;
      cqe_last_byte = cqe->opcode_cqefmt_se_owner;

      if ((cqe_last_byte & 0x1) != owner)
	break;

      cqe_last_byte &= 0xfe;	/* remove owner bit */

      if (cqe_last_byte == 0x2c)
	{
	  u32 n_mini_cqes = clib_net_to_host_u32 (cqe->mini_cqe_num);
	  u32 n_left = VLIB_FRAME_SIZE - n_rx_packets;
	  u16 flags = cqe->flags;

	  if (n_left >= n_mini_cqes)
	    {
	      process_mini_cqes (rxq, 0, n_mini_cqes, cq_ci, mask, byte_cnt);
	      clib_memset_u16 (cqe_flags, flags, n_mini_cqes);
	      compressed_cqe_reset_owner (rxq, n_mini_cqes, cq_ci, mask,
					  log2_cq_size);
	      n_rx_packets += n_mini_cqes;
	      byte_cnt += n_mini_cqes;
	      cqe_flags += n_mini_cqes;
	      cq_ci += n_mini_cqes;
	    }
	  else
	    {
	      process_mini_cqes (rxq, 0, n_left, cq_ci, mask, byte_cnt);
	      clib_memset_u16 (cqe_flags, flags, n_left);
	      n_rx_packets = VLIB_FRAME_SIZE;
	      rxq->n_mini_cqes = n_mini_cqes;
	      rxq->n_mini_cqes_left = n_mini_cqes - n_left;
	      rxq->last_cqe_flags = flags;
	      goto done;
	    }
	  continue;
	}

      if (cqe_last_byte == 0x20)
	{
	  byte_cnt[0] = cqe->byte_cnt;
	  cqe_flags[0] = cqe->flags;
	  n_rx_packets++;
	  cq_ci++;
	  byte_cnt++;
	  continue;
	}

      rd->flags |= RDMA_DEVICE_F_ERROR;
      break;
    }

done:
  if (n_rx_packets)
    rxq->cq_db[0] = rxq->cq_ci = cq_ci;
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
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 __clib_aligned (32) byte_cnts[VLIB_FRAME_SIZE];
  vlib_buffer_t bt;
  u32 next_index, *to_next, n_left_to_next, n_rx_bytes = 0;
  int n_rx_packets, skip_ip4_cksum = 0;
  u32 mask = rxq->size - 1;

  if (use_mlx5dv)
    n_rx_packets = rdma_device_poll_cq_mlx5dv (rd, rxq, byte_cnts,
					       ptd->cqe_flags);
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

  vlib_buffer_copy_indices_from_ring (to_next, rxq->bufs, rxq->head & mask,
				      rxq->size, n_rx_packets);

  vlib_get_buffers (vm, to_next, bufs, n_rx_packets);

  if (use_mlx5dv)
    {
      u16 mask = CQE_FLAG_L3_HDR_TYPE_MASK | CQE_FLAG_L3_OK;
      u16 match = CQE_FLAG_L3_HDR_TYPE_IP4 << CQE_FLAG_L3_HDR_TYPE_SHIFT;
      u32 n_left = n_rx_packets;
      u32 *bc = byte_cnts;

      /* verify that all ip4 packets have l3_ok flag set and convert packet
         length from network to host byte order */
      skip_ip4_cksum = 1;

#if defined CLIB_HAVE_VEC256
      u16x16 mask16 = u16x16_splat (mask);
      u16x16 match16 = u16x16_splat (match);
      u16x16 r = { };

      for (int i = 0; i * 16 < n_rx_packets; i++)
	r |= (ptd->cqe_flags16[i] & mask16) != match16;

      if (!u16x16_is_all_zero (r))
	skip_ip4_cksum = 0;

      for (int i = 0; i < n_rx_packets; i += 8)
	*(u32x8 *) (bc + i) = u32x8_byte_swap (*(u32x8 *) (bc + i));
#elif defined CLIB_HAVE_VEC128
      u16x8 mask8 = u16x8_splat (mask);
      u16x8 match8 = u16x8_splat (match);
      u16x8 r = { };

      for (int i = 0; i * 8 < n_rx_packets; i++)
	r |= (ptd->cqe_flags8[i] & mask8) != match8;

      if (!u16x8_is_all_zero (r))
	skip_ip4_cksum = 0;

      for (int i = 0; i < n_rx_packets; i += 4)
	*(u32x4 *) (bc + i) = u32x4_byte_swap (*(u32x4 *) (bc + i));
#else
      for (int i = 0; i < n_rx_packets; i++)
	if ((ptd->cqe_flags[i] & mask) == match)
	  skip_ip4_cksum = 0;

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

	  /* next */
	  bc++;
	  b++;
	  n_left--;
	}
    }
  else
    n_rx_bytes = rdma_device_input_bufs (vm, rd, bufs, wc, n_rx_packets, &bt);

  rdma_device_input_ethernet (vm, node, rd, next_index, skip_ip4_cksum);

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  rxq->head += n_rx_packets;

  rdma_device_input_trace (vm, node, rd, n_rx_packets, to_next, next_index,
			   ptd->cqe_flags, use_mlx5dv);

  /* reset flags to zero for the next run */
  if (use_mlx5dv)
    clib_memset_u16 (ptd->cqe_flags, 0, VLIB_FRAME_SIZE);

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

    if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_ERROR))
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
