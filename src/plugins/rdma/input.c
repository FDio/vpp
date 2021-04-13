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
#include <vnet/interface/rx_queue_funcs.h>

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

static_always_inline u32
rdma_device_legacy_input_refill_additional (vlib_main_t * vm,
					    rdma_device_t * rd,
					    rdma_rxq_t * rxq,
					    rdma_per_thread_data_t * ptd,
					    vlib_buffer_t * bt,
					    u32 first_slot, u32 n_alloc)
{
  int i;
  u8 log_wqe_sz = rxq->log_wqe_sz;
  u32 *bi = ptd->tmp_bi;
  vlib_buffer_t **bufs = ptd->tmp_bufs;

  for (i = 0; i < n_alloc; i++)
    {
      u8 chain_sz = rxq->n_used_per_chain[first_slot + i];
      u8 chain_sz_alloc;
      mlx5dv_wqe_ds_t *current_wqe =
	rxq->wqes + ((first_slot + i) << log_wqe_sz);
      if (chain_sz == 0)
	continue;
      if (PREDICT_FALSE ((chain_sz_alloc =
			  vlib_buffer_alloc_from_pool (vm, bi, chain_sz,
						       rd->pool)) !=
			 chain_sz))
	{
	  vlib_buffer_free (vm, bi, chain_sz_alloc);
	  break;
	}
      /*Build the chain */
      vlib_get_buffers (vm, bi, bufs, chain_sz);
      for (int j = 0; j < chain_sz - 1; j++)
	{
	  vlib_buffer_copy_template (bufs[j], bt);
	  bufs[j]->next_buffer = bi[j + 1];
	  bufs[j]->flags |= VLIB_BUFFER_NEXT_PRESENT;
	}
      /* The chain starting at the second buffer is pre-initialised */
      vlib_buffer_copy_template (bufs[chain_sz - 1], bt);
      /* Stick with the already existing chain */
      if (chain_sz < rxq->n_ds_per_wqe - 1)
	{
	  bufs[chain_sz - 1]->next_buffer = rxq->second_bufs[first_slot + i];
	  bufs[chain_sz - 1]->flags |= VLIB_BUFFER_NEXT_PRESENT;
	}
      else
	{
	  bufs[chain_sz - 1]->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	}

      /* Update the wqes */
      for (int j = 0; j < chain_sz; j++)
	{
	  u64 addr;
	  vlib_get_buffers_with_offset (vm, bi + j,
					(void *) &addr, 1,
					sizeof (vlib_buffer_t));
	  current_wqe[j + 1].addr = clib_host_to_net_u64 (addr);
	}
      rxq->n_used_per_chain[first_slot + i] = 0;
      rxq->n_total_additional_segs -= chain_sz;
      rxq->second_bufs[first_slot + i] = bi[0];
    }
  return i;
}

static_always_inline void
rdma_device_input_refill (vlib_main_t * vm, rdma_device_t * rd,
			  rdma_rxq_t * rxq, vlib_buffer_t * bt,
			  const int is_mlx5dv, const int is_striding)
{
  u32 n_alloc, n;
  u16 ring_space;
  struct ibv_recv_wr wr[VLIB_FRAME_SIZE], *w = wr;
  struct ibv_sge sge[VLIB_FRAME_SIZE], *s = sge;
  rdma_per_thread_data_t *ptd =
    &rdma_main.per_thread_data[vlib_get_thread_index ()];
  u32 mask = rxq->size - 1;
  u32 slot = rxq->tail & mask;
  u32 *bufs = rxq->bufs + slot;
  u32 data_size = rxq->buf_sz;
  u32 lkey = rd->lkey;
  const int log_stride_per_wqe = is_striding ? rxq->log_stride_per_wqe : 0;
  const int log_wqe_sz = rxq->log_wqe_sz;

  /*In legacy mode, maybe some buffers chains are incomplete? */
  if (PREDICT_FALSE
      (is_mlx5dv && !is_striding && (rxq->incomplete_tail != rxq->tail)))
    {
      int n_incomplete = rxq->incomplete_tail - rxq->tail;
      int n_completed =
	rdma_device_legacy_input_refill_additional (vm, rd, rxq, ptd, bt,
						    slot,
						    n_incomplete);
      rxq->tail += n_completed;
      slot = rxq->tail & mask;
      /* Don't start recycling head buffers if there are incomplete chains */
      if (n_completed != n_incomplete)
	return;
    }

  /* refilled buffers must be a multiple of 8 and of strides per WQE */
  u32 alloc_multiple = 1 << (clib_max (3, log_stride_per_wqe));

  ring_space = rxq->size - (rxq->tail - rxq->head);

  n_alloc = clib_min (VLIB_FRAME_SIZE, ring_space);

  /* do not bother to allocate if too small */
  if (n_alloc < 2 * alloc_multiple)
    return;

  /* avoid wrap-around logic in core loop */
  n_alloc = clib_min (n_alloc, rxq->size - slot);

  n_alloc &= ~(alloc_multiple - 1);	/* round to alloc_multiple */

  n = vlib_buffer_alloc_to_ring_from_pool (vm, rxq->bufs, slot, rxq->size,
					   n_alloc, rd->pool);

  if (PREDICT_FALSE (n != n_alloc))
    {
      u32 n_free;
      if (n < alloc_multiple)
	{
	  if (n)
	    vlib_buffer_free_from_ring (vm, rxq->bufs, slot, rxq->size, n);
	  return;
	}

      /* partial allocation, round and return rest */
      n_free = n & (alloc_multiple - 1);
      n -= n_free;
      if (n_free)
	vlib_buffer_free_from_ring (vm, rxq->bufs, (slot + n) & mask,
				    rxq->size, n_free);
    }

  n_alloc = n;

  if (is_mlx5dv)
    {
      u64 __clib_aligned (32) va[8];

      /* slot does not necessarily correspond to the slot
         in the wqes ring (in 16B words) */
      u32 wqes_slot = slot << (log_wqe_sz - log_stride_per_wqe);
      const u32 wqe_cnt = rxq->wqe_cnt;
      mlx5dv_wqe_ds_t *wqe = rxq->wqes + wqes_slot;
      const int wqe_sz = 1 << log_wqe_sz;
      const int stride_per_wqe = 1 << log_stride_per_wqe;
      int current_data_seg = 0;

      /* In legacy mode, this function only refills head descriptors for each
         WQE, so RDMA_RXQ_MAX_CHAIN_SZ-1 data segments are skipped per WQE */
      const int log_skip_wqe = is_striding ? 0 : log_wqe_sz;

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

	  /*In striding RQ mode, the first 16B-word of the WQE is the SRQ header.
	     It is initialised as if it were a LINKED_LIST, as we have no guarantee
	     about what RDMA core does (CYCLIC_RQ or LINKED_LIST_RQ). In cyclic
	     mode, the SRQ header is ignored anyways... */

/* *INDENT-OFF* */
	  if (is_striding && !(current_data_seg & (wqe_sz - 1)))
	    *(mlx5dv_wqe_srq_next_t *) wqe = (mlx5dv_wqe_srq_next_t)
	    {
	      .rsvd0 = {0},
	      .next_wqe_index = clib_host_to_net_u16 (((wqes_slot >> log_wqe_sz) + 1) & (wqe_cnt - 1)),
              .signature = 0,
              .rsvd1 = {0}
	    };
/* *INDENT-ON* */

	  /* TODO: when log_skip_wqe > 2, hw_prefetcher doesn't work, lots of LLC store
	     misses occur for wqes, to be fixed... */
	  if (!is_striding || !(current_data_seg & ~(stride_per_wqe - 1)))
	    {
	      wqe[(0 << log_skip_wqe) + is_striding].addr = va[0];
	      wqe[(1 << log_skip_wqe) + is_striding].addr = va[1];
	      wqe[(2 << log_skip_wqe) + is_striding].addr = va[2];
	      wqe[(3 << log_skip_wqe) + is_striding].addr = va[3];
	      wqe[(4 << log_skip_wqe) + is_striding].addr = va[4];
	      wqe[(5 << log_skip_wqe) + is_striding].addr = va[5];
	      wqe[(6 << log_skip_wqe) + is_striding].addr = va[6];
	      wqe[(7 << log_skip_wqe) + is_striding].addr = va[7];
	      slot += 8;
	      n -= 8;
	    }
	  wqe += 8 << log_skip_wqe;
	  wqes_slot += 8 << log_skip_wqe;
	  current_data_seg += 8;
	  current_data_seg &= wqe_sz - 1;
	}

      /* In legacy mode, there is some work required to finish building the SG lists */
      if (!is_striding)
	{
	  int first_slot = slot - n_alloc;
	  rxq->incomplete_tail += n_alloc;
	  if (PREDICT_FALSE (rxq->n_total_additional_segs))
	    n_alloc =
	      rdma_device_legacy_input_refill_additional (vm, rd, rxq, ptd,
							  bt, first_slot,
							  n_alloc);
	}
      CLIB_MEMORY_STORE_BARRIER ();
      rxq->tail += n_alloc;
      if (is_striding)
	{
	  rxq->striding_wqe_tail += n_alloc >> log_stride_per_wqe;
	  rxq->wq_db[MLX5_RCV_DBR] =
	    clib_host_to_net_u32 (rxq->striding_wqe_tail);
	}
      else
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
			 const rdma_device_t * rd, u32 n_left,
			 const u32 * bi, u32 next_index, u16 * cqe_flags,
			 int is_mlx5dv)
{
  u32 n_trace = vlib_get_trace_count (vm, node);

  if (PREDICT_TRUE (0 == n_trace))
    return;

  while (n_trace && n_left)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
      if (PREDICT_TRUE
	  (vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0)))
	{
	  rdma_input_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next_index;
	  tr->hw_if_index = rd->hw_if_index;
	  tr->cqe_flags = is_mlx5dv ? clib_net_to_host_u16 (cqe_flags[0]) : 0;
	  n_trace--;
	}
      /* next */
      n_left--;
      cqe_flags++;
      bi++;
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
	  clib_prefetch_load (&wc[4 + 0]);
	  clib_prefetch_load (&wc[4 + 1]);
	  clib_prefetch_load (&wc[4 + 2]);
	  clib_prefetch_load (&wc[4 + 3]);
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

      cqe_last_byte &= 0xfc;	/* remove owner and solicited bits */

      if (cqe_last_byte == 0x2c)	/* OPCODE = 0x2 (Responder Send), Format = 0x3 (Compressed CQE) */
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

      if (cqe_last_byte == 0x20)	/* OPCODE = 0x2 (Responder Send), Format = 0x0 (no inline data) */
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

static_always_inline int
rdma_device_mlx5dv_striding_rq_parse_bc (int n_rx_packets, int *n_rx_segs,
					 u32 * bc)
{
/* Determine if slow path is needed  */
  int filler = 0;
  for (int i = 0; i < n_rx_packets; i++)
    {
      *n_rx_segs +=
	(bc[i] & CQE_BC_CONSUMED_STRIDES_MASK) >>
	CQE_BC_CONSUMED_STRIDES_SHIFT;
      filler |= ! !(bc[i] & CQE_BC_FILLER_MASK);
    }
  return n_rx_packets != *n_rx_segs || filler;
}

static_always_inline int
rdma_device_mlx5dv_legacy_rq_slow_path_needed (u32 buf_sz, int n_rx_packets,
					       u32 * bc)
{
#if defined CLIB_HAVE_VEC_SCALABLE
  i32 i = 0;
  boolxn m;
  u32xn bcv;
  i32 eno;
  u32xn thresh = u32xn_splat (buf_sz);
  scalable_vector_foreach2 (
    i, eno, m, n_rx_packets, 32, ({
      bcv = u32xn_load_unaligned (m, bc + i);
      if (boolxn_anytrue (m, u32xn_great_than (m, bcv, thresh)))
	return 1;
    }));
#elif defined CLIB_HAVE_VEC256
  u32x8 thresh8 = u32x8_splat (buf_sz);
  for (int i = 0; i < n_rx_packets; i += 8)
    if (!u32x8_is_all_zero (*(u32x8 *) (bc + i) > thresh8))
      return 1;
#elif defined CLIB_HAVE_VEC128
  u32x4 thresh4 = u32x4_splat (buf_sz);
  for (int i = 0; i < n_rx_packets; i += 4)
    if (!u32x4_is_all_zero (*(u32x4 *) (bc + i) > thresh4))
      return 1;
#else
  while (n_rx_packets)
    {
      if (*bc > buf_sz)
	return 1;
      bc++;
      n_rx_packets--;
    }
#endif

  return 0;
}

static_always_inline int
rdma_device_mlx5dv_l3_validate_and_swap_bc (rdma_per_thread_data_t
					    * ptd, int n_rx_packets, u32 * bc)
{
  u16 mask = CQE_FLAG_L3_HDR_TYPE_MASK | CQE_FLAG_L3_OK;
  u16 match = CQE_FLAG_L3_HDR_TYPE_IP4 << CQE_FLAG_L3_HDR_TYPE_SHIFT;

  /* verify that all ip4 packets have l3_ok flag set and convert packet
     length from network to host byte order */
  int skip_ip4_cksum = 1;

#if defined CLIB_HAVE_VEC_SCALABLE
  i32 i = 0;
  boolxn m;
  i32 eno;
  u16xn maskv = u16xn_splat (mask);
  u16xn matchv = u16xn_splat (match);
  u16xn flagsv;
  u32xn bcv;
  scalable_vector_foreach2 (
    i, eno, m, n_rx_packets, 16, ({
      flagsv = u16xn_load_unaligned (m, ptd->cqe_flags + i);
      boolxn ne = u16xn_unequal (m, matchv, u16xn_and (m, flagsv, maskv));
      if (boolxn_anytrue (m, ne))
	{
	  skip_ip4_cksum = 0;
	  goto fast_ntoh;
	}
    }));
fast_ntoh:
  scalable_vector_foreach2 (i, eno, m, n_rx_packets, 32, ({
			      bcv = u32xn_load_unaligned (m, bc + i);
			      bcv = u32xn_byte_swap (m, bcv);
			      u32xn_store_unaligned (m, bcv, bc + i);
			    }));
#elif defined CLIB_HAVE_VEC256
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
    if ((ptd->cqe_flags[i] & mask) != match)
      skip_ip4_cksum = 0;

  for (int i = 0; i < n_rx_packets; i++)
    bc[i] = clib_net_to_host_u32 (bc[i]);
#endif
  return skip_ip4_cksum;
}

static_always_inline u32
rdma_device_mlx5dv_fast_input (vlib_main_t * vm, rdma_rxq_t * rxq,
			       vlib_buffer_t ** bufs,
			       u32 qs_mask, vlib_buffer_t * bt,
			       u32 * to_next, u32 n_rx_segs, u32 * bc,
			       u32 bc_mask)
{
  vlib_buffer_t **b = bufs;
  u32 n_left = n_rx_segs;
  u32 n_rx_bytes = 0;
  vlib_buffer_copy_indices_from_ring (to_next, rxq->bufs,
				      rxq->head & qs_mask, rxq->size,
				      n_rx_segs);
  rxq->head += n_rx_segs;
  vlib_get_buffers (vm, to_next, bufs, n_rx_segs);
  while (n_left >= 8)
    {
      clib_prefetch_store (b[4]);
      vlib_buffer_copy_template (b[0], bt);
      n_rx_bytes += b[0]->current_length = bc[0] & bc_mask;
      clib_prefetch_store (b[5]);
      vlib_buffer_copy_template (b[1], bt);
      n_rx_bytes += b[1]->current_length = bc[1] & bc_mask;
      clib_prefetch_store (b[6]);
      vlib_buffer_copy_template (b[2], bt);
      n_rx_bytes += b[2]->current_length = bc[2] & bc_mask;
      clib_prefetch_store (b[7]);
      vlib_buffer_copy_template (b[3], bt);
      n_rx_bytes += b[3]->current_length = bc[3] & bc_mask;
      /* next */
      bc += 4;
      b += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      vlib_buffer_copy_template (b[0], bt);
      n_rx_bytes += b[0]->current_length = bc[0] & bc_mask;
      /* next */
      bc++;
      b++;
      n_left--;
    }
  return n_rx_bytes;
}

static_always_inline void
rdma_device_mlx5dv_legacy_rq_fix_chains (vlib_main_t * vm, rdma_rxq_t * rxq,
					 vlib_buffer_t ** bufs, u32 qs_mask,
					 u32 n)
{
  u32 buf_sz = rxq->buf_sz;
  uword slot = (rxq->head - n) & qs_mask;
  u32 *second = &rxq->second_bufs[slot];
  u32 n_wrap_around = (slot + n) & (qs_mask + 1) ? (slot + n) & qs_mask : 0;
  u8 *n_used_per_chain = &rxq->n_used_per_chain[slot];
  n -= n_wrap_around;
wrap_around:
  while (n > 0)
    {
      u16 total_length = bufs[0]->current_length;
      if (total_length > buf_sz)
	{
	  vlib_buffer_t *current_buf = bufs[0];
	  u8 current_chain_sz = 0;
	  current_buf->current_length = buf_sz;
	  total_length -= buf_sz;
	  current_buf->total_length_not_including_first_buffer = total_length;
	  current_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  current_buf->next_buffer = second[0];
	  do
	    {
	      current_buf = vlib_get_buffer (vm, current_buf->next_buffer);
	      current_buf->current_length = clib_min (buf_sz, total_length);
	      total_length -= current_buf->current_length;
	      current_chain_sz++;
	    }
	  while (total_length > 0);
	  current_buf->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
	  second[0] = current_buf->next_buffer;
	  current_buf->next_buffer = 0;
	  rxq->n_total_additional_segs += current_chain_sz;
	  n_used_per_chain[0] = current_chain_sz;
	}
      bufs++;
      second++;
      n_used_per_chain++;
      n--;
    }
  if (PREDICT_FALSE (n_wrap_around))
    {
      n = n_wrap_around;
      n_wrap_around = 0;
      second = rxq->second_bufs;
      n_used_per_chain = rxq->n_used_per_chain;
      goto wrap_around;
    }
}

static_always_inline u32
rdma_device_mlx5dv_striding_rq_input (vlib_main_t * vm,
				      rdma_per_thread_data_t * ptd,
				      rdma_rxq_t * rxq,
				      vlib_buffer_t * bt, u32 * to_next,
				      int n_rx_segs, int *n_rx_packets,
				      u32 * bc, int slow_path_needed)
{
  u32 mask = rxq->size - 1;
  u32 n_rx_bytes = 0;
  if (PREDICT_TRUE (!slow_path_needed))
    {
      vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
      n_rx_bytes +=
	rdma_device_mlx5dv_fast_input (vm, rxq, bufs, mask, bt, to_next,
				       n_rx_segs, bc, CQE_BC_BYTE_COUNT_MASK);
    }
  else				/* Slow path with multiseg */
    {
      vlib_buffer_t *pkt_head;	/*Current head buffer */
      vlib_buffer_t *pkt_prev;	/* Buffer processed at the previous iteration */
      u32 pkt_head_idx;
      vlib_buffer_t **pkt;
      uword n_segs_remaining = 0;	/*Remaining strides in current buffer */
      u32 n_bytes_remaining = 0;	/*Remaining bytes in current buffer */
      u32 *next_in_frame = to_next;
      u32 *next_to_free = ptd->to_free_buffers;
      bt->current_length = vlib_buffer_get_default_data_size (vm);
      do
	{
	  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	  u32 n_left = clib_min (n_rx_segs, VLIB_FRAME_SIZE);
	  n_rx_segs -= n_left;
	  vlib_buffer_copy_indices_from_ring (ptd->current_segs,
					      rxq->bufs, rxq->head & mask,
					      rxq->size, n_left);
	  rxq->head += n_left;
	  vlib_get_buffers (vm, ptd->current_segs, bufs, n_left);
	  pkt = bufs;
	  while (n_left > 0)
	    {
	      /* Initialize the current buffer as full size */
	      vlib_buffer_copy_template (pkt[0], bt);
	      if (!n_segs_remaining)	/* No pending chain */
		{
		  n_segs_remaining =
		    (bc[0] & CQE_BC_CONSUMED_STRIDES_MASK) >>
		    CQE_BC_CONSUMED_STRIDES_SHIFT;
		  pkt_head = pkt[0];
		  pkt_head_idx = ptd->current_segs[pkt - bufs];
		  n_bytes_remaining = bc[0] & CQE_BC_BYTE_COUNT_MASK;
		  pkt_head->total_length_not_including_first_buffer =
		    n_segs_remaining >
		    1 ? n_bytes_remaining - pkt[0]->current_length : 0;
		}
	      else		/* Perform chaining if it's a continuation buffer */
		{
		  pkt_prev->next_buffer = ptd->current_segs[pkt - bufs];
		  pkt_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  pkt[0]->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
		}
	      if (n_segs_remaining == 1)	/* Last buffer of the chain */
		{
		  pkt[0]->current_length = n_bytes_remaining;
		  if (bc[0] & CQE_BC_FILLER_MASK)
		    {
		      (next_to_free++)[0] = pkt_head_idx;
		      (*n_rx_packets)--;
		    }

		  else
		    {
		      (next_in_frame++)[0] = pkt_head_idx;
		      n_rx_bytes +=
			pkt_head->current_length +
			pkt_head->total_length_not_including_first_buffer;
		    }
		  /*Go to next CQE */
		  bc++;
		}
	      else
		{
		  n_bytes_remaining -= pkt[0]->current_length;
		  pkt_prev = pkt[0];
		}
	      n_segs_remaining--;
	      n_left--;
	      pkt++;
	    }

	}
      while (n_rx_segs > 0);
      vlib_buffer_free (vm, ptd->to_free_buffers,
			next_to_free - ptd->to_free_buffers);
    }
  return n_rx_bytes;
}

static_always_inline uword
rdma_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame, rdma_device_t * rd,
			  u16 qid, const int use_mlx5dv)
{
  rdma_main_t *rm = &rdma_main;
  vnet_main_t *vnm = vnet_get_main ();
  rdma_per_thread_data_t *ptd = vec_elt_at_index (rm->per_thread_data,
						  vm->thread_index);
  rdma_rxq_t *rxq = vec_elt_at_index (rd->rxqs, qid);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u32 __clib_aligned (32) byte_cnts[VLIB_FRAME_SIZE];
  vlib_buffer_t bt;
  u32 next_index, *to_next, n_left_to_next, n_rx_bytes = 0;
  int n_rx_packets, skip_ip4_cksum = 0;
  u32 mask = rxq->size - 1;
  const int is_striding = ! !(rd->flags & RDMA_DEVICE_F_STRIDING_RQ);

  if (use_mlx5dv)
    n_rx_packets = rdma_device_poll_cq_mlx5dv (rd, rxq, byte_cnts,
					       ptd->cqe_flags);
  else
    n_rx_packets = ibv_poll_cq (rxq->cq, VLIB_FRAME_SIZE, wc);

  /* init buffer template */
  vlib_buffer_copy_template (&bt, &ptd->buffer_template);
  vnet_buffer (&bt)->sw_if_index[VLIB_RX] = rd->sw_if_index;
  bt.buffer_pool_index = rd->pool;

  if (PREDICT_FALSE (n_rx_packets <= 0))
    goto refill;

  /* update buffer template for input feature arcs if any */
  next_index = rd->per_interface_next_index;
  if (PREDICT_FALSE (vnet_device_input_have_features (rd->sw_if_index)))
    vnet_feature_start_device_input_x1 (rd->sw_if_index, &next_index, &bt);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (use_mlx5dv)
    {
      u32 *bc = byte_cnts;
      int slow_path_needed;
      skip_ip4_cksum =
	rdma_device_mlx5dv_l3_validate_and_swap_bc (ptd, n_rx_packets, bc);
      if (is_striding)
	{
	  int n_rx_segs = 0;
	  slow_path_needed =
	    rdma_device_mlx5dv_striding_rq_parse_bc (n_rx_packets,
						     &n_rx_segs, bc);
	  n_rx_bytes =
	    rdma_device_mlx5dv_striding_rq_input (vm, ptd, rxq, &bt,
						  to_next, n_rx_segs,
						  &n_rx_packets, bc,
						  slow_path_needed);
	}
      else
	{
	  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
	  slow_path_needed =
	    rdma_device_mlx5dv_legacy_rq_slow_path_needed (rxq->buf_sz,
							   n_rx_packets, bc);
	  n_rx_bytes = rdma_device_mlx5dv_fast_input (
	    vm, rxq, bufs, mask, &bt, to_next, n_rx_packets, bc, ~0);

	  /* If there are chained buffers, some of the head buffers have a current length
	     higher than buf_sz: it needs to be fixed */
	  if (PREDICT_FALSE (slow_path_needed))
	    rdma_device_mlx5dv_legacy_rq_fix_chains (vm, rxq, bufs, mask,
						     n_rx_packets);
	}
    }
  else
    {
      vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
      vlib_buffer_copy_indices_from_ring (to_next, rxq->bufs,
					  rxq->head & mask,
					  rxq->size, n_rx_packets);
      vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
      rxq->head += n_rx_packets;
      n_rx_bytes =
	rdma_device_input_bufs (vm, rd, bufs, wc, n_rx_packets, &bt);

    }

  rdma_device_input_ethernet (vm, node, rd, next_index, skip_ip4_cksum);
  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);
  rdma_device_input_trace (vm, node, rd, n_rx_packets, to_next,
			   next_index, ptd->cqe_flags, use_mlx5dv);
  /* reset flags to zero for the next run */
  if (use_mlx5dv)
    clib_memset_u16 (ptd->cqe_flags, 0, VLIB_FRAME_SIZE);
  vlib_increment_combined_counter (vnm->interface_main.
				   combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, rd->hw_if_index,
				   n_rx_packets, n_rx_bytes);
refill:
  rdma_device_input_refill (vm, rd, rxq, &bt, use_mlx5dv, is_striding);
  return n_rx_packets;
}

VLIB_NODE_FN (rdma_input_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u32 n_rx = 0;
  rdma_main_t *rm = &rdma_main;
  vnet_hw_if_rxq_poll_vector_t *pv;
  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);
  for (int i = 0; i < vec_len (pv); i++)
    {
      rdma_device_t *rd;
      rd = vec_elt_at_index (rm->devices, pv[i].dev_instance);
      if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_ADMIN_UP) == 0)
	continue;

      if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_ERROR))
	continue;

      if (PREDICT_TRUE (rd->flags & RDMA_DEVICE_F_MLX5DV))
	n_rx +=
	  rdma_device_input_inline (vm, node, frame, rd, pv[i].queue_id, 1);
      else
	n_rx +=
	  rdma_device_input_inline (vm, node, frame, rd, pv[i].queue_id, 0);
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
