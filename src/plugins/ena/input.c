/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>

#define ENA_RX_REFILL_BATCH 32

#define foreach_ena_input_error _ (BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f, s) ENA_INPUT_ERROR_##f,
  foreach_ena_input_error
#undef _
    ENA_INPUT_N_ERROR,
} ena_input_error_t;

static char *ena_input_error_strings[] = {
#define _(n, s) s,
  foreach_ena_input_error
#undef _
};

typedef struct
{
  u8 log2_n_desc;
  u16 n_desc;
  u32 mask;
  ena_rx_cdesc_status_t st_or;
  ena_rx_cdesc_status_t st_and;
  u16 *comp_sqe_indices;
  u32 *sq_buffer_indices;
} ena_rx_ctx_t;

static_always_inline void
ena_device_input_status_to_flags (ena_rx_cdesc_status_t *statuses, u32 *flags,
				  u32 n_desc, vlib_frame_bitmap_t first_bmp,
				  int maybe_chained)
{
  const ena_rx_cdesc_status_t mask_first = { .first = 1 },
			      match_first1 = { .first = 1 };

  const ena_rx_cdesc_status_t mask_last = { .last = 1 },
			      match_last0 = { .last = 0 };

  const ena_rx_cdesc_status_t mask_l4_csum = { .ipv4_frag = 1,
					       .l4_csum_checked = 1,
					       .l4_csum_err = 1 },
			      match_l4_csum_ok = { .l4_csum_checked = 1 };

  clib_memset_u32 (statuses + n_desc, 0, 8);
#if defined(CLIB_HAVE_VEC128)

#if defined(CxLIB_HAVE_VEC512)
#define N	    16
#define u32xN	    u32x16
#define u32xNu	    u32x16u
#define u32xN_splat u32x16_splat
#elif defined(CxLIB_HAVE_VEC256)
#define N	    8
#define u32xN	    u32x8
#define u32xNu	    u32x8u
#define u32xN_splat u32x8_splat
#else
#define N	    4
#define u32xN	    u32x4
#define u32xNu	    u32x4u
#define u32xN_splat u32x4_splat
#endif

  const u32xN st_mask_first = u32xN_splat (mask_first.as_u32);
  const u32xN st_match_first1 = u32xN_splat (match_first1.as_u32);
  const u32xN st_mask_last = u32xN_splat (mask_last.as_u32);
  const u32xN st_match_last0 = u32xN_splat (match_last0.as_u32);
  const u32xN st_mask_l4_csum = u32xN_splat (mask_l4_csum.as_u32);
  const u32xN st_match_l4_csum_ok = u32xN_splat (match_l4_csum_ok.as_u32);
  const u32xN f_total_len_valid = u32xN_splat (VLIB_BUFFER_TOTAL_LENGTH_VALID);
  const u32xN f_next_preset = u32xN_splat (VLIB_BUFFER_NEXT_PRESENT);
  const u32xN f_l4_csum = u32xN_splat (VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
				       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);

  for (u32 i = 0; i < round_pow2 (n_desc, 2 * N); i += 2 * N)
    {
      uword msk = 0;
      u32xN f0, f1, r0, r1;
      u32xN s0 = ((u32xNu *) (statuses + i))[0];
      u32xN s1 = ((u32xNu *) (statuses + i))[1];

      r0 = (s0 & st_mask_first) == st_match_first1;
      r1 = (s1 & st_mask_first) == st_match_first1;
      f0 = r0 & f_total_len_valid;
      f1 = r1 & f_total_len_valid;

      if (maybe_chained)
	{
#if defined(CxLIB_HAVE_VEC512)
	  u64 msb_mask = 0x1111111111111111;
	  msk = bit_extract_u64 (u8x64_msb_mask ((u8x64) r0), msb_mask);
	  msk |= bit_extract_u64 (u8x64_msb_mask ((u8x64) r1), msb_mask) << 16;
#elif defined(CxLIB_HAVE_VEC256)
	  msk = u8x32_msb_mask ((u8x32) r0);
	  msk |= (u64) u8x32_msb_mask ((u8x32) r1) << 32;
	  msk = bit_extract_u64 (msk, 0x1111111111111111);
#else
	  msk = u8x16_msb_mask ((u8x16) r0);
	  msk |= (u32) u8x16_msb_mask ((u8x16) r1) << 16;
	  msk = bit_extract_u32 (msk, 0x11111111);
#endif
	  first_bmp[i / uword_bits] |= msk << (i % uword_bits);
	}

      f0 |= ((s0 & st_mask_last) == st_match_last0) & f_next_preset;
      f1 |= ((s1 & st_mask_last) == st_match_last0) & f_next_preset;

      f0 |= ((s0 & st_mask_l4_csum) == st_match_l4_csum_ok) & f_l4_csum;
      f1 |= ((s1 & st_mask_l4_csum) == st_match_l4_csum_ok) & f_l4_csum;

      ((u32xNu *) (flags + i))[0] = f0;
      ((u32xNu *) (flags + i))[1] = f1;
    }
#else
  while (n_left)
    {
      u16 f = 0;
      ena_rx_cdesc_status_t st = statuses++[0];

      if ((st.as_u32 & mask_first.as_u32) == match_first1.as_u32)
	f |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

      if ((st.as_u32 & mask_last.as_u32) == match_last0.as_u32)
	f |= VLIB_BUFFER_NEXT_PRESENT;

      if ((st.as_u32 & mask_l4_csum.as_u32) == match_l4_csum_ok.as_u32)
	f |= VNET_BUFFER_F_L4_CHECKSUM_COMPUTED |
	     VNET_BUFFER_F_L4_CHECKSUM_CORRECT;

      flags++[0] = f;
      n_left--;
    }
#endif
}

static_always_inline u16
ena_device_input_cq_dequeue_no_wrap (ena_rx_ctx_t *ctx, ena_rxq_t *rxq,
				     ena_rx_cdesc_status_t *statuses,
				     u16 *lengths, u16 *csi)
{
  u32 next = rxq->cq_next;
  ena_rx_cdesc_t *cqes = rxq->cqes;
  u32 phase = 1 & (next >> ctx->log2_n_desc);
  u16 index = next & ctx->mask;
  ena_rx_cdesc_t *cd = cqes + index;
  ena_rx_cdesc_status_t st;
  u32 n_to_check, i = 0;

  st = cd->status;
  if (st.phase == phase)
    return 0;

  n_to_check = clib_min (VLIB_FRAME_SIZE, ctx->n_desc - index);

  ctx->st_or.as_u32 |= st.as_u32;
  ctx->st_and.as_u32 &= st.as_u32;
  statuses[i] = st;
  lengths[i] = cd->length;
  csi[i] = cd->req_id;
  i++;
  cd++;

more:
  for (st = cd->status; i < n_to_check && st.phase != phase;
       i++, st = (++cd)->status)
    {
      ctx->st_or.as_u32 |= st.as_u32;
      ctx->st_and.as_u32 &= st.as_u32;
      statuses[i] = st;
      lengths[i] = cd->length;
      csi[i] = cd->req_id;
    }

  if (i == n_to_check)
    {
      n_to_check = VLIB_FRAME_SIZE - n_to_check;
      if (n_to_check)
	{
	  phase ^= 1;
	  cd = cqes;
	  goto more;
	}
    }

  /* revert incomplete */
  if (PREDICT_FALSE (statuses[i - 1].last == 0))
    {
      i--;
      while (i && statuses[i - 1].last == 0)
	i--;
    }

  return i;
}

static_always_inline void
ena_device_input_refill (vlib_main_t *vm, ena_rx_ctx_t *ctx, ena_rxq_t *rxq,
			 int use_va)
{
  const u64x2 flip_phase = (ena_rx_desc_t){ .lo.phase = 1 }.as_u64x2;
  u32 buffer_indices[ENA_RX_REFILL_BATCH];
  uword dma_addr[ENA_RX_REFILL_BATCH];
  u32 n_alloc, n_compl_sqes = rxq->n_compl_sqes;
  u16 *csi = ctx->comp_sqe_indices;
  ena_rx_desc_t *sqes = rxq->sqes;

  while (n_compl_sqes > 0)
    {
      n_alloc = vlib_buffer_alloc_from_pool (
	vm, buffer_indices, clib_min (ENA_RX_REFILL_BATCH, n_compl_sqes),
	rxq->buffer_pool_index);

      if (PREDICT_FALSE (n_alloc == 0))
	break;

      vlib_get_buffers_with_offset (vm, buffer_indices, (void **) dma_addr,
				    ENA_RX_REFILL_BATCH,
				    STRUCT_OFFSET_OF (vlib_buffer_t, data));

      if (!use_va)
	for (u32 i = 0; i < n_alloc; i++)
	  dma_addr[i] = vlib_physmem_get_pa (vm, (void *) dma_addr[i]);

      for (u32 i = 0; i < n_alloc; i++)
	{
	  u16 slot = csi[i];
	  u64x2 r = sqes[slot].as_u64x2 ^ flip_phase;
	  ctx->sq_buffer_indices[slot] = buffer_indices[i];
	  r[1] = dma_addr[i];
	  sqes[slot].as_u64x2 = r; /* write SQE as single 16-byte store */
	}

      csi += n_alloc;
      n_compl_sqes -= n_alloc;
    }

  if (n_compl_sqes == rxq->n_compl_sqes)
    return;

  rxq->sq_next += rxq->n_compl_sqes - n_compl_sqes;
  __atomic_store_n (rxq->sq_db, rxq->sq_next, __ATOMIC_RELEASE);

  if (PREDICT_FALSE (n_compl_sqes))
    clib_memmove (ctx->comp_sqe_indices, csi, n_compl_sqes * sizeof (csi[0]));

  rxq->n_compl_sqes = n_compl_sqes;
}

static_always_inline uword
ena_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, ena_device_t *ed, ena_rxq_t *rxq,
			 int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE], **b;
  ena_rx_cdesc_status_t statuses[VLIB_FRAME_SIZE + 8];
  u16 lengths[VLIB_FRAME_SIZE + 8], *l;
  u32 flags[VLIB_FRAME_SIZE + 8], *f;
  u16 *csi;
  uword n_rx_packets = 0, n_rx_bytes = 0;
  vlib_frame_bitmap_t head_bmp = {};
  u32 n_trace, n_deq, n_left;
  u32 cq_next = rxq->cq_next;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t bt;
  vlib_frame_t *next_frame;
  u32 *bi;
  int maybe_chained;

  ena_rx_ctx_t ctx = { .log2_n_desc = rxq->log2_n_desc,
		       .n_desc = 1U << ctx.log2_n_desc,
		       .mask = pow2_mask (ctx.log2_n_desc),
		       .st_and.as_u32 = ~0,
		       .comp_sqe_indices = ena_rxq_get_compl_sqe_indices (rxq),
		       .sq_buffer_indices = rxq->sq_buffer_indices };

  /* we may have completed SQE indices from previous run */
  csi = ctx.comp_sqe_indices + rxq->n_compl_sqes;

  n_deq =
    ena_device_input_cq_dequeue_no_wrap (&ctx, rxq, statuses, lengths, csi);

  if (n_deq == 0)
    goto refill;

  rxq->n_compl_sqes += n_deq;

  maybe_chained = ctx.st_and.first && ctx.st_and.last ? 0 : 1;

  /* initialize buffer headers and find next node */
  vlib_buffer_copy_template (&bt, &ed->buffer_template);

  if (PREDICT_FALSE (ed->per_interface_next_index != ~0))
    next_index = ed->per_interface_next_index;

  if (PREDICT_FALSE (vnet_device_input_have_features (ed->sw_if_index)))
    vnet_feature_start_device_input_x1 (ed->sw_if_index, &next_index, &bt);

  next_frame =
    vlib_get_next_frame_internal (vm, node, next_index, /* new frame */ 1);
  bi = vlib_frame_vector_args (next_frame);

  /* move buffer indices from the ring */
  for (u32 i = 0; i < n_deq; i++)
    {
      u32 slot = csi[i];
      bi[i] = ctx.sq_buffer_indices[slot];
      ctx.sq_buffer_indices[slot] = VLIB_BUFFER_INVALID_INDEX;
    }

  vlib_get_buffers (vm, bi, buffers, n_deq);

  if (PREDICT_FALSE (maybe_chained))
    ena_device_input_status_to_flags (statuses, flags, n_deq, head_bmp, 1);
  else
    ena_device_input_status_to_flags (statuses, flags, n_deq, head_bmp, 0);

  for (b = buffers, l = lengths, f = flags, n_left = n_deq; n_left >= 8;
       b += 4, f += 4, l += 4, n_left -= 4)
    {
      clib_prefetch_store (b[4]);
      clib_prefetch_store (b[5]);
      clib_prefetch_store (b[6]);
      clib_prefetch_store (b[7]);
      vlib_buffer_copy_template (b[0], &bt);
      n_rx_bytes += b[0]->current_length = l[0];
      b[0]->flags = f[0];
      vlib_buffer_copy_template (b[1], &bt);
      n_rx_bytes += b[1]->current_length = l[1];
      b[1]->flags = f[1];
      vlib_buffer_copy_template (b[2], &bt);
      n_rx_bytes += b[2]->current_length = l[2];
      b[2]->flags = f[2];
      vlib_buffer_copy_template (b[3], &bt);
      n_rx_bytes += b[3]->current_length = l[3];
      b[3]->flags = f[3];
    }

  for (; n_left > 0; b += 1, f += 1, l += 1, n_left -= 1)
    {
      vlib_buffer_copy_template (b[0], &bt);
      n_rx_bytes += b[0]->current_length = l[0];
      b[0]->flags = f[0];
    }

  if (maybe_chained)
    {
      vlib_buffer_t *hb = 0;
      vlib_frame_bitmap_t tail_buf_bmp = {};
      u32 i, total_len = 0, head_flags = 0, tail_flags = 0;
      n_rx_packets = vlib_frame_bitmap_count_set_bits (head_bmp);

      vlib_frame_bitmap_init (tail_buf_bmp, n_deq);
      vlib_frame_bitmap_xor (tail_buf_bmp, head_bmp);

      foreach_vlib_frame_bitmap_set_bit_index (i, tail_buf_bmp)
	{
	  vlib_buffer_t *pb = buffers[i - 1];
	  /* only store opertations here */
	  pb->next_buffer = bi[i];
	  if (vlib_frame_bitmap_is_bit_set (tail_buf_bmp, i - 1) == 0)
	    {
	      if (hb)
		{
		  hb->total_length_not_including_first_buffer = total_len;
		  /* tail descriptor contains protocol info so we need to
		   * combine head and tail buffer flags */
		  hb->flags = head_flags | tail_flags;
		}
	      head_flags = flags[i - 1];
	      total_len = 0;
	      hb = pb;
	    }
	  total_len += lengths[i];
	  tail_flags = flags[i];
	}

      hb->total_length_not_including_first_buffer = total_len;
      hb->flags = head_flags | tail_flags;
    }
  else
    n_rx_packets = n_deq;

  /* packet tracing */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 i;
      if (!maybe_chained)
	vlib_frame_bitmap_init (head_bmp, n_deq);
      foreach_vlib_frame_bitmap_set_bit_index (i, head_bmp)
	{
	  vlib_buffer_t *b = buffers[i];
	  if (vlib_trace_buffer (vm, node, next_index, b, 0))
	    {
	      u32 j = i;
	      ena_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next_index;
	      tr->qid = rxq->qid;
	      tr->hw_if_index = ed->hw_if_index;
	      tr->n_desc = 1;
	      tr->length = lengths[i];
	      tr->req_id = csi[i];
	      tr->status = statuses[i];
	      while (statuses[j].last == 0)
		{
		  j++;
		  tr->n_desc++;
		  tr->length += lengths[j];
		}
	      tr->status = statuses[j];

	      if (-n_trace)
		goto trace_done;
	    }
	}
    trace_done:
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_FALSE (maybe_chained))
    clib_compress_u32 (bi, bi, head_bmp, n_deq);

  if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
    {
      ethernet_input_frame_t *ef;
      next_frame->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (next_frame);
      ef->sw_if_index = ed->sw_if_index;
      ef->hw_if_index = ed->hw_if_index;

      if (ctx.st_or.l3_csum_err == 0)
	next_frame->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      vlib_frame_no_append (next_frame);
    }

  vlib_put_next_frame (vm, node, next_index, VLIB_FRAME_SIZE - n_rx_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, ed->hw_if_index, n_rx_packets, n_rx_bytes);

  rxq->cq_next = cq_next + n_deq;

refill:
  if (ed->va_dma)
    ena_device_input_refill (vm, &ctx, rxq, 1);
  else
    ena_device_input_refill (vm, &ctx, rxq, 0);

  return n_rx_packets;
}

VLIB_NODE_FN (ena_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  vnet_hw_if_rxq_poll_vector_t *pv;

  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  for (int i = 0; i < vec_len (pv); i++)
    {
      ena_device_t *ed = ena_get_device (pv[i].dev_instance);
      ena_rxq_t *rxq = *pool_elt_at_index (ed->rxqs, pv[i].queue_id);

      if (ena_queue_state_set_in_use (&rxq->state) != ENA_QUEUE_STATE_DISABLED)
	{
	  n_rx += ena_device_input_inline (vm, node, frame, ed, rxq, 0);
	  ena_queue_state_set_ready (&rxq->state);
	}
    }

  return n_rx;
}

VLIB_REGISTER_NODE (ena_input_node) = {
  .name = "ena-input",
  .sibling_of = "device-input",
  .format_trace = format_ena_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = ENA_INPUT_N_ERROR,
  .error_strings = ena_input_error_strings,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};
