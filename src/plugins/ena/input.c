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

#define foreach_ena_input_error _ (BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f, s) ENA_INPUT_ERROR_##f,
  foreach_ena_input_error
#undef _
    ENA_INPUT_N_ERROR,
} ena_input_error_t;

static __clib_unused char *ena_input_error_strings[] = {
#define _(n, s) s,
  foreach_ena_input_error
#undef _
};

static_always_inline u16
ena_device_input_cq_dequeue_no_wrap (ena_rx_cdesc_t *cd, u32 next,
				     u8 log2_n_desc,
				     ena_rx_cdesc_status_t *statuses,
				     u16 *lengths, u16 n_left)
{
  u16 mask = pow2_mask (log2_n_desc);
  u32 phase = 1 & (next >> log2_n_desc);
  u16 index = next & mask;
  ena_rx_cdesc_t *cd0;

  cd0 = cd += index;

  if (cd->status.phase == phase)
    return 0;

  statuses++[0] = cd->status;
  lengths++[0] = cd->length;
  n_left = clib_min (n_left, (1U << log2_n_desc) - index) - 1;
  cd++;

  while (n_left > 0 && cd->status.phase != phase)
    {
      statuses++[0] = cd->status;
      lengths++[0] = cd->length;
      n_left--;
      cd++;
    }

  /* revert incomplete */
  if (PREDICT_FALSE (cd[-1].status.last == 0))
    {
      cd--;
      while (cd > cd0 && cd[-1].status.last == 0)
	cd--;
    }

  return cd - cd0;
}

static_always_inline void
ena_rx_desc_write (ena_rx_desc_t *d, ena_rx_desc_t *t, u64 addr)
{
  u64x2 r = (u64x2) t->as_u32x4;
  r[1] = addr;
  d->as_u32x4 = (u32x4) r;
}

static_always_inline void
ena_device_input_refill (vlib_main_t *vm, ena_rxq_t *rxq, int use_va)
{
  u8 log2_n_desc = rxq->log2_n_desc;
  u32 n_desc = 1U << log2_n_desc;
  u32 n, n_refill, first, offset, *bi;

  n_refill = n_desc - rxq->n_enq;

  /* we refill in blocks of 8 buffers */
  if (n_refill < 8)
    return;

  first = rxq->next - n_refill;
  offset = first & pow2_mask (log2_n_desc);
  bi = rxq->buffers + offset;

  n_refill &= ~7U;

  n = vlib_buffer_alloc_from_pool (vm, bi, n_refill, rxq->buffer_pool_index);

  if (PREDICT_FALSE (n < n_refill))
    {
      u32 n_free = n & 7;
      n -= n_free;
      vlib_buffer_free (vm, bi + n, n_free);
      if (n == 0)
	return;
      n_refill = n;
    }

  if (n_refill)
    {
      ena_rx_desc_t *d = rxq->sqes + offset;
      ena_rx_desc_t t = rxq->desc_template;
      t.phase = first >> log2_n_desc;
      rxq->n_enq += n_refill;

      while (n_refill >= 8)
	{
	  vlib_buffer_t *b[8];
	  vlib_get_buffers (vm, bi, b, 8);
	  if (use_va)
	    {
	      ena_rx_desc_write (d + 0, &t, vlib_buffer_get_va (b[0]));
	      ena_rx_desc_write (d + 1, &t, vlib_buffer_get_va (b[1]));
	      ena_rx_desc_write (d + 2, &t, vlib_buffer_get_va (b[2]));
	      ena_rx_desc_write (d + 3, &t, vlib_buffer_get_va (b[3]));
	      ena_rx_desc_write (d + 4, &t, vlib_buffer_get_va (b[4]));
	      ena_rx_desc_write (d + 5, &t, vlib_buffer_get_va (b[5]));
	      ena_rx_desc_write (d + 6, &t, vlib_buffer_get_va (b[6]));
	      ena_rx_desc_write (d + 7, &t, vlib_buffer_get_va (b[7]));
	    }
	  else
	    {
	      ena_rx_desc_write (d + 0, &t, vlib_buffer_get_pa (vm, b[0]));
	      ena_rx_desc_write (d + 1, &t, vlib_buffer_get_pa (vm, b[1]));
	      ena_rx_desc_write (d + 2, &t, vlib_buffer_get_pa (vm, b[2]));
	      ena_rx_desc_write (d + 3, &t, vlib_buffer_get_pa (vm, b[3]));
	      ena_rx_desc_write (d + 4, &t, vlib_buffer_get_pa (vm, b[4]));
	      ena_rx_desc_write (d + 5, &t, vlib_buffer_get_pa (vm, b[5]));
	      ena_rx_desc_write (d + 6, &t, vlib_buffer_get_pa (vm, b[6]));
	      ena_rx_desc_write (d + 7, &t, vlib_buffer_get_pa (vm, b[7]));
	    }
	  n_refill -= 8;
	  bi += 8;
	  d += 8;
	}
      __atomic_store_n (rxq->sq_db, rxq->next + rxq->n_enq, __ATOMIC_RELEASE);
    }
}

static_always_inline uword
ena_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, ena_device_t *ed, u16 qid,
			 int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 buffer_indices[VLIB_FRAME_SIZE];
  ena_rx_cdesc_status_t statuses[VLIB_FRAME_SIZE];
  u16 lengths[VLIB_FRAME_SIZE];
  uword n_rx_packets = 0, n_rx_bytes = 0;
  ena_rxq_t *rxq = pool_elt_at_index (ed->rxqs, qid);
  vlib_frame_bitmap_t head_buf_bmp = {}, tail_buf_bmp = {};
  u32 n_tail_desc = 0;
  ena_rx_cdesc_status_t status_match, status_mask;
  u32 n_deq = 0;
  u32 next = rxq->next;
  u8 log2_n_desc = rxq->log2_n_desc;
  u32 mask = pow2_mask (log2_n_desc);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t bt;
  vlib_frame_t *f;
  u32 *to;

  n_deq = ena_device_input_cq_dequeue_no_wrap (
    rxq->cqes, next, log2_n_desc, statuses, lengths, VLIB_FRAME_SIZE);

  if (n_deq == 0)
    goto refill;

  vlib_buffer_copy_indices (buffer_indices, rxq->buffers + (next & mask),
			    n_deq);

  /* if case of ring wrap there may be more */
  if (PREDICT_FALSE (((next + n_deq) & mask) == 0))
    {
      u32 n = ena_device_input_cq_dequeue_no_wrap (
	rxq->cqes + n_deq, next + n_deq, log2_n_desc, statuses + n_deq,
	lengths + n_deq, VLIB_FRAME_SIZE - n_deq);
      if (n)
	{
	  vlib_buffer_copy_indices (buffer_indices + n_deq, rxq->buffers, n);
	  n_deq += n;
	}
    }

  /* classify descriptors into 3 groups, each represented by bitmap:
   * - head descriptors
   * - tail descriptors
   * - metadata descriptors */

  status_mask = (ena_rx_cdesc_status_t){ .first = 1 };
  status_match = status_mask;
  clib_mask_compare_masked_u32 (status_match.as_u32, status_mask.as_u32,
				&statuses[0].as_u32, head_buf_bmp, n_deq);

  n_rx_packets = vlib_frame_bitmap_count_set_bits (head_buf_bmp);

  if (PREDICT_FALSE ((n_rx_packets < n_deq)))
    {
      vlib_frame_bitmap_init (tail_buf_bmp, n_deq);
      vlib_frame_bitmap_xor (tail_buf_bmp, head_buf_bmp);
      n_tail_desc = n_deq - n_rx_packets;
    }

  /* initialize buffer headers */
  vlib_buffer_copy_template (&bt, &ed->buffer_template);

  if (PREDICT_FALSE (ed->per_interface_next_index != ~0))
    next_index = ed->per_interface_next_index;

  if (PREDICT_FALSE (vnet_device_input_have_features (ed->sw_if_index)))
    vnet_feature_start_device_input_x1 (ed->sw_if_index, &next_index, &bt);

  for (u32 i = 0; i < n_deq; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      vlib_buffer_copy_template (b, &bt);
      b->current_length = lengths[i];
    }

  if (n_tail_desc)
    {
      vlib_buffer_t *f, *p;
      u32 i;
      foreach_vlib_frame_bitmap_set_bit_index (i, tail_buf_bmp)
	{
	  p = vlib_get_buffer (vm, buffer_indices[i - 1]);
	  if (vlib_frame_bitmap_is_bit_set (tail_buf_bmp, i - 1) == 0)
	    f = p;
	  p->flags = bt.flags & VLIB_BUFFER_NEXT_PRESENT;
	  p->next_buffer = buffer_indices[i];
	  f->total_length_not_including_first_buffer += lengths[i];
	}
    }

  /* packet tracing */
  u32 n_trace;
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 i;
      foreach_vlib_frame_bitmap_set_bit_index (i, head_buf_bmp)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  if (vlib_trace_buffer (vm, node, next_index, b, 0))
	    {
	      u32 j = i;
	      ena_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next_index;
	      tr->qid = qid;
	      tr->hw_if_index = ed->hw_if_index;
	      tr->n_desc = 1;
	      tr->length = lengths[i];
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

  /* enqueue to next node */
  f = vlib_get_next_frame_internal (vm, node, next_index, /* new frame */ 1);
  to = vlib_frame_vector_args (f);

  if (n_deq == n_rx_packets)
    vlib_buffer_copy_indices (to, buffer_indices, n_deq);
  else
    clib_compress_u32 (to, buffer_indices, head_buf_bmp, n_deq);

  if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
    {
      ethernet_input_frame_t *ef;
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = ed->sw_if_index;
      ef->hw_if_index = ed->hw_if_index;

      // if ((or_qw1 & AVF_RXD_ERROR_IPE) == 0)
      // f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, VLIB_FRAME_SIZE - n_rx_packets);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, ed->hw_if_index, n_rx_packets, n_rx_bytes);

  rxq->next = next + n_deq;
  rxq->n_enq -= n_deq;

refill:
  if (ed->va_dma)
    ena_device_input_refill (vm, rxq, 1);
  else
    ena_device_input_refill (vm, rxq, 0);

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
      ena_device_t *ad = ena_get_device (pv[i].dev_instance);
      if ((ad->admin_up) == 0)
	continue;
      n_rx += ena_device_input_inline (vm, node, frame, ad, pv[i].queue_id, 0);
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
