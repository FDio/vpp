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

#define foreach_ena_input_error                                               \
  _ (BUFFER_ALLOC, "buffer alloc error")                                      \
  _ (METADATA_DESC, "metadata descriptors")                                   \
  _ (CHAINED_BUFFERS, "chained buffers")

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

  while (n_left != cd->status.phase == phase)
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
  vlib_frame_bitmap_t head_buf_bmp, tail_buf_bmp = {};
  u32 n_tail_desc = 0;
  u32 n_metadata_desc = 0;
  ena_rx_cdesc_status_t status_match, status_mask;
  u32 n_deq = 0;
  u32 next = rxq->next;
  u8 log2_n_desc = rxq->log2_n_desc;
  u32 mask = pow2_mask (log2_n_desc);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t bt;

  n_deq = ena_device_input_cq_dequeue_no_wrap (
    rxq->cqes, next, log2_n_desc, statuses, lengths, VLIB_FRAME_SIZE);

  if (n_deq == 0)
    return 0;

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

  status_mask = (ena_rx_cdesc_status_t){ .first = 1, .buffer = 1 };
  status_match = status_mask;
  clib_mask_compare_masked_u32 (status_match.as_u32, status_mask.as_u32,
				&statuses[0].as_u32, head_buf_bmp, n_deq);

  n_rx_packets = vlib_frame_bitmap_count_set_bits (head_buf_bmp);

  if (PREDICT_FALSE ((n_rx_packets < n_deq)))
    {
      status_match = (ena_rx_cdesc_status_t){ .first = 0, .buffer = 1 };

      clib_mask_compare_masked_u32 (status_match.as_u32, status_mask.as_u32,
				    &statuses[0].as_u32, tail_buf_bmp, n_deq);

      n_tail_desc = vlib_frame_bitmap_count_set_bits (tail_buf_bmp);
      n_metadata_desc = n_deq - n_tail_desc - n_rx_packets;

      if (n_metadata_desc)
	{
	  u32 drop[VLIB_FRAME_SIZE];
	  vlib_frame_bitmap_t metadata_bmp = {};
	  vlib_frame_bitmap_init (metadata_bmp, n_deq);
	  vlib_frame_bitmap_xor (metadata_bmp, head_buf_bmp);
	  vlib_frame_bitmap_xor (metadata_bmp, tail_buf_bmp);
	  clib_compress_u32 (drop, buffer_indices, metadata_bmp, n_deq);
	  vlib_buffer_free_no_next (vm, drop, n_metadata_desc);
	  vlib_node_increment_counter (vm, node->node_index,
				       ENA_INPUT_ERROR_METADATA_DESC,
				       n_metadata_desc);
	}
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

  u32 *to_next;
  u32 n_left_to_next;
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = ed->sw_if_index;
      ef->hw_if_index = ed->hw_if_index;

      // if ((or_qw1 & AVF_RXD_ERROR_IPE) == 0)
      // f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      vlib_frame_no_append (f);
    }

  n_left_to_next -= n_rx_packets;
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, ed->hw_if_index, n_rx_packets, n_rx_bytes);

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
