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

#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <marvell/pp2/pp2.h>

#define foreach_mrvl_pp2_input_error \
  _(PPIO_RECV, "pp2_ppio_recv error") \
  _(BPOOL_GET_NUM_BUFFS, "pp2_bpool_get_num_buffs error") \
  _(BPOOL_PUT_BUFFS, "pp2_bpool_put_buffs error") \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(MAC_CE, "MAC error (CRC error)") \
  _(MAC_OR, "overrun error") \
  _(MAC_RSVD, "unknown MAC error") \
  _(MAC_RE, "resource error") \
  _(IP_HDR, "ip4 header error")

typedef enum
{
#define _(f,s) MRVL_PP2_INPUT_ERROR_##f,
  foreach_mrvl_pp2_input_error
#undef _
    MRVL_PP2_INPUT_N_ERROR,
} mrvl_pp2_input_error_t;

static __clib_unused char *mrvl_pp2_input_error_strings[] = {
#define _(n,s) s,
  foreach_mrvl_pp2_input_error
#undef _
};

static_always_inline void
mrvl_pp2_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node, u32 next0,
		      vlib_buffer_t * b0, uword * n_trace,
		      mrvl_pp2_if_t * ppif, struct pp2_ppio_desc *d)
{
  mrvl_pp2_input_trace_t *tr;
  vlib_trace_buffer (vm, node, next0, b0,
		     /* follow_chain */ 0);
  vlib_set_trace_count (vm, node, --(*n_trace));
  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
  tr->next_index = next0;
  tr->hw_if_index = ppif->hw_if_index;
  clib_memcpy_fast (&tr->desc, d, sizeof (struct pp2_ppio_desc));
}

static_always_inline u16
mrvl_pp2_set_buf_data_len_flags (vlib_buffer_t * b, struct pp2_ppio_desc *d,
				 u32 add_flags)
{
  u16 len;
  len = pp2_ppio_inq_desc_get_pkt_len (d);
  b->total_length_not_including_first_buffer = 0;
  b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID | add_flags;

  if (add_flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    vnet_buffer (b)->l2_hdr_offset = 2;

  if (add_flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    {
      u16 offset = DM_RXD_GET_L3_OFF (d);
      vnet_buffer (b)->l3_hdr_offset = offset;
      b->current_data = offset;
      b->current_length = len - offset + 2;
    }
  else
    {
      b->current_data = 2;
      b->current_length = len;
    }

  if (add_flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    vnet_buffer (b)->l4_hdr_offset = vnet_buffer (b)->l3_hdr_offset +
      DM_RXD_GET_IPHDR_LEN (d) * 4;

  return len;
}

static_always_inline u16
mrvl_pp2_next_from_desc (vlib_node_runtime_t * node, struct pp2_ppio_desc * d,
			 vlib_buffer_t * b, u32 * next)
{
  u8 l3_info;
  /* ES bit set means MAC error  - drop and count */
  if (PREDICT_FALSE (DM_RXD_GET_ES (d)))
    {
      *next = VNET_DEVICE_INPUT_NEXT_DROP;
      u8 ec = DM_RXD_GET_EC (d);
      if (ec == 0)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_CE];
      else if (ec == 1)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_OR];
      else if (ec == 2)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_RSVD];
      else if (ec == 3)
	b->error = node->errors[MRVL_PP2_INPUT_ERROR_MAC_RE];
      return mrvl_pp2_set_buf_data_len_flags (b, d, 0);
    }
  l3_info = DM_RXD_GET_L3_PRS_INFO (d);

  /* ipv4 packet can be value 1, 2 or 3 */
  if (PREDICT_TRUE ((l3_info - 1) < 3))
    {
      if (PREDICT_FALSE (DM_RXD_GET_L3_IP4_HDR_ERR (d) != 0))
	{
	  *next = VNET_DEVICE_INPUT_NEXT_DROP;
	  b->error = node->errors[MRVL_PP2_INPUT_ERROR_IP_HDR];
	  return mrvl_pp2_set_buf_data_len_flags (b, d, 0);
	}
      *next = VNET_DEVICE_INPUT_NEXT_IP4_NCS_INPUT;
      return mrvl_pp2_set_buf_data_len_flags
	(b, d,
	 VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L4_HDR_OFFSET_VALID | VNET_BUFFER_F_IS_IP4);
    }

  /* ipv4 packet can be value 4 or 5 */
  if (PREDICT_TRUE ((l3_info - 4) < 2))
    {
      *next = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
      return mrvl_pp2_set_buf_data_len_flags
	(b, d,
	 VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	 VNET_BUFFER_F_L4_HDR_OFFSET_VALID | VNET_BUFFER_F_IS_IP6);
    }

  *next = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  return mrvl_pp2_set_buf_data_len_flags (b, d,
					  VNET_BUFFER_F_L2_HDR_OFFSET_VALID);
}

static_always_inline uword
mrvl_pp2_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame, mrvl_pp2_if_t * ppif,
			      u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  u32 thread_index = vm->thread_index;
  mrvl_pp2_inq_t *inq = vec_elt_at_index (ppif->inqs, qid);
  uword n_trace = vlib_get_trace_count (vm, node);
  mrvl_pp2_per_thread_data_t *ptd =
    vec_elt_at_index (ppm->per_thread_data, thread_index);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 sw_if_index[VLIB_N_RX_TX];
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  struct pp2_ppio_desc *d;
  u16 n_desc = VLIB_FRAME_SIZE;
  u32 n_bufs;
  u32 *buffers;
  int i;

  vec_validate_aligned (ptd->descs, n_desc, CLIB_CACHE_LINE_BYTES);
  if (PREDICT_FALSE (pp2_ppio_recv (ppif->ppio, 0, qid, ptd->descs, &n_desc)))
    {
      vlib_error_count (vm, node->node_index, MRVL_PP2_INPUT_ERROR_PPIO_RECV,
			1);
      n_desc = 0;
    }
  n_rx_packets = n_desc;

  for (i = 0; i < n_desc; i++)
    ptd->buffers[i] = pp2_ppio_inq_desc_get_cookie (&ptd->descs[i]);

  d = ptd->descs;
  buffers = ptd->buffers;
  sw_if_index[VLIB_RX] = ppif->sw_if_index;
  sw_if_index[VLIB_TX] = (u32) ~ 0;
  while (n_desc)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      u32 next0, next1;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_desc >= 4 && n_left_to_next >= 2)
	{
	  /* prefetch */
	  bi0 = buffers[0];
	  bi1 = buffers[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  if (PREDICT_TRUE (ppif->per_interface_next_index == ~0))
	    {
	      n_rx_bytes += mrvl_pp2_next_from_desc (node, d, b0, &next0);
	      n_rx_bytes += mrvl_pp2_next_from_desc (node, d + 1, b1, &next1);
	      vnet_feature_start_device_input_x2 (ppif->sw_if_index, &next0,
						  &next1, b0, b1);
	    }
	  else
	    {
	      n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b0, d, 0);
	      n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b1, d + 1, 0);
	      next0 = next1 = ppif->per_interface_next_index;
	    }

	  clib_memcpy_fast (vnet_buffer (b0)->sw_if_index, sw_if_index,
			    sizeof (sw_if_index));
	  clib_memcpy_fast (vnet_buffer (b1)->sw_if_index, sw_if_index,
			    sizeof (sw_if_index));

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      mrvl_pp2_input_trace (vm, node, next0, b0, &n_trace, ppif, d);
	      if (n_trace > 0)
		mrvl_pp2_input_trace (vm, node, next1, b1, &n_trace, ppif,
				      d + 1);
	    }

	  to_next += 2;
	  n_left_to_next -= 2;
	  d += 2;
	  buffers += 2;
	  n_desc -= 2;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);

	}
      while (n_desc && n_left_to_next)
	{
	  u32 bi0 = buffers[0];
	  to_next[0] = bi0;
	  b0 = vlib_get_buffer (vm, bi0);

	  if (PREDICT_TRUE (ppif->per_interface_next_index == ~0))
	    {
	      n_rx_bytes += mrvl_pp2_next_from_desc (node, d, b0, &next0);
	      vnet_feature_start_device_input_x1 (ppif->sw_if_index, &next0,
						  b0);
	    }
	  else
	    {
	      n_rx_bytes += mrvl_pp2_set_buf_data_len_flags (b0, d, 0);
	      next0 = ppif->per_interface_next_index;
	    }

	  clib_memcpy_fast (vnet_buffer (b0)->sw_if_index, sw_if_index,
			    sizeof (sw_if_index));

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  if (PREDICT_FALSE (n_trace > 0))
	    mrvl_pp2_input_trace (vm, node, next0, b0, &n_trace, ppif, d);

	  to_next += 1;
	  n_left_to_next--;
	  d++;
	  buffers++;
	  n_desc--;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_increment_combined_counter (vnm->
				   interface_main.combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX, thread_index,
				   ppif->hw_if_index, n_rx_packets,
				   n_rx_bytes);

  if (PREDICT_FALSE (pp2_bpool_get_num_buffs (inq->bpool, &n_bufs)))
    {
      vlib_error_count (vm, node->node_index,
			MRVL_PP2_INPUT_ERROR_BPOOL_GET_NUM_BUFFS, 1);
      goto done;
    }

  n_bufs = inq->size - n_bufs;
  while (n_bufs >= MRVL_PP2_BUFF_BATCH_SZ)
    {
      u16 n_alloc, i;
      struct buff_release_entry *e = ptd->bre;
      u32 *buffers = ptd->buffers;

      n_alloc = vlib_buffer_alloc (vm, ptd->buffers, MRVL_PP2_BUFF_BATCH_SZ);
      i = n_alloc;

      if (PREDICT_FALSE (n_alloc == 0))
	{
	  vlib_error_count (vm, node->node_index,
			    MRVL_PP2_INPUT_ERROR_BUFFER_ALLOC, 1);
	  goto done;
	}

      while (i--)
	{
	  u32 bi = buffers[0];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  e->buff.addr = vlib_buffer_get_pa (vm, b) - 64;
	  e->buff.cookie = bi;
	  e->bpool = inq->bpool;
	  e++;
	  buffers++;
	}

      i = n_alloc;
      if (PREDICT_FALSE (pp2_bpool_put_buffs (ptd->hif, ptd->bre, &i)))
	{
	  vlib_error_count (vm, node->node_index,
			    MRVL_PP2_INPUT_ERROR_BPOOL_PUT_BUFFS, 1);
	  vlib_buffer_free (vm, ptd->buffers, n_alloc);
	  goto done;
	}

      if (PREDICT_FALSE (i != n_alloc))
	vlib_buffer_free (vm, ptd->buffers + i, n_alloc - i);

      n_bufs -= i;
    }

done:
  return n_rx_packets;
}

uword
mrvl_pp2_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{
  u32 n_rx = 0;
  mrvl_pp2_main_t *ppm = &mrvl_pp2_main;
  vnet_hw_if_rxq_poll_vector_t *pv;

  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  for (int i = 0; i < vec_len (pv); i++)
    {
      mrvl_pp2_if_t *ppif;
      ppif = vec_elt_at_index (ppm->interfaces, pv[i].dev_instance);
      if (ppif->flags & MRVL_PP2_IF_F_ADMIN_UP)
	n_rx +=
	  mrvl_pp2_device_input_inline (vm, node, frame, ppif, pv[i].queue_id);
    }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mrvl_pp2_input_node) = {
  .function = mrvl_pp2_input_fn,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .name = "mrvl-pp2-input",
  .sibling_of = "device-input",
  .format_trace = format_mrvl_pp2_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = MRVL_PP2_INPUT_N_ERROR,
  .error_strings = mrvl_pp2_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
