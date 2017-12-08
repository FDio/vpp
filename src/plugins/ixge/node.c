/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <ixge/ixge.h>
#include <ixge/inline.h>

#define IXGE_HWBP_RACE_ELOG 0


static char *ixge_error_strings[] = {
#define _(n,s) s,
  foreach_ixge_error
#undef _
};

always_inline void
ixge_rx_next_and_error_from_status_x1 (ixge_device_t * xd,
				       u32 s00, u32 s02,
				       u8 * next0, u8 * error0, u32 * flags0)
{
  u8 is0_ip4, is0_ip6, n0, e0;
  u32 f0;

  e0 = IXGE_ERROR_none;
  n0 = IXGE_RX_NEXT_ETHERNET_INPUT;

  is0_ip4 = s02 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED;
  n0 = is0_ip4 ? IXGE_RX_NEXT_IP4_INPUT : n0;

  e0 = (is0_ip4 && (s02 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR)
	? IXGE_ERROR_ip4_checksum_error : e0);

  is0_ip6 = s00 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6;
  n0 = is0_ip6 ? IXGE_RX_NEXT_IP6_INPUT : n0;

  n0 = (xd->per_interface_next_index != ~0) ?
    xd->per_interface_next_index : n0;

  /* Check for error. */
  n0 = e0 != IXGE_ERROR_none ? IXGE_RX_NEXT_DROP : n0;

  f0 = ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED
		| IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED))
	? VNET_BUFFER_F_L4_CHECKSUM_COMPUTED : 0);

  f0 |= ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR
		 | IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR))
	 ? 0 : VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  *error0 = e0;
  *next0 = n0;
  *flags0 = f0;
}

always_inline void
ixge_rx_next_and_error_from_status_x2 (ixge_device_t * xd,
				       u32 s00, u32 s02,
				       u32 s10, u32 s12,
				       u8 * next0, u8 * error0, u32 * flags0,
				       u8 * next1, u8 * error1, u32 * flags1)
{
  u8 is0_ip4, is0_ip6, n0, e0;
  u8 is1_ip4, is1_ip6, n1, e1;
  u32 f0, f1;

  e0 = e1 = IXGE_ERROR_none;
  n0 = n1 = IXGE_RX_NEXT_IP4_INPUT;

  is0_ip4 = s02 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED;
  is1_ip4 = s12 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED;

  n0 = is0_ip4 ? IXGE_RX_NEXT_IP4_INPUT : n0;
  n1 = is1_ip4 ? IXGE_RX_NEXT_IP4_INPUT : n1;

  e0 = (is0_ip4 && (s02 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR)
	? IXGE_ERROR_ip4_checksum_error : e0);
  e1 = (is1_ip4 && (s12 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR)
	? IXGE_ERROR_ip4_checksum_error : e1);

  is0_ip6 = s00 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6;
  is1_ip6 = s10 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6;

  n0 = is0_ip6 ? IXGE_RX_NEXT_IP6_INPUT : n0;
  n1 = is1_ip6 ? IXGE_RX_NEXT_IP6_INPUT : n1;

  n0 = (xd->per_interface_next_index != ~0) ?
    xd->per_interface_next_index : n0;
  n1 = (xd->per_interface_next_index != ~0) ?
    xd->per_interface_next_index : n1;

  /* Check for error. */
  n0 = e0 != IXGE_ERROR_none ? IXGE_RX_NEXT_DROP : n0;
  n1 = e1 != IXGE_ERROR_none ? IXGE_RX_NEXT_DROP : n1;

  *error0 = e0;
  *error1 = e1;

  *next0 = n0;
  *next1 = n1;

  f0 = ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED
		| IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED))
	? VNET_BUFFER_F_L4_CHECKSUM_COMPUTED : 0);
  f1 = ((s12 & (IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED
		| IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED))
	? VNET_BUFFER_F_L4_CHECKSUM_COMPUTED : 0);

  f0 |= ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR
		 | IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR))
	 ? 0 : VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
  f1 |= ((s12 & (IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR
		 | IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR))
	 ? 0 : VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  *flags0 = f0;
  *flags1 = f1;
}

static void
ixge_rx_trace (ixge_main_t * xm,
	       ixge_device_t * xd,
	       ixge_dma_queue_t * dq,
	       ixge_descriptor_t * before_descriptors,
	       u32 * before_buffers,
	       ixge_descriptor_t * after_descriptors, uword n_descriptors)
{
  vlib_main_t *vm = xm->vlib_main;
  vlib_node_runtime_t *node = dq->rx.node;
  ixge_rx_from_hw_descriptor_t *bd;
  ixge_rx_to_hw_descriptor_t *ad;
  u32 *b, n_left, is_sop, next_index_sop;

  n_left = n_descriptors;
  b = before_buffers;
  bd = &before_descriptors->rx_from_hw;
  ad = &after_descriptors->rx_to_hw;
  is_sop = dq->rx.is_start_of_packet;
  next_index_sop = dq->rx.saved_start_of_packet_next_index;

  while (n_left >= 2)
    {
      u32 bi0, bi1, flags0, flags1;
      vlib_buffer_t *b0, *b1;
      ixge_rx_dma_trace_t *t0, *t1;
      u8 next0, error0, next1, error1;

      bi0 = b[0];
      bi1 = b[1];
      n_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      ixge_rx_next_and_error_from_status_x2 (xd,
					     bd[0].status[0], bd[0].status[2],
					     bd[1].status[0], bd[1].status[2],
					     &next0, &error0, &flags0,
					     &next1, &error1, &flags1);

      next_index_sop = is_sop ? next0 : next_index_sop;
      vlib_trace_buffer (vm, node, next_index_sop, b0, /* follow_chain */ 0);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      next_index_sop = is_sop ? next1 : next_index_sop;
      vlib_trace_buffer (vm, node, next_index_sop, b1, /* follow_chain */ 0);
      t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
      t1->is_start_of_packet = is_sop;
      is_sop = (b1->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t1->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t1->device_index = xd->device_index;
      t0->before.rx_from_hw = bd[0];
      t1->before.rx_from_hw = bd[1];
      t0->after.rx_to_hw = ad[0];
      t1->after.rx_to_hw = ad[1];
      t0->buffer_index = bi0;
      t1->buffer_index = bi1;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (&t1->buffer, b1, sizeof (b1[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));
      memcpy (t1->buffer.pre_data, b1->data + b1->current_data,
	      sizeof (t1->buffer.pre_data));

      b += 2;
      bd += 2;
      ad += 2;
    }

  while (n_left >= 1)
    {
      u32 bi0, flags0;
      vlib_buffer_t *b0;
      ixge_rx_dma_trace_t *t0;
      u8 next0, error0;

      bi0 = b[0];
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      ixge_rx_next_and_error_from_status_x1 (xd,
					     bd[0].status[0], bd[0].status[2],
					     &next0, &error0, &flags0);

      next_index_sop = is_sop ? next0 : next_index_sop;
      vlib_trace_buffer (vm, node, next_index_sop, b0, /* follow_chain */ 0);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t0->before.rx_from_hw = bd[0];
      t0->after.rx_to_hw = ad[0];
      t0->buffer_index = bi0;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));

      b += 1;
      bd += 1;
      ad += 1;
    }
}

static uword
ixge_rx_queue_no_wrap (ixge_main_t * xm,
		       ixge_device_t * xd,
		       ixge_dma_queue_t * dq,
		       u32 start_descriptor_index, u32 n_descriptors)
{
  vlib_main_t *vm = xm->vlib_main;
  vlib_node_runtime_t *node = dq->rx.node;
  ixge_descriptor_t *d;
  static ixge_descriptor_t *d_trace_save;
  static u32 *d_trace_buffers;
  u32 n_descriptors_left = n_descriptors;
  u32 *to_rx =
    vec_elt_at_index (dq->descriptor_buffer_indices, start_descriptor_index);
  u32 *to_add;
  u32 bi_sop = dq->rx.saved_start_of_packet_buffer_index;
  u32 bi_last = dq->rx.saved_last_buffer_index;
  u32 next_index_sop = dq->rx.saved_start_of_packet_next_index;
  u32 is_sop = dq->rx.is_start_of_packet;
  u32 next_index, n_left_to_next, *to_next;
  u32 n_packets = 0;
  u32 n_bytes = 0;
  u32 n_trace = vlib_get_trace_count (vm, node);
  vlib_buffer_t *b_last, b_dummy;

  ASSERT (start_descriptor_index + n_descriptors <= dq->n_descriptors);
  d = &dq->descriptors[start_descriptor_index];

  b_last = bi_last != ~0 ? vlib_get_buffer (vm, bi_last) : &b_dummy;
  next_index = dq->rx.next_index;

  if (n_trace > 0)
    {
      u32 n = clib_min (n_trace, n_descriptors);
      if (d_trace_save)
	{
	  _vec_len (d_trace_save) = 0;
	  _vec_len (d_trace_buffers) = 0;
	}
      vec_add (d_trace_save, (ixge_descriptor_t *) d, n);
      vec_add (d_trace_buffers, to_rx, n);
    }

  {
    uword l = vec_len (xm->rx_buffers_to_add);

    if (l < n_descriptors_left)
      {
	u32 n_to_alloc = 2 * dq->n_descriptors - l;
	u32 n_allocated;

	vec_resize (xm->rx_buffers_to_add, n_to_alloc);

	_vec_len (xm->rx_buffers_to_add) = l;
	n_allocated =
	  vlib_buffer_alloc (vm, xm->rx_buffers_to_add + l, n_to_alloc);
	_vec_len (xm->rx_buffers_to_add) += n_allocated;

	/* Handle transient allocation failure */
	if (PREDICT_FALSE (l + n_allocated <= n_descriptors_left))
	  {
	    if (n_allocated == 0)
	      vlib_error_count (vm, ixge_input_node.index,
				IXGE_ERROR_rx_alloc_no_physmem, 1);
	    else
	      vlib_error_count (vm, ixge_input_node.index,
				IXGE_ERROR_rx_alloc_fail, 1);

	    n_descriptors_left = l + n_allocated;
	  }
	n_descriptors = n_descriptors_left;
      }

    /* Add buffers from end of vector going backwards. */
    to_add = vec_end (xm->rx_buffers_to_add) - 1;
  }

  while (n_descriptors_left > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_descriptors_left >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  u32 bi0, fi0, len0, l3_offset0, s20, s00, flags0;
	  u32 bi1, fi1, len1, l3_offset1, s21, s01, flags1;
	  u8 is_eop0, error0, next0;
	  u8 is_eop1, error1, next1;
	  ixge_descriptor_t d0, d1;

	  vlib_prefetch_buffer_with_index (vm, to_rx[2], STORE);
	  vlib_prefetch_buffer_with_index (vm, to_rx[3], STORE);

	  CLIB_PREFETCH (d + 2, 32, STORE);

	  d0.as_u32x4 = d[0].as_u32x4;
	  d1.as_u32x4 = d[1].as_u32x4;

	  s20 = d0.rx_from_hw.status[2];
	  s21 = d1.rx_from_hw.status[2];

	  s00 = d0.rx_from_hw.status[0];
	  s01 = d1.rx_from_hw.status[0];

	  if (!
	      ((s20 & s21) & IXGE_RX_DESCRIPTOR_STATUS2_IS_OWNED_BY_SOFTWARE))
	    goto found_hw_owned_descriptor_x2;

	  bi0 = to_rx[0];
	  bi1 = to_rx[1];

	  ASSERT (to_add - 1 >= xm->rx_buffers_to_add);
	  fi0 = to_add[0];
	  fi1 = to_add[-1];

	  to_rx[0] = fi0;
	  to_rx[1] = fi1;
	  to_rx += 2;
	  to_add -= 2;

#if 0
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, bi0));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, bi1));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, fi0));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, fi1));
#endif

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /*
	   * Turn this on if you run into
	   * "bad monkey" contexts, and you want to know exactly
	   * which nodes they've visited... See main.c...
	   */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);

	  CLIB_PREFETCH (b0->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);

	  is_eop0 = (s20 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET) != 0;
	  is_eop1 = (s21 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET) != 0;

	  ixge_rx_next_and_error_from_status_x2 (xd, s00, s20, s01, s21,
						 &next0, &error0, &flags0,
						 &next1, &error1, &flags1);

	  next0 = is_sop ? next0 : next_index_sop;
	  next1 = is_eop0 ? next1 : next0;
	  next_index_sop = next1;

	  b0->flags |= flags0 | (!is_eop0 << VLIB_BUFFER_LOG2_NEXT_PRESENT);
	  b1->flags |= flags1 | (!is_eop1 << VLIB_BUFFER_LOG2_NEXT_PRESENT);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  b0->error = node->errors[error0];
	  b1->error = node->errors[error1];

	  len0 = d0.rx_from_hw.n_packet_bytes_this_descriptor;
	  len1 = d1.rx_from_hw.n_packet_bytes_this_descriptor;
	  n_bytes += len0 + len1;
	  n_packets += is_eop0 + is_eop1;

	  /* Give new buffers to hardware. */
	  d0.rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm, fi0);
	  d1.rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm, fi1);
	  d0.rx_to_hw.head_address = d[0].rx_to_hw.tail_address;
	  d1.rx_to_hw.head_address = d[1].rx_to_hw.tail_address;
	  d[0].as_u32x4 = d0.as_u32x4;
	  d[1].as_u32x4 = d1.as_u32x4;

	  d += 2;
	  n_descriptors_left -= 2;

	  /* Point to either l2 or l3 header depending on next. */
	  l3_offset0 = (is_sop && (next0 != IXGE_RX_NEXT_ETHERNET_INPUT))
	    ? IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s00) : 0;
	  l3_offset1 = (is_eop0 && (next1 != IXGE_RX_NEXT_ETHERNET_INPUT))
	    ? IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s01) : 0;

	  b0->current_length = len0 - l3_offset0;
	  b1->current_length = len1 - l3_offset1;
	  b0->current_data = l3_offset0;
	  b1->current_data = l3_offset1;

	  b_last->next_buffer = is_sop ? ~0 : bi0;
	  b0->next_buffer = is_eop0 ? ~0 : bi1;
	  bi_last = bi1;
	  b_last = b1;

	  if (CLIB_DEBUG > 0)
	    {
	      u32 bi_sop0 = is_sop ? bi0 : bi_sop;
	      u32 bi_sop1 = is_eop0 ? bi1 : bi_sop0;

	      if (is_eop0)
		{
		  u8 *msg = vlib_validate_buffer (vm, bi_sop0,
						  /* follow_buffer_next */ 1);
		  ASSERT (!msg);
		}
	      if (is_eop1)
		{
		  u8 *msg = vlib_validate_buffer (vm, bi_sop1,
						  /* follow_buffer_next */ 1);
		  ASSERT (!msg);
		}
	    }
	  if (0)		/* "Dave" version */
	    {
	      u32 bi_sop0 = is_sop ? bi0 : bi_sop;
	      u32 bi_sop1 = is_eop0 ? bi1 : bi_sop0;

	      if (is_eop0)
		{
		  to_next[0] = bi_sop0;
		  to_next++;
		  n_left_to_next--;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi_sop0, next0);
		}
	      if (is_eop1)
		{
		  to_next[0] = bi_sop1;
		  to_next++;
		  n_left_to_next--;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi_sop1, next1);
		}
	      is_sop = is_eop1;
	      bi_sop = bi_sop1;
	    }
	  if (1)		/* "Eliot" version */
	    {
	      /* Speculatively enqueue to cached next. */
	      u8 saved_is_sop = is_sop;
	      u32 bi_sop_save = bi_sop;

	      bi_sop = saved_is_sop ? bi0 : bi_sop;
	      to_next[0] = bi_sop;
	      to_next += is_eop0;
	      n_left_to_next -= is_eop0;

	      bi_sop = is_eop0 ? bi1 : bi_sop;
	      to_next[0] = bi_sop;
	      to_next += is_eop1;
	      n_left_to_next -= is_eop1;

	      is_sop = is_eop1;

	      if (PREDICT_FALSE
		  (!(next0 == next_index && next1 == next_index)))
		{
		  /* Undo speculation. */
		  to_next -= is_eop0 + is_eop1;
		  n_left_to_next += is_eop0 + is_eop1;

		  /* Re-do both descriptors being careful about where we enqueue. */
		  bi_sop = saved_is_sop ? bi0 : bi_sop_save;
		  if (is_eop0)
		    {
		      if (next0 != next_index)
			vlib_set_next_frame_buffer (vm, node, next0, bi_sop);
		      else
			{
			  to_next[0] = bi_sop;
			  to_next += 1;
			  n_left_to_next -= 1;
			}
		    }

		  bi_sop = is_eop0 ? bi1 : bi_sop;
		  if (is_eop1)
		    {
		      if (next1 != next_index)
			vlib_set_next_frame_buffer (vm, node, next1, bi_sop);
		      else
			{
			  to_next[0] = bi_sop;
			  to_next += 1;
			  n_left_to_next -= 1;
			}
		    }

		  /* Switch cached next index when next for both packets is the same. */
		  if (is_eop0 && is_eop1 && next0 == next1)
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      next_index = next0;
		      vlib_get_next_frame (vm, node, next_index,
					   to_next, n_left_to_next);
		    }
		}
	    }
	}

      /* Bail out of dual loop and proceed with single loop. */
    found_hw_owned_descriptor_x2:

      while (n_descriptors_left > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, fi0, len0, l3_offset0, s20, s00, flags0;
	  u8 is_eop0, error0, next0;
	  ixge_descriptor_t d0;

	  d0.as_u32x4 = d[0].as_u32x4;

	  s20 = d0.rx_from_hw.status[2];
	  s00 = d0.rx_from_hw.status[0];

	  if (!(s20 & IXGE_RX_DESCRIPTOR_STATUS2_IS_OWNED_BY_SOFTWARE))
	    goto found_hw_owned_descriptor_x1;

	  bi0 = to_rx[0];
	  ASSERT (to_add >= xm->rx_buffers_to_add);
	  fi0 = to_add[0];

	  to_rx[0] = fi0;
	  to_rx += 1;
	  to_add -= 1;

#if 0
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, bi0));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, fi0));
#endif

	  b0 = vlib_get_buffer (vm, bi0);

	  /*
	   * Turn this on if you run into
	   * "bad monkey" contexts, and you want to know exactly
	   * which nodes they've visited...
	   */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  is_eop0 = (s20 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET) != 0;
	  ixge_rx_next_and_error_from_status_x1
	    (xd, s00, s20, &next0, &error0, &flags0);

	  next0 = is_sop ? next0 : next_index_sop;
	  next_index_sop = next0;

	  b0->flags |= flags0 | (!is_eop0 << VLIB_BUFFER_LOG2_NEXT_PRESENT);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  b0->error = node->errors[error0];

	  len0 = d0.rx_from_hw.n_packet_bytes_this_descriptor;
	  n_bytes += len0;
	  n_packets += is_eop0;

	  /* Give new buffer to hardware. */
	  d0.rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm, fi0);
	  d0.rx_to_hw.head_address = d0.rx_to_hw.tail_address;
	  d[0].as_u32x4 = d0.as_u32x4;

	  d += 1;
	  n_descriptors_left -= 1;

	  /* Point to either l2 or l3 header depending on next. */
	  l3_offset0 = (is_sop && (next0 != IXGE_RX_NEXT_ETHERNET_INPUT))
	    ? IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s00) : 0;
	  b0->current_length = len0 - l3_offset0;
	  b0->current_data = l3_offset0;

	  b_last->next_buffer = is_sop ? ~0 : bi0;
	  bi_last = bi0;
	  b_last = b0;

	  bi_sop = is_sop ? bi0 : bi_sop;

	  if (CLIB_DEBUG > 0 && is_eop0)
	    {
	      u8 *msg =
		vlib_validate_buffer (vm, bi_sop, /* follow_buffer_next */ 1);
	      ASSERT (!msg);
	    }

	  if (0)		/* "Dave" version */
	    {
	      if (is_eop0)
		{
		  to_next[0] = bi_sop;
		  to_next++;
		  n_left_to_next--;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi_sop, next0);
		}
	    }
	  if (1)		/* "Eliot" version */
	    {
	      if (PREDICT_TRUE (next0 == next_index))
		{
		  to_next[0] = bi_sop;
		  to_next += is_eop0;
		  n_left_to_next -= is_eop0;
		}
	      else
		{
		  if (next0 != next_index && is_eop0)
		    vlib_set_next_frame_buffer (vm, node, next0, bi_sop);

		  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		  next_index = next0;
		  vlib_get_next_frame (vm, node, next_index,
				       to_next, n_left_to_next);
		}
	    }
	  is_sop = is_eop0;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

found_hw_owned_descriptor_x1:
  if (n_descriptors_left > 0)
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  _vec_len (xm->rx_buffers_to_add) = (to_add + 1) - xm->rx_buffers_to_add;

  {
    u32 n_done = n_descriptors - n_descriptors_left;

    if (n_trace > 0 && n_done > 0)
      {
	u32 n = clib_min (n_trace, n_done);
	ixge_rx_trace (xm, xd, dq,
		       d_trace_save,
		       d_trace_buffers,
		       &dq->descriptors[start_descriptor_index], n);
	vlib_set_trace_count (vm, node, n_trace - n);
      }
    if (d_trace_save)
      {
	_vec_len (d_trace_save) = 0;
	_vec_len (d_trace_buffers) = 0;
      }

    /* Don't keep a reference to b_last if we don't have to.
       Otherwise we can over-write a next_buffer pointer after already haven
       enqueued a packet. */
    if (is_sop)
      {
	b_last->next_buffer = ~0;
	bi_last = ~0;
      }

    dq->rx.n_descriptors_done_this_call = n_done;
    dq->rx.n_descriptors_done_total += n_done;
    dq->rx.is_start_of_packet = is_sop;
    dq->rx.saved_start_of_packet_buffer_index = bi_sop;
    dq->rx.saved_last_buffer_index = bi_last;
    dq->rx.saved_start_of_packet_next_index = next_index_sop;
    dq->rx.next_index = next_index;
    dq->rx.n_bytes += n_bytes;

    return n_packets;
  }
}

static uword
ixge_rx_queue (ixge_main_t * xm,
	       ixge_device_t * xd,
	       vlib_node_runtime_t * node, u32 queue_index)
{
  ixge_dma_queue_t *dq =
    vec_elt_at_index (xd->dma_queues[VLIB_RX], queue_index);
  ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_RX, dq->queue_index);
  uword n_packets = 0;
  u32 hw_head_index, sw_head_index;

  /* One time initialization. */
  if (!dq->rx.node)
    {
      dq->rx.node = node;
      dq->rx.is_start_of_packet = 1;
      dq->rx.saved_start_of_packet_buffer_index = ~0;
      dq->rx.saved_last_buffer_index = ~0;
    }

  dq->rx.next_index = node->cached_next_index;

  dq->rx.n_descriptors_done_total = 0;
  dq->rx.n_descriptors_done_this_call = 0;
  dq->rx.n_bytes = 0;

  /* Fetch head from hardware and compare to where we think we are. */
  hw_head_index = dr->head_index;
  sw_head_index = dq->head_index;

  if (hw_head_index == sw_head_index)
    goto done;

  if (hw_head_index < sw_head_index)
    {
      u32 n_tried = dq->n_descriptors - sw_head_index;
      n_packets += ixge_rx_queue_no_wrap (xm, xd, dq, sw_head_index, n_tried);
      sw_head_index =
	ixge_ring_add (dq, sw_head_index,
		       dq->rx.n_descriptors_done_this_call);

      if (dq->rx.n_descriptors_done_this_call != n_tried)
	goto done;
    }
  if (hw_head_index >= sw_head_index)
    {
      u32 n_tried = hw_head_index - sw_head_index;
      n_packets += ixge_rx_queue_no_wrap (xm, xd, dq, sw_head_index, n_tried);
      sw_head_index =
	ixge_ring_add (dq, sw_head_index,
		       dq->rx.n_descriptors_done_this_call);
    }

done:
  dq->head_index = sw_head_index;
  dq->tail_index =
    ixge_ring_add (dq, dq->tail_index, dq->rx.n_descriptors_done_total);

  /* Give tail back to hardware. */
  CLIB_MEMORY_BARRIER ();

  dr->tail_index = dq->tail_index;

  vlib_increment_combined_counter (vnet_main.
				   interface_main.combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX,
				   0 /* thread_index */ ,
				   xd->vlib_sw_if_index, n_packets,
				   dq->rx.n_bytes);

  return n_packets;
}

static void
ixge_tx_queue (ixge_main_t * xm, ixge_device_t * xd, u32 queue_index)
{
  vlib_main_t *vm = xm->vlib_main;
  ixge_dma_queue_t *dq =
    vec_elt_at_index (xd->dma_queues[VLIB_TX], queue_index);
  u32 n_clean, *b, *t, *t0;
  i32 n_hw_owned_descriptors;
  i32 first_to_clean, last_to_clean;
  u64 hwbp_race = 0;

  /* Handle case where head write back pointer update
   * arrives after the interrupt during high PCI bus loads.
   */
  while ((dq->head_index == dq->tx.head_index_write_back[0]) &&
	 dq->tx.n_buffers_on_ring && (dq->head_index != dq->tail_index))
    {
      hwbp_race++;
      if (IXGE_HWBP_RACE_ELOG && (hwbp_race == 1))
	{
	  ELOG_TYPE_DECLARE (e) =
	  {
	  .function = (char *) __FUNCTION__,.format =
	      "ixge %d tx head index race: head %4d, tail %4d, buffs %4d",.format_args
	      = "i4i4i4i4",};
	  struct
	  {
	    u32 instance, head_index, tail_index, n_buffers_on_ring;
	  } *ed;
	  ed = ELOG_DATA (&vm->elog_main, e);
	  ed->instance = xd->device_index;
	  ed->head_index = dq->head_index;
	  ed->tail_index = dq->tail_index;
	  ed->n_buffers_on_ring = dq->tx.n_buffers_on_ring;
	}
    }

  dq->head_index = dq->tx.head_index_write_back[0];
  n_hw_owned_descriptors = ixge_ring_sub (dq, dq->head_index, dq->tail_index);
  ASSERT (dq->tx.n_buffers_on_ring >= n_hw_owned_descriptors);
  n_clean = dq->tx.n_buffers_on_ring - n_hw_owned_descriptors;

  if (IXGE_HWBP_RACE_ELOG && hwbp_race)
    {
      ELOG_TYPE_DECLARE (e) =
      {
      .function = (char *) __FUNCTION__,.format =
	  "ixge %d tx head index race: head %4d, hw_owned %4d, n_clean %4d, retries %d",.format_args
	  = "i4i4i4i4i4",};
      struct
      {
	u32 instance, head_index, n_hw_owned_descriptors, n_clean, retries;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->instance = xd->device_index;
      ed->head_index = dq->head_index;
      ed->n_hw_owned_descriptors = n_hw_owned_descriptors;
      ed->n_clean = n_clean;
      ed->retries = hwbp_race;
    }

  /*
   * This function used to wait until hardware owned zero descriptors.
   * At high PPS rates, that doesn't happen until the TX ring is
   * completely full of descriptors which need to be cleaned up.
   * That, in turn, causes TX ring-full drops and/or long RX service
   * interruptions.
   */
  if (n_clean == 0)
    return;

  /* Clean the n_clean descriptors prior to the reported hardware head */
  last_to_clean = dq->head_index - 1;
  last_to_clean = (last_to_clean < 0) ? last_to_clean + dq->n_descriptors :
    last_to_clean;

  first_to_clean = (last_to_clean) - (n_clean - 1);
  first_to_clean = (first_to_clean < 0) ? first_to_clean + dq->n_descriptors :
    first_to_clean;

  vec_resize (xm->tx_buffers_pending_free, dq->n_descriptors - 1);
  t0 = t = xm->tx_buffers_pending_free;
  b = dq->descriptor_buffer_indices + first_to_clean;

  /* Wrap case: clean from first to end, then start to last */
  if (first_to_clean > last_to_clean)
    {
      t += clean_block (b, t, (dq->n_descriptors - 1) - first_to_clean);
      first_to_clean = 0;
      b = dq->descriptor_buffer_indices;
    }

  /* Typical case: clean from first to last */
  if (first_to_clean <= last_to_clean)
    t += clean_block (b, t, (last_to_clean - first_to_clean) + 1);

  if (t > t0)
    {
      u32 n = t - t0;
      vlib_buffer_free_no_next (vm, t0, n);
      ASSERT (dq->tx.n_buffers_on_ring >= n);
      dq->tx.n_buffers_on_ring -= n;
      _vec_len (xm->tx_buffers_pending_free) = 0;
    }
}

static void
ixge_interrupt (ixge_main_t * xm, ixge_device_t * xd, u32 i)
{
  vlib_main_t *vm = xm->vlib_main;
  ixge_regs_t *r = xd->regs;

  if (i != 20)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) = {
	.function = (char *) __FUNCTION__,
	.format = "ixge %d, %s",
	.format_args = "i1t1",
	.n_enum_strings = 16,
	.enum_strings = {
	    "flow director",
	    "rx miss",
	    "pci exception",
	    "mailbox",
	    "link status change",
	    "linksec key exchange",
	    "manageability event",
	    "reserved23",
	    "sdp0",
	    "sdp1",
	    "sdp2",
	    "sdp3",
	    "ecc",
	    "descriptor handler error",
	    "tcp timer",
	    "other",
	},
      };
      /* *INDENT-ON* */
      struct
      {
	u8 instance;
	u8 index;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->instance = xd->device_index;
      ed->index = i - 16;
    }
  else
    {
      u32 v = r->xge_mac.link_status;
      uword is_up = (v & (1 << 30)) != 0;

      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) = {
        .function = (char *) __FUNCTION__,
	.format = "ixge %d, link status change 0x%x",
	.format_args = "i4i4",
      };
      /* *INDENT-ON* */
      struct
      {
	u32 instance, link_status;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->instance = xd->device_index;
      ed->link_status = v;
      xd->link_status_at_last_link_change = v;

      vlib_process_signal_event (vm, ixge_process_node.index,
				 EVENT_SET_FLAGS,
				 ((is_up << 31) | xd->vlib_hw_if_index));
    }
}

static uword
ixge_device_input (ixge_main_t * xm,
		   ixge_device_t * xd, vlib_node_runtime_t * node)
{
  ixge_regs_t *r = xd->regs;
  u32 i, s;
  uword n_rx_packets = 0;

  s = r->interrupt.status_write_1_to_set;
  if (s)
    r->interrupt.status_write_1_to_clear = s;

  /* *INDENT-OFF* */
  foreach_set_bit (i, s, ({
    if (ixge_interrupt_is_rx_queue (i))
      n_rx_packets += ixge_rx_queue (xm, xd, node, ixge_interrupt_rx_queue (i));

    else if (ixge_interrupt_is_tx_queue (i))
      ixge_tx_queue (xm, xd, ixge_interrupt_tx_queue (i));

    else
      ixge_interrupt (xm, xd, i);
  }));
  /* *INDENT-ON* */

  return n_rx_packets;
}



static uword
ixge_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd;
  uword n_rx_packets = 0;

  if (node->state == VLIB_NODE_STATE_INTERRUPT)
    {
      uword i;

      /* Loop over devices with interrupts. */
      /* *INDENT-OFF* */
      foreach_set_bit (i, node->runtime_data[0], ({
	xd = vec_elt_at_index (xm->devices, i);
	n_rx_packets += ixge_device_input (xm, xd, node);

	/* Re-enable interrupts since we're going to stay in interrupt mode. */
	if (! (node->flags & VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE))
	  xd->regs->interrupt.enable_write_1_to_set = ~0;
      }));
      /* *INDENT-ON* */

      /* Clear mask of devices with pending interrupts. */
      node->runtime_data[0] = 0;
    }
  else
    {
      /* Poll all devices for input/interrupts. */
      vec_foreach (xd, xm->devices)
      {
	n_rx_packets += ixge_device_input (xm, xd, node);

	/* Re-enable interrupts when switching out of polling mode. */
	if (node->flags &
	    VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE)
	  xd->regs->interrupt.enable_write_1_to_set = ~0;
      }
    }

  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ixge_input_node) = {
  .function = ixge_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "ixge-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_ixge_rx_dma_trace,

  .n_errors = IXGE_N_ERROR,
  .error_strings = ixge_error_strings,

  .n_next_nodes = IXGE_RX_N_NEXT,
  .next_nodes = {
    [IXGE_RX_NEXT_DROP] = "error-drop",
    [IXGE_RX_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [IXGE_RX_NEXT_IP4_INPUT] = "ip4-input",
    [IXGE_RX_NEXT_IP6_INPUT] = "ip6-input",
  },
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
