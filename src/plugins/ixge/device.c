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

always_inline uword
ixge_tx_descriptor_matches_template (ixge_main_t * xm,
				     ixge_tx_descriptor_t * d)
{
  u32 cmp;

  cmp = ((d->status0 & xm->tx_descriptor_template_mask.status0)
	 ^ xm->tx_descriptor_template.status0);
  if (cmp)
    return 0;
  cmp = ((d->status1 & xm->tx_descriptor_template_mask.status1)
	 ^ xm->tx_descriptor_template.status1);
  if (cmp)
    return 0;

  return 1;
}


static void
ixge_clear_hw_interface_counters (u32 instance)
{
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, instance);
  ixge_update_counters (xd);
  memcpy (xd->counters_last_clear, xd->counters, sizeof (xd->counters));
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void
ixge_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  ixge_main_t *xm = &ixge_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ixge_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      xd->per_interface_next_index = node_index;
      return;
    }

  xd->per_interface_next_index =
    vlib_node_add_next (xm->vlib_main, ixge_input_node.index, node_index);
}



static void
ixge_sfp_device_up_down (ixge_device_t * xd, uword is_up)
{
  u32 v;

  if (is_up)
    {
      /* pma/pmd 10g serial SFI. */
      xd->regs->xge_mac.auto_negotiation_control2 &= ~(3 << 16);
      xd->regs->xge_mac.auto_negotiation_control2 |= 2 << 16;

      v = xd->regs->xge_mac.auto_negotiation_control;
      v &= ~(7 << 13);
      v |= (0 << 13);
      /* Restart autoneg. */
      v |= (1 << 12);
      xd->regs->xge_mac.auto_negotiation_control = v;

      while (!(xd->regs->xge_mac.link_partner_ability[0] & 0xf0000))
	;

      v = xd->regs->xge_mac.auto_negotiation_control;

      /* link mode 10g sfi serdes */
      v &= ~(7 << 13);
      v |= (3 << 13);

      /* Restart autoneg. */
      v |= (1 << 12);
      xd->regs->xge_mac.auto_negotiation_control = v;

      xd->regs->xge_mac.link_status;
    }

  ixge_sfp_enable_disable_laser (xd, /* enable */ is_up);

  /* Give time for link partner to notice that we're up. */
  if (is_up && vlib_in_process_context (vlib_get_main ()))
    {
      vlib_process_suspend (vlib_get_main (), 300e-3);
    }
}


static clib_error_t *
ixge_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, hif->dev_instance);
  ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_RX, 0);

  if (is_up)
    {
      xd->regs->rx_enable |= 1;
      xd->regs->tx_dma_control |= 1;
      dr->control |= 1 << 25;
      while (!(dr->control & (1 << 25)))
	;
    }
  else
    {
      xd->regs->rx_enable &= ~1;
      xd->regs->tx_dma_control &= ~1;
    }

  ixge_sfp_device_up_down (xd, is_up);

  return /* no error */ 0;
}

typedef struct
{
  vlib_node_runtime_t *node;
  u32 is_start_of_packet;
  u32 n_bytes_in_packet;

  ixge_tx_descriptor_t *start_of_packet_descriptor;
} ixge_tx_state_t;

static void
ixge_tx_trace (ixge_main_t * xm,
	       ixge_device_t * xd,
	       ixge_dma_queue_t * dq,
	       ixge_tx_state_t * tx_state,
	       ixge_tx_descriptor_t * descriptors,
	       u32 * buffers, uword n_descriptors)
{
  vlib_main_t *vm = xm->vlib_main;
  vlib_node_runtime_t *node = tx_state->node;
  ixge_tx_descriptor_t *d;
  u32 *b, n_left, is_sop;

  n_left = n_descriptors;
  b = buffers;
  d = descriptors;
  is_sop = tx_state->is_start_of_packet;

  while (n_left >= 2)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      ixge_tx_dma_trace_t *t0, *t1;

      bi0 = b[0];
      bi1 = b[1];
      n_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
      t1->is_start_of_packet = is_sop;
      is_sop = (b1->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t1->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t1->device_index = xd->device_index;
      t0->descriptor = d[0];
      t1->descriptor = d[1];
      t0->buffer_index = bi0;
      t1->buffer_index = bi1;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (&t1->buffer, b1, sizeof (b1[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));
      memcpy (t1->buffer.pre_data, b1->data + b1->current_data,
	      sizeof (t1->buffer.pre_data));

      b += 2;
      d += 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ixge_tx_dma_trace_t *t0;

      bi0 = b[0];
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t0->descriptor = d[0];
      t0->buffer_index = bi0;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));

      b += 1;
      d += 1;
    }
}

static uword
ixge_tx_no_wrap (ixge_main_t * xm,
		 ixge_device_t * xd,
		 ixge_dma_queue_t * dq,
		 u32 * buffers,
		 u32 start_descriptor_index,
		 u32 n_descriptors, ixge_tx_state_t * tx_state)
{
  vlib_main_t *vm = xm->vlib_main;
  ixge_tx_descriptor_t *d, *d_sop;
  u32 n_left = n_descriptors;
  u32 *to_free = vec_end (xm->tx_buffers_pending_free);
  u32 *to_tx =
    vec_elt_at_index (dq->descriptor_buffer_indices, start_descriptor_index);
  u32 is_sop = tx_state->is_start_of_packet;
  u32 len_sop = tx_state->n_bytes_in_packet;
  u16 template_status = xm->tx_descriptor_template.status0;
  u32 descriptor_prefetch_rotor = 0;

  ASSERT (start_descriptor_index + n_descriptors <= dq->n_descriptors);
  d = &dq->descriptors[start_descriptor_index].tx;
  d_sop = is_sop ? d : tx_state->start_of_packet_descriptor;

  while (n_left >= 4)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, fi0, len0;
      u32 bi1, fi1, len1;
      u8 is_eop0, is_eop1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, buffers[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[3], LOAD);

      if ((descriptor_prefetch_rotor & 0x3) == 0)
	CLIB_PREFETCH (d + 4, CLIB_CACHE_LINE_BYTES, STORE);

      descriptor_prefetch_rotor += 2;

      bi0 = buffers[0];
      bi1 = buffers[1];

      to_free[0] = fi0 = to_tx[0];
      to_tx[0] = bi0;
      to_free += fi0 != 0;

      to_free[0] = fi1 = to_tx[1];
      to_tx[1] = bi1;
      to_free += fi1 != 0;

      buffers += 2;
      n_left -= 2;
      to_tx += 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      is_eop0 = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;
      is_eop1 = (b1->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      len0 = b0->current_length;
      len1 = b1->current_length;

      ASSERT (ixge_tx_descriptor_matches_template (xm, d + 0));
      ASSERT (ixge_tx_descriptor_matches_template (xm, d + 1));

      d[0].buffer_address =
	vlib_get_buffer_data_physical_address (vm, bi0) + b0->current_data;
      d[1].buffer_address =
	vlib_get_buffer_data_physical_address (vm, bi1) + b1->current_data;

      d[0].n_bytes_this_buffer = len0;
      d[1].n_bytes_this_buffer = len1;

      d[0].status0 =
	template_status | (is_eop0 <<
			   IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET);
      d[1].status0 =
	template_status | (is_eop1 <<
			   IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET);

      len_sop = (is_sop ? 0 : len_sop) + len0;
      d_sop[0].status1 =
	IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET (len_sop);
      d += 1;
      d_sop = is_eop0 ? d : d_sop;

      is_sop = is_eop0;

      len_sop = (is_sop ? 0 : len_sop) + len1;
      d_sop[0].status1 =
	IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET (len_sop);
      d += 1;
      d_sop = is_eop1 ? d : d_sop;

      is_sop = is_eop1;
    }

  while (n_left > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0, fi0, len0;
      u8 is_eop0;

      bi0 = buffers[0];

      to_free[0] = fi0 = to_tx[0];
      to_tx[0] = bi0;
      to_free += fi0 != 0;

      buffers += 1;
      n_left -= 1;
      to_tx += 1;

      b0 = vlib_get_buffer (vm, bi0);

      is_eop0 = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      len0 = b0->current_length;

      ASSERT (ixge_tx_descriptor_matches_template (xm, d + 0));

      d[0].buffer_address =
	vlib_get_buffer_data_physical_address (vm, bi0) + b0->current_data;

      d[0].n_bytes_this_buffer = len0;

      d[0].status0 =
	template_status | (is_eop0 <<
			   IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET);

      len_sop = (is_sop ? 0 : len_sop) + len0;
      d_sop[0].status1 =
	IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET (len_sop);
      d += 1;
      d_sop = is_eop0 ? d : d_sop;

      is_sop = is_eop0;
    }

  if (tx_state->node->flags & VLIB_NODE_FLAG_TRACE)
    {
      to_tx =
	vec_elt_at_index (dq->descriptor_buffer_indices,
			  start_descriptor_index);
      ixge_tx_trace (xm, xd, dq, tx_state,
		     &dq->descriptors[start_descriptor_index].tx, to_tx,
		     n_descriptors);
    }

  _vec_len (xm->tx_buffers_pending_free) =
    to_free - xm->tx_buffers_pending_free;

  /* When we are done d_sop can point to end of ring.  Wrap it if so. */
  {
    ixge_tx_descriptor_t *d_start = &dq->descriptors[0].tx;

    ASSERT (d_sop - d_start <= dq->n_descriptors);
    d_sop = d_sop - d_start == dq->n_descriptors ? d_start : d_sop;
  }

  tx_state->is_start_of_packet = is_sop;
  tx_state->start_of_packet_descriptor = d_sop;
  tx_state->n_bytes_in_packet = len_sop;

  return n_descriptors;
}

static uword
ixge_interface_tx (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ixge_main_t *xm = &ixge_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, rd->dev_instance);
  ixge_dma_queue_t *dq;
  u32 *from, n_left_tx, n_descriptors_to_tx, n_tail_drop;
  u32 queue_index = 0;		/* fixme parameter */
  ixge_tx_state_t tx_state;

  tx_state.node = node;
  tx_state.is_start_of_packet = 1;
  tx_state.start_of_packet_descriptor = 0;
  tx_state.n_bytes_in_packet = 0;

  from = vlib_frame_vector_args (f);

  dq = vec_elt_at_index (xd->dma_queues[VLIB_TX], queue_index);

  dq->head_index = dq->tx.head_index_write_back[0];

  /* Since head == tail means ring is empty we can send up to dq->n_descriptors - 1. */
  n_left_tx = dq->n_descriptors - 1;
  n_left_tx -= ixge_ring_sub (dq, dq->head_index, dq->tail_index);

  _vec_len (xm->tx_buffers_pending_free) = 0;

  n_descriptors_to_tx = f->n_vectors;
  n_tail_drop = 0;
  if (PREDICT_FALSE (n_descriptors_to_tx > n_left_tx))
    {
      i32 i, n_ok, i_eop, i_sop;

      i_sop = i_eop = ~0;
      for (i = n_left_tx - 1; i >= 0; i--)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	  if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      if (i_sop != ~0 && i_eop != ~0)
		break;
	      i_eop = i;
	      i_sop = i + 1;
	    }
	}
      if (i == 0)
	n_ok = 0;
      else
	n_ok = i_eop + 1;

      {
	ELOG_TYPE_DECLARE (e) =
	{
	.function = (char *) __FUNCTION__,.format =
	    "ixge %d, ring full to tx %d head %d tail %d",.format_args =
	    "i2i2i2i2",};
	struct
	{
	  u16 instance, to_tx, head, tail;
	} *ed;
	ed = ELOG_DATA (&vm->elog_main, e);
	ed->instance = xd->device_index;
	ed->to_tx = n_descriptors_to_tx;
	ed->head = dq->head_index;
	ed->tail = dq->tail_index;
      }

      if (n_ok < n_descriptors_to_tx)
	{
	  n_tail_drop = n_descriptors_to_tx - n_ok;
	  vec_add (xm->tx_buffers_pending_free, from + n_ok, n_tail_drop);
	  vlib_error_count (vm, ixge_input_node.index,
			    IXGE_ERROR_tx_full_drops, n_tail_drop);
	}

      n_descriptors_to_tx = n_ok;
    }

  dq->tx.n_buffers_on_ring += n_descriptors_to_tx;

  /* Process from tail to end of descriptor ring. */
  if (n_descriptors_to_tx > 0 && dq->tail_index < dq->n_descriptors)
    {
      u32 n =
	clib_min (dq->n_descriptors - dq->tail_index, n_descriptors_to_tx);
      n = ixge_tx_no_wrap (xm, xd, dq, from, dq->tail_index, n, &tx_state);
      from += n;
      n_descriptors_to_tx -= n;
      dq->tail_index += n;
      ASSERT (dq->tail_index <= dq->n_descriptors);
      if (dq->tail_index == dq->n_descriptors)
	dq->tail_index = 0;
    }

  if (n_descriptors_to_tx > 0)
    {
      u32 n =
	ixge_tx_no_wrap (xm, xd, dq, from, 0, n_descriptors_to_tx, &tx_state);
      from += n;
      ASSERT (n == n_descriptors_to_tx);
      dq->tail_index += n;
      ASSERT (dq->tail_index <= dq->n_descriptors);
      if (dq->tail_index == dq->n_descriptors)
	dq->tail_index = 0;
    }

  /* We should only get full packets. */
  ASSERT (tx_state.is_start_of_packet);

  /* Report status when last descriptor is done. */
  {
    u32 i = dq->tail_index == 0 ? dq->n_descriptors - 1 : dq->tail_index - 1;
    ixge_tx_descriptor_t *d = &dq->descriptors[i].tx;
    d->status0 |= IXGE_TX_DESCRIPTOR_STATUS0_REPORT_STATUS;
  }

  /* Give new descriptors to hardware. */
  {
    ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_TX, queue_index);

    CLIB_MEMORY_BARRIER ();

    dr->tail_index = dq->tail_index;
  }

  /* Free any buffers that are done. */
  {
    u32 n = _vec_len (xm->tx_buffers_pending_free);
    if (n > 0)
      {
	vlib_buffer_free_no_next (vm, xm->tx_buffers_pending_free, n);
	_vec_len (xm->tx_buffers_pending_free) = 0;
	ASSERT (dq->tx.n_buffers_on_ring >= n);
	dq->tx.n_buffers_on_ring -= (n - n_tail_drop);
      }
  }

  return f->n_vectors;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ixge_device_class) = {
  .name = "ixge",
  .tx_function = ixge_interface_tx,
  .format_device_name = format_ixge_device_name,
  .format_device = format_ixge_device,
  .format_tx_trace = format_ixge_tx_dma_trace,
  .clear_counters = ixge_clear_hw_interface_counters,
  .admin_up_down_function = ixge_interface_admin_up_down,
  .rx_redirect_to_node = ixge_set_interface_next_node,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
