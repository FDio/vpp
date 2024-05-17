/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>

#include <dev_armada/pp2/pp2.h>

#define MRVL_PP2_BUFF_BATCH_SZ VLIB_FRAME_SIZE

static_always_inline void
mvpp2_rx_trace (vlib_main_t *vm, vlib_node_runtime_t *node, u32 next0,
		vlib_buffer_t *b0, uword *n_trace, struct pp2_ppio_desc *d)
{
  if (PREDICT_TRUE (
	vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0)))
    {
      mvpp2_rx_trace_t *tr;
      vlib_set_trace_count (vm, node, --(*n_trace));
      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
      tr->desc = *d;
    }
}

static_always_inline uword
mrvl_pp2_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame, vnet_dev_rx_queue_t *rxq)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = rxq->buffer_template;
  u32 thread_index = vm->thread_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 next_index = rxq->next_index;
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  u32 *to_next = 0;
  struct pp2_hif *hif = md->hif[thread_index];
  struct pp2_ppio_desc descs[VLIB_FRAME_SIZE], *d;
  u16 n_desc = VLIB_FRAME_SIZE;
  u32 buffers[VLIB_FRAME_SIZE];
  u32 n_bufs, *bi, i;

  bt.current_data = 2;

  if (PREDICT_FALSE (
	pp2_ppio_recv (mp->ppio, 0, rxq->queue_id, descs, &n_desc)))
    {
      vlib_error_count (vm, node->node_index, MVPP2_RX_NODE_CTR_PPIO_RECV, 1);
      n_desc = 0;
    }
  n_rx_packets = n_desc;

  for (i = 0; i < n_desc; i++)
    buffers[i] = pp2_ppio_inq_desc_get_cookie (descs + i);

  d = descs;
  bi = buffers;
  while (n_desc)
    {
      u32 n_left_to_next;
      vlib_buffer_t *b0, *b1;
      u32 bi0, bi1;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_desc >= 4 && n_left_to_next >= 2)
	{
	  /* prefetch */
	  bi0 = bi[0];
	  bi1 = bi[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b0->template = bt;
	  b1->template = bt;

	  n_rx_bytes += b0->current_length = pp2_ppio_inq_desc_get_pkt_len (d);
	  n_rx_bytes += b1->current_length =
	    pp2_ppio_inq_desc_get_pkt_len (d + 1);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      mvpp2_rx_trace (vm, node, next_index, b0, &n_trace, d);
	      if (n_trace > 0)
		mvpp2_rx_trace (vm, node, next_index, b1, &n_trace, d + 1);
	    }

	  to_next += 2;
	  n_left_to_next -= 2;
	  d += 2;
	  bi += 2;
	  n_desc -= 2;
	}
      while (n_desc && n_left_to_next)
	{
	  u32 bi0 = bi[0];
	  to_next[0] = bi0;
	  b0 = vlib_get_buffer (vm, bi0);
	  b0->template = bt;

	  n_rx_bytes += b0->current_length = pp2_ppio_inq_desc_get_pkt_len (d);

	  if (PREDICT_FALSE (n_trace > 0))
	    mvpp2_rx_trace (vm, node, next_index, b0, &n_trace, d);

	  to_next += 1;
	  n_left_to_next--;
	  d++;
	  bi++;
	  n_desc--;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thread_index, port->intf.sw_if_index, n_rx_packets, n_rx_bytes);

  if (PREDICT_FALSE (pp2_bpool_get_num_buffs (mrq->bpool, &n_bufs)))
    {
      vlib_error_count (vm, node->node_index,
			MVPP2_RX_NODE_CTR_BPOOL_GET_NUM_BUFFS, 1);
      goto done;
    }

  n_bufs = rxq->size - n_bufs;
  while (n_bufs >= MRVL_PP2_BUFF_BATCH_SZ)
    {
      u16 n_alloc, i;
      struct buff_release_entry *e = mrq->bre;

      n_alloc = vlib_buffer_alloc (vm, buffers, MRVL_PP2_BUFF_BATCH_SZ);
      i = n_alloc;

      if (PREDICT_FALSE (n_alloc == 0))
	{
	  vlib_error_count (vm, node->node_index,
			    MVPP2_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  goto done;
	}

      while (i--)
	{
	  u32 x = bi[0];
	  vlib_buffer_t *b = vlib_get_buffer (vm, x);
	  e->buff.addr = vlib_buffer_get_pa (vm, b) - 64;
	  e->buff.cookie = x;
	  e->bpool = mrq->bpool;
	  e++;
	  bi++;
	}

      i = n_alloc;
      if (PREDICT_FALSE (pp2_bpool_put_buffs (hif, mrq->bre, &i)))
	{
	  vlib_error_count (vm, node->node_index,
			    MVPP2_RX_NODE_CTR_BPOOL_PUT_BUFFS, 1);
	  vlib_buffer_free (vm, buffers, n_alloc);
	  goto done;
	}

      if (PREDICT_FALSE (i != n_alloc))
	vlib_buffer_free (vm, buffers + i, n_alloc - i);

      n_bufs -= i;
    }

done:
  return n_rx_packets;
}

VNET_DEV_NODE_FN (mvpp2_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    n_rx += mrvl_pp2_device_input_inline (vm, node, frame, rxq);
  return n_rx;
}
