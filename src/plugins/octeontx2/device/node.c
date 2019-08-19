/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

/* Copyright (c) 2019 Marvell International Ltd. */

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/mpls/packet.h>
#include <vnet/handoff.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <octeontx2/buffer.h>
#include <octeontx2/device/octeontx2.h>
#include <octeontx2/device/otx2_priv.h>
#include <octeontx2/device/mempool.h>

static char *otx2_error_strings[] = {
#define _(n,s) s,
  foreach_otx2_error
#undef _
};

/* make sure all flags we need are stored in lower 8 bits */
STATIC_ASSERT ((PKT_RX_IP_CKSUM_BAD | PKT_RX_FDIR) <
	       256, "dpdk flags not un lower byte, fix needed");

static_always_inline u32
otx2_device_input (vlib_main_t * vm, otx2_main_t * dm, otx2_device_t * xd,
		   vlib_node_runtime_t * node, u32 thread_index, u16 queue_id)
{
  uword n_rx_packets = 0, n_rx_bytes = 0;
  u32 n_left, n_trace;
  u32 *buffers;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  vlib_buffer_t **b;
  vlib_buffer_t *b0;
  u16 *next;
  u32 n;
  int single_next = 0;

  otx2_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);
  vlib_buffer_t *bt = &ptd->buffer_template;

  if ((xd->flags & OTX2_DEVICE_FLAG_ADMIN_UP) == 0)
    return 0;

  /* Update buffer template */
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = xd->sw_if_index;
  bt->error = node->errors[OTX2_ERROR_NONE];
  bt->buffer_pool_index = xd->buffer_pool_for_queue[queue_id];
  bt->ref_count = 1;
  vnet_buffer (bt)->feature_arc_index = 0;
  bt->current_config_index = 0;
  ptd->xd_flags = xd->flags;
  ptd->rx_n_bytes = 0;
  ptd->rx_or_flags = 0;

  /** rte_eth_rx_burst() does following
   * - convert descriptors to vlib_buffers
   * - Copy buffer template
   * - Set b->current_length and b->current_data
   * - Set ptd->rx_or_flags for rx offload
   * - Set ptd->nrx_n_bytes;
   **/
  while (n_rx_packets < OTX2_RX_BURST_SZ)
    {
      n = rte_eth_rx_burst (xd->port_id, queue_id,
			    (struct rte_mbuf **) ptd->vbufs + n_rx_packets,
			    OTX2_RX_BURST_SZ - n_rx_packets);
      n_rx_packets += n;

      if (n < 32)
	break;
    }

  if (n_rx_packets == 0)
    return 0;

  ptd->n_buffers_to_free += n_rx_packets;
  n_rx_bytes = ptd->rx_n_bytes;

  if (PREDICT_FALSE (xd->per_interface_next_index != ~0))
    next_index = xd->per_interface_next_index;

  /* as all packets belong to the same interface feature arc lookup
     can be don once and result stored in the buffer template */
  if (PREDICT_FALSE (vnet_device_input_have_features (xd->sw_if_index)))
    vnet_feature_start_device_input_x1 (xd->sw_if_index, &next_index, bt);


  if (PREDICT_FALSE (ptd->rx_or_flags & PKT_RX_FDIR))
    {
      /* some packets will need to go to different next nodes */
      for (n = 0; n < n_rx_packets; n++)
	ptd->next[n] = next_index;

      /* enqueue buffers to the next node */
      vlib_get_buffer_indices_with_offset (vm, (void **) ptd->vbufs,
					   ptd->buffers, n_rx_packets, 0);

      vlib_buffer_enqueue_to_next (vm, node, ptd->buffers, ptd->next,
				   n_rx_packets);
    }
  else
    {
      u32 *to_next, n_left_to_next;

      vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
      vlib_get_buffer_indices_with_offset (vm, (void **) ptd->vbufs, to_next,
					   n_rx_packets, 0);

      if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	  f = vlib_get_frame (vm, nf->frame);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	  ef = vlib_frame_scalar_args (f);
	  ef->sw_if_index = xd->sw_if_index;
	  ef->hw_if_index = xd->hw_if_index;

	  /* if PMD supports ip4 checksum check and there are no packets
	     marked as ip4 checksum bad we can notify ethernet input so it
	     can send pacets to ip4-input-no-checksum node */
	  if (xd->flags & OTX2_DEVICE_FLAG_RX_IP4_CKSUM &&
	      (ptd->rx_or_flags & PKT_RX_IP_CKSUM_BAD) == 0)
	    f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
	  vlib_frame_no_append (f);
	}
      n_left_to_next -= n_rx_packets;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      single_next = 1;
    }

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      if (single_next)
	vlib_get_buffer_indices_with_offset (vm, (void **) ptd->vbufs,
					     ptd->buffers, n_rx_packets, 0);

      n_left = n_rx_packets;
      buffers = ptd->buffers;
      b = ptd->vbufs;
      next = ptd->next;

      while (n_trace && n_left)
	{
	  b0 = vlib_get_buffer (vm, buffers[0]);
	  if (single_next == 0)
	    next_index = next[0];
	  vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 0);

	  otx2_rx_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof t0[0]);
	  t0->queue_index = queue_id;
	  t0->device_index = xd->device_index;
	  t0->buffer_index = vlib_get_buffer_index (vm, b0);

	  clib_memcpy_fast (&t0->buffer, b0,
			    sizeof b0[0] - sizeof b0->pre_data);
	  clib_memcpy_fast (t0->buffer.pre_data, b0->data,
			    sizeof t0->buffer.pre_data);

	  clib_memcpy_fast (&t0->data, b0->data, sizeof t0->data);
	  n_trace--;
	  n_left--;
	  buffers++;
	  b++;
	  next++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX, thread_index, xd->sw_if_index,
     n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);

  return n_rx_packets;
}

VLIB_NODE_FN (otx2_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * f)
{
  otx2_main_t *dm = &otx2_main;
  otx2_device_t *xd;
  uword n_rx_packets = 0;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;
  u32 thread_index = node->thread_index;
  otx2_per_thread_data_t *ptd = vec_elt_at_index (dm->per_thread_data,
						  thread_index);

  /*We have enough buffers to refill */
  if (ptd->n_buffers_to_free >= OTX2_RX_BURST_SZ)
    {
      ptd->n_buffers_to_free -=
	otx2_mempool_refill (vm, ptd->buffer_pool_index,
			     OTX2_RX_BURST_SZ,
			     ptd->buffers, (void **) ptd->vbufs);
    }

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  /* *INDENT-OFF* */
  foreach_device_and_queue (dq, rt->devices_and_queues)
    {
      xd = vec_elt_at_index(dm->devices, dq->dev_instance);
      n_rx_packets += otx2_device_input (vm, dm, xd, node, thread_index,
					 dq->queue_id);
    }
  /* *INDENT-ON* */
  return n_rx_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (otx2_input_node) = {
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "octeontx2-input",
  .sibling_of = "device-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_otx2_rx_trace,

  .n_errors = OTX2_N_ERROR,
  .error_strings = otx2_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
