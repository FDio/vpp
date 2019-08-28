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

#include <af_xdp/af_xdp.h>
#include <af_xdp/xsk_defs.h>

#define foreach_af_xdp_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) AF_XDP_INPUT_ERROR_##f,
  foreach_af_xdp_input_error
#undef _
    AF_XDP_INPUT_N_ERROR,
} af_xdp_input_error_t;

static __clib_unused char *af_xdp_input_error_strings[] = {
#define _(n,s) s,
  foreach_af_xdp_input_error
#undef _
};

always_inline void
buffer_add_to_chain (vlib_main_t * vm, u32 bi, u32 first_bi, u32 prev_bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_t *first_b = vlib_get_buffer (vm, first_bi);
  vlib_buffer_t *prev_b = vlib_get_buffer (vm, prev_bi);

  /* update first buffer */
  first_b->total_length_not_including_first_buffer += b->current_length;

  /* update previous buffer */
  prev_b->next_buffer = bi;
  prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;

  /* update current buffer */
  b->next_buffer = 0;
}

always_inline int
refill_rx_buffer (vlib_main_t * vm, u32 thread_index)
{
  af_xdp_main_t *amp = &af_xdp_main;
  u32 n_free_bufs = vec_len (amp->rx_buffers[thread_index]);

  if (n_free_bufs < VLIB_FRAME_SIZE)
    {
      vec_validate (amp->rx_buffers[thread_index], VLIB_FRAME_SIZE);

      n_free_bufs +=
	vlib_buffer_alloc (vm, &amp->rx_buffers[thread_index][n_free_bufs],
			   VLIB_FRAME_SIZE - n_free_bufs);

      _vec_len (amp->rx_buffers[thread_index]) = n_free_bufs;
    }

  return n_free_bufs;
}

static_always_inline uword
af_xdp_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, af_xdp_device_t * ad,
			    u16 qid)
{
  uword n_rx_packets = 0;
  af_xdp_main_t *amp = &af_xdp_main;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u32 n_free_bufs;
  u32 n_rx_bytes = 0;
  u32 *to_next = 0;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 thread_index = vm->thread_index;
  u32 n_buffer_bytes = vlib_buffer_get_default_data_size (vm);
  u32 min_bufs = FRAME_SIZE / n_buffer_bytes;
  u32 n_batch = 0;

  struct xsk_info *xsk = ad->xsk;
  struct xdp_uqueue *uq = &xsk->rx;
  struct xdp_desc *r = uq->ring;

  if (ad->per_interface_next_index != ~0)
    next_index = ad->per_interface_next_index;

  n_free_bufs = refill_rx_buffer (vm, thread_index);

  struct xdp_desc descs[BATCH_SIZE];
  vlib_buffer_t *b0 = 0, *first_b0 = 0;
  u32 next0 = next_index;
  u32 i = 0;			/// rename

  u32 n_left_to_next;
  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
  n_batch = xq_nb_avail (uq, BATCH_SIZE);

  while (n_free_bufs > min_bufs)
    {
      if (PREDICT_FALSE (0 == n_batch))
	{
	  *uq->consumer = uq->cached_cons;
	  umem_fill_to_kernel_ex (&xsk->umem->fq, descs, i);
	  i = 0;
	  n_batch = xq_nb_avail (uq, BATCH_SIZE);
	  if (PREDICT_FALSE (0 == n_batch))
	    break;
	}
      if (PREDICT_FALSE (0 == n_left_to_next))
	{
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	  b0 = 0, first_b0 = 0;
	  next0 = next_index;
	  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	  if (PREDICT_FALSE (0 == n_left_to_next))
	    break;
	}

      int idx = uq->cached_cons++ & DEFAULT_RX_RING_MASK;
      descs[i] = r[idx];

      u8 *pktdata = xq_get_data (xsk, descs[i].addr);
      u32 pktdata_len = descs[i].len;
      u32 offset = 0;
      u32 bi0 = 0, first_bi0 = 0, prev_bi0;

      while (pktdata_len)
	{
	  n_free_bufs--;
	  prev_bi0 = bi0;
	  bi0 = amp->rx_buffers[thread_index][n_free_bufs];
	  b0 = vlib_get_buffer (vm, bi0);
	  _vec_len (amp->rx_buffers[thread_index]) = n_free_bufs;

	  /* copy data */
	  u32 bytes_to_copy =
	    pktdata_len > n_buffer_bytes ? n_buffer_bytes : pktdata_len;
	  b0->current_data = 0;
	  clib_memcpy_fast (((u8 *) vlib_buffer_get_current (b0)),
			    pktdata + offset, bytes_to_copy);
	  b0->current_length = bytes_to_copy;

	  if (offset == 0)
	    {
	      b0->total_length_not_including_first_buffer = 0;
	      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = ad->sw_if_index;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      first_bi0 = bi0;
	      first_b0 = vlib_get_buffer (vm, first_bi0);
	    }
	  else
	    buffer_add_to_chain (vm, bi0, first_bi0, prev_bi0);

	  offset += bytes_to_copy;
	  pktdata_len -= bytes_to_copy;
	}

      n_rx_packets++;		/// TODO check counters correctness
      n_rx_bytes += descs[i].len;
      to_next[0] = first_bi0;
      to_next += 1;
      n_left_to_next--;
      n_batch--;
      i++;

      next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      /* redirect if feature path enabled */
      vnet_feature_start_device_input_x1 (ad->sw_if_index, &next0, first_b0);

      /* trace */
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (first_b0);
      if (PREDICT_FALSE (n_trace > 0))
	{
	  af_xdp_input_trace_t *tr;
	  vlib_trace_buffer (vm, node, next0, first_b0, /* follow_chain */ 0);
	  vlib_set_trace_count (vm, node, --n_trace);
	  tr = vlib_add_trace (vm, node, first_b0, sizeof (*tr));
	  tr->next_index = next0;
	  tr->hw_if_index = ad->hw_if_index;
	}

      /* enque and take next packet */
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
				       n_left_to_next, first_bi0, next0);
    }
  *uq->consumer = uq->cached_cons;
  umem_fill_to_kernel_ex (&xsk->umem->fq, descs, i);
  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_get_thread_index (), ad->hw_if_index, n_rx_packets, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, n_rx_packets);
  return n_rx_packets;
}

VLIB_NODE_FN (af_xdp_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_rx = 0;
  af_xdp_main_t *am = &af_xdp_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    af_xdp_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AF_XDP_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += af_xdp_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (af_xdp_input_node) = {
  .name = "af_xdp-input",
  .sibling_of = "device-input",
  .format_trace = format_af_xdp_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AF_XDP_INPUT_N_ERROR,
  .error_strings = af_xdp_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
